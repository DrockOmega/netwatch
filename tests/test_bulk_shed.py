"""BULK_SHED_BYTES: the kernel sheds bulk TCP/QUIC payload and the volume detectors count those flows from Zeek.

The filter cases run the real libpcap compiler and matcher; the volume cases run the real ZeekCollector into the
store and the real dod_core_process reading it back, beside packets of the same flow.
"""

import ctypes
import json
import queue
import threading
import time

import pytest

import netwatch_workers
from netwatch_capture import parse_ethernet_frame
from netwatch_config import CAPTURE_PROFILES, build_config, bulk_shed_filter
from netwatch_core import make_message
from netwatch_ja3 import fingerprint
from netwatch_security_store import security_store_from_config
from netwatch_zeek import ZeekCollector
from tests.test_capture import dns_query, ethernet, ipv4, ipv6, tcp, udp
from tests.test_core_publish import worker_config
from tests.test_ja3 import build_client_hello

LOCAL, REMOTE = "192.168.1.10", "142.250.1.1"
MSS = b"\x17" + b"d" * 1447  # a mid-stream TLS application-data segment
HELLO = build_client_hello(ciphers=tuple(range(0x1301, 0x1301 + 520)), sni="big.example")  # 1.1 kB, one segment


def _tcp(payload=b"", sport=50000, dport=443, flags=0x10):
    return tcp(payload, sport, dport, flags)


FRAMES = {  # name: (frame, kept by the kernel)
    "v4 bulk data segment": (ethernet(ipv4(_tcp(MSS), 6)), False),
    "v6 bulk data segment": (ethernet(ipv6(_tcp(MSS), 6), 0x86DD), False),
    "v4 QUIC short-header packet": (ethernet(ipv4(udp(b"\x45" + MSS[:1300], dport=443), 17)), False),
    "v6 QUIC short-header packet": (ethernet(ipv6(udp(b"\x45" + MSS[:1300], sport=443), 17), 0x86DD), False),
    "SYN": (ethernet(ipv4(_tcp(flags=0x02), 6)), True),
    "v6 SYN-ACK": (ethernet(ipv6(_tcp(sport=443, dport=50000, flags=0x12), 6), 0x86DD), True),
    "pure ACK": (ethernet(ipv4(_tcp(), 6)), True),
    "large FIN": (ethernet(ipv4(_tcp(MSS, flags=0x11), 6)), True),
    "RST": (ethernet(ipv6(_tcp(flags=0x14), 6), 0x86DD), True),
    "small data": (ethernet(ipv4(_tcp(MSS[:300]), 6)), True),
    "large ClientHello": (ethernet(ipv4(_tcp(HELLO, flags=0x18), 6)), True),
    "ClientHello first segment": (ethernet(ipv4(_tcp(b"\x16\x03\x01\x07\x00\x01" + MSS[6:]), 6)), True),
    "v6 ClientHello first segment": (ethernet(ipv6(_tcp(b"\x16\x03\x01\x07\x00\x01" + MSS[6:]), 6), 0x86DD), True),
    "ClientHello second segment": (ethernet(ipv4(_tcp(MSS[:420]), 6)), True),
    "QUIC Initial": (ethernet(ipv4(udp(b"\xc3" + MSS[:1250], dport=443), 17)), True),
    "DNS query": (ethernet(ipv4(udp(dns_query()), 17)), True),
    "large DNS over UDP": (ethernet(ipv4(udp(dns_query() + MSS[:1300], sport=53, dport=50000), 17)), True),
    "large DNS over TCP": (ethernet(ipv6(_tcp(MSS, sport=53, dport=50000), 6), 0x86DD), True),
    "large UDP off 443": (ethernet(ipv4(udp(MSS, dport=41641), 17)), True),
    "large ICMP": (ethernet(ipv4(b"\x08\x00\x00\x00\x00\x01\x00\x01" + MSS, 1)), True),
    "ARP": (ethernet(b"\x00\x01\x08\x00\x06\x04\x00\x01" + bytes(20), 0x0806), True),
}


def test_filter_sheds_only_bulk_payload():
    try:
        from scapy.arch.common import compile_filter
        from scapy.libs.winpcapy import _lib, pcap_pkthdr
        program = compile_filter(bulk_shed_filter(1000), linktype=1)
    except Exception as exc:  # no libpcap on this host
        pytest.skip(f"libpcap unavailable: {exc}")
    match = _lib.pcap_offline_filter
    match.argtypes = [ctypes.c_void_p, ctypes.POINTER(pcap_pkthdr), ctypes.c_char_p]
    kept = {}
    for name, (frame, _) in FRAMES.items():
        header = pcap_pkthdr()
        header.caplen = header.len = len(frame)
        kept[name] = match(ctypes.byref(program), ctypes.byref(header), frame) != 0
    assert kept == {name: expected for name, (_, expected) in FRAMES.items()}
    # What the filter keeps parses as before: SYN flags, the DNS name, JA3 and SNI from the handshake segment.
    parsed = {name: parse_ethernet_frame(FRAMES[name][0], 1.0, fingerprint)[1]
              for name in ("SYN", "DNS query", "large ClientHello")}
    assert parsed["SYN"]["tcp_flags"] == "S" and parsed["DNS query"]["dns_qname"] == "example.com"
    assert parsed["large ClientHello"]["ja3"] and parsed["large ClientHello"]["sni_domain"] == "big.example"
    assert len(FRAMES["large ClientHello"][0]) > 1000


def test_config_adds_the_clause_only_with_zeek(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    config, notes = build_config(str(tmp_path), hostname="h", extra={"BULK_SHED_BYTES": 1000})
    assert config["BULK_SHED_BYTES"] == 0 and config["BPF_FILTER"] is None
    assert any("BULK_SHED_BYTES needs ZEEK_LOGS_ENABLED" in note for note in notes)
    config, _ = build_config(str(tmp_path), hostname="h", extra={
        "BULK_SHED_BYTES": 1000, "ZEEK_LOGS_ENABLED": True, "CAPTURE_PROFILE": "balanced"})
    assert config["BPF_FILTER"] == f"({CAPTURE_PROFILES['balanced']}) and ({bulk_shed_filter(1000)})"
    with pytest.raises(ValueError, match="BULK_SHED_BYTES"):
        build_config(str(tmp_path), hostname="h", extra={"BULK_SHED_BYTES": 100, "ZEEK_LOGS_ENABLED": True})


def _event(frame, stamp, size=None):
    data = parse_ethernet_frame(frame, stamp)[1]
    data.update(sensor_id="t", interface="t", mac_src="02:00:00:00:00:10")
    data.pop("control_payload", None)
    if size is not None:
        data["size_bytes"] = size  # one event standing in for many wire packets
    return data


def _conn(uid, start, duration, orig_pkts, orig_bytes, interim=False, proto="tcp", dport=443, sport=50000):
    record = {"uid": uid, "id.orig_h": LOCAL, "id.orig_p": sport, "id.resp_h": REMOTE, "id.resp_p": dport,
              "proto": proto, "duration": duration, "orig_pkts": orig_pkts, "orig_bytes": orig_bytes,
              "orig_ip_bytes": orig_bytes + orig_pkts * 52, "resp_pkts": orig_pkts // 3, "resp_bytes": 0,
              "resp_ip_bytes": orig_pkts // 3 * 52,
              "orig_l2_addr": "02:00:00:00:00:10", "resp_l2_addr": "02:00:00:00:00:01"}
    record["ts"] = start + duration if interim else start
    return record


class Sensor:
    """The single core plus the Zeek collector over one store, as the runtime wires them."""

    def __init__(self, tmp_path, **extra):
        (tmp_path / "zeek").mkdir()
        self.zeek_dir = tmp_path / "zeek"
        self.config = dict(worker_config(tmp_path), BULK_SHED_BYTES=1000, ZEEK_LOGS_ENABLED=True,
                           ZEEK_LOG_PATHS=[str(self.zeek_dir / "conn*.log")], LOCAL_PREFIXES=("192.168.1.0/24",),
                           BASELINE_ENABLED=False, **extra)
        self.qs = {name: queue.Queue() for name in ("ingest", "render", "alert", "policy", "db", "evidence",
                                                     "status", "inventory")}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=netwatch_workers.dod_core_process, daemon=True, args=(
            self.qs["ingest"], self.qs["render"], self.qs["alert"], self.qs["policy"], self.qs["db"],
            self.qs["evidence"], self.config, self.qs["status"], self.qs["inventory"], self.stop))
        self.store = security_store_from_config(self.config)
        self.collector = ZeekCollector(self.store, self.config)
        self.alerts = []
        self.thread.start()
        time.sleep(0.5)  # the core takes its Zeek cursor before any record is committed

    def packets(self, events):
        self.qs["ingest"].put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": events}))
        deadline = time.time() + 10
        while time.time() < deadline and not self.qs["ingest"].empty():
            time.sleep(0.05)
        time.sleep(0.3)

    def zeek(self, log, *records):
        with (self.zeek_dir / f"{log}.log").open("a") as f:
            f.writelines(json.dumps(record) + "\n" for record in records)
        assert self.collector.poll() == len(records)
        time.sleep(2.0)  # the core reads the stream every second

    def volume_alerts(self):
        while not self.qs["alert"].empty():
            message = self.qs["alert"].get_nowait()
            text = message["data"].get("message", "")
            if text.startswith(("EXFIL ALERT", "UDP FLOOD ALERT")):
                self.alerts.append(text)
        return self.alerts

    def close(self):
        self.stop.set()
        self.thread.join(10)
        self.collector.close()
        self.store.close()
        assert not self.thread.is_alive()


@pytest.fixture
def sensor(tmp_path):
    made = []
    yield lambda **extra: made.append(Sensor(tmp_path, **extra)) or made[-1]
    for one in made:
        one.close()


def test_bulk_upload_raises_exfil_from_zeek_without_double_counting(sensor):
    s = sensor()
    now = time.time()
    # What still reaches the sniffer of a 60 MB shed upload (here as 600 x 100 kB events): never counted.
    s.packets([_event(ethernet(ipv4(_tcp(flags=0x02), 6, LOCAL, REMOTE)), now)]
              + [_event(ethernet(ipv4(_tcp(), 6, LOCAL, REMOTE)), now + i / 1000, size=100_000) for i in range(600)]
              + [_event(ethernet(ipv4(udp(dns_query()), 17, LOCAL, "192.168.1.1")), now + 0.7)])
    assert s.volume_alerts() == []
    # Zeek's interim record of the same upload: 60 MB in 6 s. Packets plus Zeek would be 120 MB and alert.
    s.zeek("conn_interim", _conn("Cbulk", now - 6, 6, 41_000, 60_000_000, interim=True))
    assert s.volume_alerts() == []
    # The next interim (cumulative 105 MB): only its 45 MB growth is added, 105 MB in the window.
    s.zeek("conn_interim", _conn("Cbulk", now - 6, 8, 72_000, 105_000_000, interim=True))
    alerts = s.volume_alerts()
    assert len(alerts) == 1 and alerts[0].startswith("EXFIL ALERT: 105.") and alerts[0].endswith(f"by {LOCAL}")


def test_final_record_and_late_interim_add_only_growth(sensor):
    s = sensor()
    now = time.time()
    s.packets([_event(ethernet(ipv4(_tcp(flags=0x02), 6, LOCAL, REMOTE)), now)])
    s.zeek("conn_interim", _conn("Cup", now - 6, 6, 1_000, 60_000_000, interim=True))
    # conn.log (another file) may be read before the last interim: each adds only growth over the other.
    s.zeek("conn", _conn("Cup", now - 6, 7, 1_010, 60_100_000))
    s.zeek("conn_interim", _conn("Cup", now - 6, 7, 1_010, 60_100_000, interim=True))
    assert s.volume_alerts() == []  # 60.1 MB counted once; twice would be 120 MB and alert


def test_long_transfer_counts_its_average_rate_and_one_way_quic_feeds_udp_flood(sensor):
    s = sensor()
    s.packets([_event(ethernet(ipv4(_tcp(flags=0x02), 6, LOCAL, REMOTE)), time.time())])
    # 600 MB over 2 minutes is 50 MB per 10 s window: below EXFIL, however late the record arrives.
    s.zeek("conn", _conn("Clong", time.time() - 120, 120, 400_000, 600_000_000))
    assert s.volume_alerts() == []
    # QUIC the server answers (1 reply per 3 sent) is a session, not a flood (b533).
    s.zeek("conn_interim", _conn("Cquic", time.time() - 10, 10, 70_000, 30_000_000, interim=True, proto="udp"))
    assert s.volume_alerts() == []
    # One-way: 70k packets in 10 s is 14k per 2 s window, over UDP_FLOOD_THRESHOLD (10k); 4 MB keeps EXFIL quiet.
    blast = _conn("Cblast", time.time() - 10, 10, 70_000, 4_000_000, interim=True, proto="udp")
    s.zeek("conn_interim", {**blast, "resp_pkts": 0, "resp_ip_bytes": 0})
    assert [a.split(":")[0] for a in s.volume_alerts()] == ["UDP FLOOD ALERT"]


def test_unshed_traffic_still_counts_from_packets(sensor):
    s = sensor(UDP_FLOOD_THRESHOLD=100)
    now = time.time()
    # UDP off 443 is never shed: the sniffer path still counts it, and Zeek records of it add nothing.
    s.packets([_event(ethernet(ipv4(udp(b"x" * 32, 50000, 3478), 17, LOCAL, REMOTE)), now + i / 1000)
               for i in range(101)])
    s.zeek("conn", _conn("Cstun", now, 0.1, 5_000, 1_000_000, proto="udp", dport=3478))
    assert [a.split(":")[0] for a in s.volume_alerts()] == ["UDP FLOOD ALERT"]
