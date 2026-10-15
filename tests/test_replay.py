"""Replay a committed pcap through the real capture callback, analytics core and ledger writer.

``tests/fixtures/replay.pcap`` is generated deterministically by ``build_replay_pcap`` (standard library
only); regenerate it with ``python -m tests.test_replay``. The runtime runs spawned workers exactly as the
service does, with only the driver socket replaced by the pcap reader.
"""

import sqlite3
import struct
import time
from pathlib import Path

import netwatch_runtime
from netwatch_backup import backup
from netwatch_security_store import DurableIncidentStore
from tests.test_capture import SRC_MAC, dns_query, ethernet, ipv4, ipv6, tcp, udp
from tests.test_control import dhcp_frame
from tests.test_ja3 import build_client_hello, build_server_hello
from tests.test_runtime import runtime_config

FIXTURE = Path(__file__).parent / "fixtures" / "replay.pcap"
CLIENT, SERVER, RESOLVER = "192.168.1.10", "93.184.216.34", "192.168.1.1"


def _frames():
    """(offset seconds, frame): one TLS session, DNS over IPv4/IPv6, an ICMP echo, ARP and DHCP."""
    out = [tcp(sport=50000, dport=443, flags=0x02), tcp(sport=443, dport=50000, flags=0x12),
           tcp(sport=50000, dport=443, flags=0x10), tcp(build_client_hello(sni="replay.example")),
           tcp(build_server_hello(), sport=443, dport=50000)]
    out += [tcp(b"\x17\x03\x03\x00\x04data", *((50000, 443) if i % 2 else (443, 50000))) for i in range(4)]
    frames = [ethernet(ipv4(segment, 6, *((CLIENT, SERVER) if segment[:2] == b"\xc3\x50" else (SERVER, CLIENT))))
              for segment in out]
    response = bytearray(dns_query("replay.example"))
    response[2:4] = b"\x81\x80"
    frames += [ethernet(ipv4(udp(dns_query("replay.example"), sport=50001), 17, CLIENT, RESOLVER)),
               ethernet(ipv4(udp(bytes(response), sport=53, dport=50001), 17, RESOLVER, CLIENT)),
               ethernet(ipv6(udp(dns_query("v6.replay.example"), sport=50002), 17), 0x86DD),
               ethernet(ipv4(struct.pack("!BBHHH", 8, 0, 0, 7, 1), 1, CLIENT, "1.1.1.1")),
               ethernet(ipv4(struct.pack("!BBHHH", 0, 0, 0, 7, 1), 1, "1.1.1.1", CLIENT)),
               ethernet(struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, SRC_MAC, bytes([192, 168, 1, 10]),
                                    b"\0" * 6, bytes([192, 168, 1, 1])), 0x0806),
               dhcp_frame()]
    return [(index * 0.05, frame) for index, frame in enumerate(frames)]


def build_replay_pcap():
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # classic pcap, Ethernet
    base = 1_791_000_000  # fixed epoch so the file is byte-for-byte reproducible
    return header + b"".join(
        struct.pack("<IIII", base + int(offset), round(offset % 1 * 1e6), len(frame), len(frame)) + frame
        for offset, frame in _frames())


def read_pcap(data):
    magic, *_ = struct.unpack_from("<IHHiIII", data)
    assert magic == 0xA1B2C3D4
    offset, records = 24, []
    while offset < len(data):
        seconds, micros, length, _ = struct.unpack_from("<IIII", data, offset)
        records.append((seconds + micros / 1e6, data[offset + 16:offset + 16 + length]))
        offset += 16 + length
    return records


def replay_capture_worker(*args):
    """io_sniffer_process with the driver replaced by the committed pcap, replayed relative to now."""
    import netwatch_capture
    from netwatch_workers import io_sniffer_process

    class PcapSocket:
        pcap_fd = None
        def setnonblock(self, _):
            pass
        def close(self):
            pass
        @staticmethod
        def select(sockets, _timeout):
            time.sleep(0.01)
            return sockets

    PcapSocket.pcap_fd = PcapSocket()
    records = read_pcap(FIXTURE.read_bytes())
    ready = Path(args[2]["LOG_DIR"]) / "replay.ready"

    def dispatcher(_sock, callback):
        def dispatch(_batch):
            if ready.exists():
                return 0
            start, first = time.time(), records[0][0]
            for stamp, frame in records:
                callback(frame, start + stamp - first)
            ready.write_text("ready")
            return len(records)
        return dispatch

    netwatch_capture.open_capture_socket = lambda *_: PcapSocket()
    netwatch_capture.set_capture_buffer = lambda *_: True
    netwatch_capture.make_capture_dispatcher = dispatcher
    netwatch_capture.pcap_stats = lambda *_: {"recv": len(records), "drop": 0, "ifdrop": 0}
    io_sniffer_process(*args)


def test_committed_fixture_is_reproducible():
    assert FIXTURE.read_bytes() == build_replay_pcap()
    assert len(read_pcap(FIXTURE.read_bytes())) == 16


def test_pcap_replay_reaches_ledger_and_native_store_with_exact_counts(tmp_path, tmp_path_factory, monkeypatch):
    monkeypatch.setattr(netwatch_runtime, "io_sniffer_process", replay_capture_worker)
    config = runtime_config(tmp_path)
    config.update(INGEST_BATCH_MAX=1000, INGEST_BATCH_SEC=3600, ARP_DETECTION_ENABLED=False,
                  LOCAL_PREFIXES=("192.168.1.0/24",), LOCAL_PREFIXES6=("2601:db8::/64",),
                  LOCAL_PREFIXES6_AUTO=False)
    runtime = netwatch_runtime.MonitoringRuntime(config)
    try:
        runtime.start()
        ready = Path(config["LOG_DIR"]) / "replay.ready"
        deadline = time.time() + 15
        stores = [ready, tmp_path / "telemetry_ledger.db", tmp_path / "telemetry_spool.db"]
        while time.time() < deadline and not all(p.exists() for p in stores):  # the db worker creates its stores asynchronously
            time.sleep(0.02)
        assert all(p.exists() for p in stores)
        # Online backup of the live runtime's WAL stores: consistent and verifiable mid-run.
        manifest = backup(tmp_path, tmp_path_factory.mktemp("backup"))
        assert {"telemetry_security.db", "telemetry_ledger.db", "telemetry_spool.db"} <= {
            entry["path"] for entry in manifest["files"] if entry["kind"] == "sqlite"}
        assert runtime.stop(grace=15) == []
        assert runtime.shutdown_report["ordered_drain"]
    finally:
        runtime.stop()
    with sqlite3.connect(config["DB_NAME"]) as conn:
        by_protocol = dict(conn.execute(
            "SELECT protocol, SUM(packet_count) FROM network_events GROUP BY protocol").fetchall())
        names = {row[0] for row in conn.execute("SELECT DISTINCT sni_domain FROM network_events")}
        flows = conn.execute("SELECT COUNT(DISTINCT community_id) FROM network_events").fetchone()[0]
    assert by_protocol == {"TCP": 9, "UDP": 4, "ICMP": 2}  # every IP frame; ARP goes only to the native store
    assert {"replay.example", "v6.replay.example"} <= names
    assert flows == 5  # TLS session, DNS v4, DNS v6, ICMP echo, DHCP: both directions share one ID
    store = DurableIncidentStore(config["INCIDENT_DB"])
    try:
        control = [row["event_type"] for row in store.source_events("CONTROL", limit=100)]
    finally:
        store.close()
    assert sorted(control) == ["arp", "dhcp", "icmp", "icmp"]


if __name__ == "__main__":
    FIXTURE.parent.mkdir(exist_ok=True)
    FIXTURE.write_bytes(build_replay_pcap())
