"""Core publish path: retry helper, permanent errors, shutdown flush, ledger-first faults, SW1 publisher."""

import ipaddress
import itertools
import logging
import queue
import sqlite3
import threading
import time
from pathlib import Path

import pytest

import netwatch_workers
from netwatch_capture import parse_ethernet_frame
from netwatch_config import DEFAULTS, PATH_KEYS, build_config
from netwatch_core import make_message
from tests.test_capture import ethernet, ipv4, tcp

LOG = logging.getLogger("netwatch.test")


class FlakyStore:
    def __init__(self, error):
        self.error, self.calls = error, 0

    def add(self, _payload):
        self.calls += 1
        raise self.error


def test_retry_stops_at_first_busy_store():
    store = FlakyStore(sqlite3.OperationalError("database is locked"))
    deferred = [make_message("T", "A", "UI_SHELL", {"n": n}) for n in range(256)]
    expected = list(deferred)
    netwatch_workers.retry_deferred(store, queue.Queue(), deferred, LOG)
    assert store.calls == 1 and deferred == expected


def test_defer_overflow_returns_false():
    store = FlakyStore(sqlite3.OperationalError("database is locked"))
    deferred = [object()] * 3
    assert netwatch_workers.publish_or_defer(store, queue.Queue(), {"x": 1}, deferred, LOG, limit=3) is False
    assert store.calls == 0 and len(deferred) == 3  # behind a backlog: no new busy wait


def test_publish_or_defer_drops_permanent_errors():
    store = FlakyStore(sqlite3.IntegrityError("UNIQUE constraint failed"))
    deferred = []
    assert netwatch_workers.publish_or_defer(store, queue.Queue(), {"x": 1}, deferred, LOG) is False
    assert deferred == []
    deferred.append({"y": 2})  # a permanent error at the head of the backlog is dropped, not retried forever
    netwatch_workers.retry_deferred(store, queue.Queue(), deferred, LOG)
    assert deferred == []


@pytest.mark.parametrize("key", ["DETECTOR_BUCKETS", "EXFIL_WINDOW_SEC", "SWEEP_WINDOW_SEC",
                                 "UDP_FLOOD_WINDOW_SEC", "MAX_ENTITIES", "DB_BATCH_CEILING"])
@pytest.mark.parametrize("bad", [0, -1, True])
def test_build_config_rejects_bad_detector_ints(tmp_path, key, bad):
    with pytest.raises(ValueError, match=key):
        build_config(str(tmp_path), extra={key: bad})


@pytest.mark.parametrize("key", ["EXFIL_THRESHOLD_BYTES", "GC_INTERVAL_SEC", "DETECTOR_ALERT_COOLDOWN_SEC"])
def test_build_config_rejects_non_integer_detector_settings(tmp_path, key):
    with pytest.raises(ValueError, match=key):
        build_config(str(tmp_path), extra={key: "10"})


# --- in-process core harness -------------------------------------------------------------

def worker_config(tmp_path):
    config = dict(DEFAULTS, SURICATA_EVE_ENABLED=False, LOG_TO_CONSOLE=False, ARP_DETECTION_ENABLED=False)
    for name in PATH_KEYS:
        if config.get(name):
            config[name] = str(tmp_path / Path(config[name]).name)
    for name in ("SIG_FILE", "POLICY_FILE", "JA3_BLOCKLIST", "OUI_DB"):
        config[name] = str(Path(__file__).resolve().parents[1] / Path(DEFAULTS[name]).name)
    return config


def run_core(tmp_path, count=1, macs=False, events=None, extra=None, linger=0.3):
    config = dict(worker_config(tmp_path), **(extra or {}))
    qs = {name: queue.Queue() for name in ("ingest", "render", "alert", "policy", "db", "evidence", "status", "inventory")}
    data = parse_ethernet_frame(ethernet(ipv4(tcp(b"x"), 6)), time.time())[1]
    data.update(sensor_id="t", interface="t")
    qs["ingest"].put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": events or [
        dict(data, mac_src=f"02:00:00:00:{n >> 8:02x}:{n & 255:02x}") if macs else dict(data) for n in range(count)]}))
    stop = threading.Event()
    thread = threading.Thread(target=netwatch_workers.dod_core_process, daemon=True, args=(
        qs["ingest"], qs["render"], qs["alert"], qs["policy"], qs["db"], qs["evidence"], config, qs["status"], qs["inventory"], stop))
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline and not qs["ingest"].empty():
        time.sleep(0.05)
    time.sleep(linger)
    stop.set()
    thread.join(10)
    assert not thread.is_alive()
    return qs


def drain(q):
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    return items


def test_core_shutdown_flushes_deferred_alerts(tmp_path, monkeypatch):
    real, state = netwatch_workers.publish_detection, {"failed": 0}

    def publish(store, presentation_queue, message):
        if not state["failed"]:
            state["failed"] = 1
            raise sqlite3.OperationalError("database is locked")
        return real(store, presentation_queue, message)

    monkeypatch.setattr(netwatch_workers, "publish_detection", publish)
    qs = run_core(tmp_path)
    assert state["failed"] and any(m["action"] == "DEVICE_NEW" for m in drain(qs["alert"]))


def test_analyser_fault_keeps_ledger_row_and_logs_once(tmp_path, monkeypatch, caplog):
    def boom(*_args, **_kwargs):
        raise ZeroDivisionError("window")

    for name in ("analyze_udp_flood", "analyze_volumetric_exfil", "analyze_port_sweep"):
        monkeypatch.setattr(netwatch_workers, name, boom)
    core_log = logging.getLogger("netwatch.core")  # propagate=False; a preset handler also skips file setup
    core_log.addHandler(caplog.handler)
    try:
        qs = run_core(tmp_path, count=1000)
    finally:
        core_log.removeHandler(caplog.handler)
    rows = [row for m in drain(qs["db"]) for row in m["data"].get("rows", [])]
    assert sum(row[13] for row in rows) == 1000
    assert 1 <= sum("event fault" in r.getMessage() for r in caplog.records) <= 2


# --- SW1: a slow store must not stall capture --------------------------------------------

def test_sniffer_capture_keeps_advancing_while_store_is_slow(tmp_path, monkeypatch):
    import netwatch_capture

    entered, added = threading.Event(), []

    class SlowStore:
        def add(self, payload):
            entered.set()
            time.sleep(2)
            added.append(payload)
            return 1

        def close(self):
            pass

    class Sock:
        pcap_fd = None

        def setnonblock(self, _):
            pass

        def close(self):
            pass

        @staticmethod
        def select(sockets, _timeout):
            time.sleep(0.01)
            return sockets

    Sock.pcap_fd = Sock()
    reads = []
    counters = itertools.count(1)
    monkeypatch.setattr(netwatch_workers, "security_store_from_config", lambda _c: SlowStore())
    monkeypatch.setattr(netwatch_capture, "open_capture_socket", lambda *_: Sock())
    monkeypatch.setattr(netwatch_capture, "set_capture_buffer", lambda *_: True)
    monkeypatch.setattr(netwatch_capture, "make_capture_dispatcher",
                        lambda _s, _cb: lambda _b: reads.append(time.time()) or 0)
    monkeypatch.setattr(netwatch_capture, "pcap_stats",  # steady loss: every sample offers a CAPTURE_LOSS
                        lambda *_: {"recv": 100 * next(counters), "drop": 50 * next(counters), "ifdrop": 0})
    config = worker_config(tmp_path)
    config.update(CONTROL_CAPTURE_ENABLED=False, EVIDENCE_CAPTURE_ENABLED=False, PCAP_STATS_INTERVAL_SEC=0.05)
    stop = threading.Event()
    thread = threading.Thread(target=netwatch_workers.io_sniffer_process, daemon=True, args=(
        queue.Queue(), queue.Queue(), config, queue.Queue(), stop))
    thread.start()
    assert entered.wait(10), "the publisher never reached the store"
    before = len(reads)
    time.sleep(1)
    assert len(reads) - before > 20  # the capture thread kept reading while add() slept
    deadline = time.time() + 10
    while not added and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    thread.join(15)
    assert added and not thread.is_alive()


def test_threat_intel_dns_domain_hit_targets_the_lan_source_not_the_resolver(tmp_path):
    from tests.test_capture import dns_query, udp

    cache = tmp_path / "intel.json"
    cache.write_text('{"domains": {"evil.example": "testfeed"}}')
    frame = ethernet(ipv4(udp(dns_query("evil.example")), 17, "10.0.0.5", "8.8.8.8"))
    data = parse_ethernet_frame(frame, time.time())[1]
    data.update(sensor_id="t", interface="t")
    qs = run_core(tmp_path, events=[data], extra={"THREATINTEL_CACHE": str(cache)})
    hits = [m for m in drain(qs["alert"]) if "THREAT INTEL" in str(m["data"].get("message"))]
    assert hits and {m["target_id"] for m in hits} == {bytes([10, 0, 0, 5])}


# --- alert targeting through the real core (TD-003, TD-007) -------------------------------

def _events(proto, src, dst, dports=(443,), n=1, payload=b"x", flags=0x18, sport=50000):
    from tests.test_capture import udp

    out = []
    for i in range(n):
        dport = dports[i % len(dports)]
        l4 = tcp(payload, sport=sport, dport=dport, flags=flags) if proto == 6 else udp(payload, sport=sport, dport=dport)
        data = parse_ethernet_frame(ethernet(ipv4(l4, proto, src, dst)), time.time() + i * 0.01)[1]
        data.update(sensor_id="t", interface="t")
        out.append(data)
    return out


def _alerts(tmp_path, events, extra=None, needle=""):
    qs = run_core(tmp_path, events=events, extra=extra)
    return [m for m in drain(qs["alert"]) if needle in str(m["data"].get("message"))]


def _ip(text):
    return bytes(int(p) for p in text.split("."))


def test_udp_flood_targets_the_local_source(tmp_path):
    hits = _alerts(tmp_path, _events(17, "192.168.1.10", "1.1.1.1", n=40), {"UDP_FLOOD_THRESHOLD": 5}, "FLOOD")
    assert hits and {m["target_id"] for m in hits} == {_ip("192.168.1.10")}


def test_port_sweep_targets_the_scanning_source(tmp_path):
    hits = _alerts(tmp_path, _events(6, "192.168.1.10", "192.168.1.77", dports=tuple(range(1000, 1020)), n=20,
                                     flags=0x02), {"SWEEP_THRESHOLD_PORTS": 5}, "PORT SCAN")
    assert hits and {m["target_id"] for m in hits} == {_ip("192.168.1.10")}


def test_port_sweep_counts_only_syns_and_skips_known_scanners(tmp_path):
    sweep = dict(dports=tuple(range(1000, 1020)), n=20)
    # The scanned gateway's SYN-ACK/RST replies to many ports are not a scan.
    for flags in (0x12, 0x14, 0x18):
        assert _alerts(tmp_path, _events(6, "192.168.1.1", "192.168.1.10", flags=flags, sport=2000, **sweep),
                       {"SWEEP_THRESHOLD_PORTS": 5}, "PORT SCAN") == []
    # A listed scanner is exempt; any other source sweeping the same way still fires.
    cfg = {"SWEEP_THRESHOLD_PORTS": 5, "SWEEP_IGNORE_SOURCES": ["192.168.1.10"]}
    assert _alerts(tmp_path, _events(6, "192.168.1.10", "192.168.1.77", flags=0x02, **sweep), cfg, "PORT SCAN") == []
    assert _alerts(tmp_path, _events(6, "192.168.1.11", "192.168.1.77", flags=0x02, **sweep), cfg, "PORT SCAN")
    # UDP keeps the old rule (no flags to read).
    assert _alerts(tmp_path, _events(17, "192.168.1.11", "192.168.1.77", **sweep), cfg, "PORT SCAN")


def test_inbound_quic_is_not_a_udp_flood(tmp_path):
    cfg = {"UDP_FLOOD_THRESHOLD": 5}
    assert _alerts(tmp_path, _events(17, "1.1.1.1", "192.168.1.10", n=40, sport=443), cfg, "FLOOD") == []
    assert _alerts(tmp_path, _events(17, "1.1.1.1", "192.168.1.10", n=40, sport=4500), cfg, "FLOOD")
    assert _alerts(tmp_path, _events(17, "192.168.1.10", "1.1.1.1", dports=(443,), n=40, sport=443), cfg, "FLOOD")


def test_tailscale_between_listed_nodes_is_not_a_udp_flood(tmp_path):
    rule = {"mac": "00:11:22:33:44:55", "networks": ["192.168.1.0/24"], "ports": [41641]}
    cfg = {"UDP_FLOOD_THRESHOLD": 5, "UDP_FLOOD_IGNORE_DEVICE_ENDPOINTS": [rule]}
    assert _alerts(tmp_path, _events(17, "192.168.1.10", "192.168.1.15", dports=(41641,), n=40), cfg, "FLOOD") == []
    # Another port, or the same port leaving the LAN, still counts.
    assert _alerts(tmp_path, _events(17, "192.168.1.10", "192.168.1.15", dports=(41642,), n=40), cfg, "FLOOD")
    assert _alerts(tmp_path, _events(17, "192.168.1.10", "1.1.1.1", dports=(41641,), n=40), cfg, "FLOOD")


def test_known_scanner_touching_lan_restricted_ports_is_not_a_threat_port(tmp_path):
    cfg = {"SWEEP_IGNORE_SOURCES": ["192.168.1.10"]}
    assert _alerts(tmp_path, _events(6, "192.168.1.10", "192.168.1.77", dports=(23,)), cfg, "THREAT PORT") == []
    assert _alerts(tmp_path, _events(6, "192.168.1.10", "1.1.1.1", dports=(23,)), cfg, "THREAT PORT")
    assert _alerts(tmp_path, _events(6, "192.168.1.11", "192.168.1.77", dports=(23,)), cfg, "THREAT PORT")


def test_exfil_targets_the_external_destination_never_the_lan_sender(tmp_path):
    hits = _alerts(tmp_path, _events(6, "192.168.1.10", "1.1.1.1", n=5, payload=b"x" * 1000),
                   {"EXFIL_THRESHOLD_BYTES": 2000}, "by 192.168.1.10")
    assert hits and {m["target_id"] for m in hits} == {_ip("1.1.1.1")}
    inbound = _alerts(tmp_path, _events(6, "1.1.1.1", "192.168.1.10", n=5, payload=b"x" * 1000),
                      {"EXFIL_THRESHOLD_BYTES": 2000}, "by ")
    assert inbound == []  # a download is not exfiltration



def test_exfil_window_exempts_only_its_device_networks_and_hours(tmp_path):
    from tests.test_capture import SRC_MAC
    mac, h = ":".join(f"{b:02x}" for b in SRC_MAC), time.localtime().tm_hour
    upload = _events(6, "192.168.1.10", "1.1.1.1", n=5, payload=b"x" * 1000)
    def cfg(networks, start, end):
        return {"EXFIL_THRESHOLD_BYTES": 2000,
                "EXFIL_IGNORE_DEVICE_WINDOWS": [{"mac": mac, "networks": networks, "hours": [start, end]}]}
    assert _alerts(tmp_path, upload, cfg(["1.1.1.0/24"], (h - 1) % 24, (h + 2) % 24), "by ") == []
    # Outside the hours, or to another network, the upload still alerts.
    assert _alerts(tmp_path, upload, cfg(["1.1.1.0/24"], (h + 3) % 24, (h + 5) % 24), "by ")
    assert _alerts(tmp_path, upload, cfg(["8.8.8.0/24"], (h - 1) % 24, (h + 2) % 24), "by ")



def test_tunnel_udp_ports_skip_flood_and_exfil(tmp_path):
    cfg = {"UDP_FLOOD_THRESHOLD": 5, "EXFIL_THRESHOLD_BYTES": 2000, "TUNNEL_UDP_PORTS": [41641]}
    out = _events(17, "192.168.1.10", "1.1.1.1", dports=(39428,), n=40, sport=41641, payload=b"x" * 1000)
    assert _alerts(tmp_path, out, cfg, "FLOOD") == [] and _alerts(tmp_path, out, cfg, "by ") == []
    other = _events(17, "192.168.1.10", "1.1.1.1", dports=(39428,), n=40, sport=41642, payload=b"x" * 1000)
    assert _alerts(tmp_path, other, cfg, "FLOOD") and _alerts(tmp_path, other, cfg, "by ")

def test_device_window_rule_and_wrapping_hours():
    from netwatch_flow import device_window_rule, in_hours
    assert device_window_rule({"mac": "00:11:22:33:44:55", "networks": ["0.0.0.0/0"], "hours": [1, 3]}) is None
    assert device_window_rule({"mac": "00:11:22:33:44:55", "networks": ["1.1.1.0/24"], "hours": [2, 2]}) is None
    assert device_window_rule({"mac": "00:11:22:33:44:55", "networks": ["1.1.1.0/24"]}) is None
    assert [h for h in range(24) if in_hours(h, 1, 3)] == [1, 2]
    assert [h for h in range(24) if in_hours(h, 23, 2)] == [0, 1, 23]

def test_restricted_port_targets_the_external_side_in_both_directions(tmp_path):
    out = _alerts(tmp_path, _events(6, "192.168.1.10", "1.1.1.1", dports=(3389,)), needle="THREAT PORT")
    assert out and {m["target_id"] for m in out} == {_ip("1.1.1.1")}
    inbound = _alerts(tmp_path, _events(6, "1.1.1.1", "192.168.1.10", dports=(3389,)), needle="THREAT PORT")
    assert inbound and {m["target_id"] for m in inbound} == {_ip("1.1.1.1")}


def _feed(tmp_path, *ranges):
    from netwatch_threatintel import IndicatorSet

    cache = tmp_path / "intel.json"
    IndicatorSet(ranges=[(int(ipaddress.ip_address(lo)), int(ipaddress.ip_address(hi)), "testfeed")
                         for lo, hi in ranges]).save(str(cache))
    return {"THREATINTEL_CACHE": str(cache)}


def test_intel_ip_hit_targets_the_bad_public_endpoint(tmp_path):
    extra = _feed(tmp_path, ("8.8.8.0", "8.8.8.255"))
    egress = _alerts(tmp_path, _events(6, "192.168.1.10", "8.8.8.8"), extra, "THREAT INTEL")
    assert egress and {m["target_id"] for m in egress} == {_ip("8.8.8.8")}
    inbound = _alerts(tmp_path, _events(6, "8.8.8.8", "192.168.1.10"), extra, "THREAT INTEL")
    assert inbound and {m["target_id"] for m in inbound} == {_ip("8.8.8.8")}


def test_accepted_egress_is_scoped_to_listed_mac_and_expires(tmp_path):
    from tests.test_capture import SRC_MAC

    extra = _feed(tmp_path, ("8.8.8.0", "8.8.8.255"))
    mac = ":".join(f"{b:02x}" for b in SRC_MAC)
    rule = {"macs": [mac], "cidrs": ["8.8.8.0/24"], "note": "test", "review_by": "2999-01-01"}
    events = _events(6, "192.168.1.10", "8.8.8.8")
    assert _alerts(tmp_path, events, extra, "THREAT INTEL") != []
    qs = run_core(tmp_path, events=events, extra={**extra, "ACCEPTED_EGRESS": [rule]})
    sent = drain(qs["alert"])
    assert not [m for m in sent if "THREAT INTEL" in str(m["data"].get("message"))]
    [info] = [m for m in sent if m["action"] == "ACCEPTED_EGRESS"]
    assert info["data"]["severity"] == "info" and info["data"]["src_mac"] == mac
    other = {**rule, "macs": ["02:00:00:00:00:99"]}  # another device still alerts
    assert _alerts(tmp_path, events, {**extra, "ACCEPTED_EGRESS": [other]}, "THREAT INTEL")
    expired = {**rule, "review_by": "2020-01-01"}  # past review_by: alerts again, one expiry info record
    qs = run_core(tmp_path, events=events, extra={**extra, "ACCEPTED_EGRESS": [expired]})
    sent = drain(qs["alert"])
    assert [m for m in sent if "THREAT INTEL" in str(m["data"].get("message"))]
    assert len([m for m in sent if m["action"] == "ACCEPTED_EGRESS_EXPIRED"]) == 1


@pytest.mark.parametrize("src,dst,lo,hi", [
    ("192.168.1.10", "192.168.1.77", "192.168.0.0", "192.168.255.255"),  # RFC1918 inside a bogon feed
    ("192.168.1.10", "224.0.0.251", "224.0.0.0", "239.255.255.255"),     # multicast
    ("169.254.5.5", "192.168.1.10", "169.254.0.0", "169.254.255.255"),   # link-local
])
def test_intel_never_matches_local_link_local_or_multicast_endpoints(tmp_path, src, dst, lo, hi):
    assert _alerts(tmp_path, _events(6, src, dst), _feed(tmp_path, (lo, hi)), "THREAT INTEL") == []


def test_core_sends_inventory_snapshot_to_durable_analysis(tmp_path):
    qs = run_core(tmp_path, count=2, macs=True, extra={"DEVICE_SAVE_INTERVAL_SEC": 0})
    snapshots = [m for m in drain(qs["inventory"]) if m["action"] == "INVENTORY_SNAPSHOT"]
    assert snapshots and {"02:00:00:00:00:00", "02:00:00:00:00:01"} <= {d["mac"] for d in snapshots[-1]["data"]["devices"]}


# --- F4: GeoIP faults are counted, not silent -------------------------------------------

def test_geo_fault_is_counted_in_the_one_second_log_and_row_keeps_placeholder(tmp_path, monkeypatch):
    import maxminddb

    class BadReader:
        def get(self, _ip):
            raise ValueError("bad address")

    monkeypatch.setattr(maxminddb, "open_database", lambda *_a, **_k: BadReader())
    messages = []
    handler = logging.Handler(logging.WARNING)
    handler.emit = lambda record: messages.append(record.getMessage())
    core_log = logging.getLogger("netwatch.core")  # propagate=False
    core_log.addHandler(handler)
    try:
        qs = run_core(tmp_path, count=5, linger=1.6)
    finally:
        core_log.removeHandler(handler)
    rows = [row for m in drain(qs["db"]) for row in m["data"].get("rows", [])]
    assert len(rows) == 1 and "--" in rows[0]  # one destination: 5 packets, one cached fault
    assert any("geo faults: 1" in m for m in messages)
