"""Packet-path equivalence: a fixed frame mix through the parser and the analytics core must
reproduce the golden capture recorded from the pre-optimisation code, field for field.

``packet_mix.pcap.gz`` is a synthetic sensor mix (bulk TCP both ways, TLS hellos, DNS, HTTP, QUIC,
ARP, ICMP/ICMPv6/ND, DHCP, VLAN, IPv6); the crafted tail drives every packet-path detector.
Regenerate the golden only for an intended output change:
``NETWATCH_REGEN_GOLDEN=1 pytest tests/test_packet_path_equivalence.py``.
"""

import gzip
import hashlib
import ipaddress
import json
import os
import queue
import re
import struct
import threading
import time
from datetime import datetime
from pathlib import Path

import netwatch_workers
from netwatch_capture import parse_ethernet_frame
from netwatch_core import make_message
from netwatch_ja3 import fingerprint as ja3_fingerprint
from tests.test_capture import dns_query, ipv4, tcp, udp
from tests.test_core_publish import worker_config
from tests.test_replay import read_pcap

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDEN = FIXTURES / "packet_path_golden.json.gz"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
LAN_MAC, GW_MAC = bytes.fromhex("02aabb0000fe"), bytes.fromhex("001122334401")
PACKET_ACTIONS = {"ALERT", "BEACON_ANOMALY", "DNS_ANOMALY", "JA3_ANOMALY", "POLICY_DECISION", "DEVICE_NEW"}


def _eth(payload, ether_type=0x0800, src=LAN_MAC, dst=GW_MAC):
    return dst + src + struct.pack("!H", ether_type) + payload


def _nxdomain(name):
    query = dns_query(name)
    return struct.pack("!HH", 1, 0x8183) + query[4:]


def frames():
    records = read_pcap(gzip.decompress((FIXTURES / "packet_mix.pcap.gz").read_bytes()))
    t = records[-1][0] + 1.0
    tail = []
    for port in range(1, 61):  # port sweep
        tail.append((t + port * 0.01, _eth(ipv4(tcp(sport=41000, dport=port, flags=0x02), 6, "192.168.1.66",
                                                "203.0.113.9"))))
    for n in range(150):  # UDP flood
        tail.append((t + 1 + n * 0.005, _eth(ipv4(udp(b"f" * 64, 40000, 9999), 17, "192.168.1.67", "8.8.4.4"))))
    for n in range(250):  # egress volume
        tail.append((t + 2 + n * 0.004, _eth(ipv4(tcp(b"e" * 1400, 40001, 443), 6, "192.168.1.68", "93.184.216.34"))))
    tail.append((t + 3.1, _eth(ipv4(tcp(sport=40002, dport=3389, flags=0x02), 6, "192.168.1.69", "198.51.100.7"))))
    tail.append((t + 3.2, _eth(ipv4(udp(dns_query("malicious-c2.com"), 40003, 53), 17, "192.168.1.70",
                                    "192.168.1.1"))))
    tail.append((t + 3.3, _eth(ipv4(udp(dns_query("xkqzvbnmwqpltrzz.biz"), 40004, 53), 17, "192.168.1.70",
                                    "192.168.1.1"))))
    for n in range(12):  # NXDOMAIN burst
        tail.append((t + 4 + n * 0.1, _eth(ipv4(udp(_nxdomain(f"h{n}.missing.example"), 53, 40005), 17,
                                                "192.168.1.1", "192.168.1.71"), src=GW_MAC, dst=LAN_MAC)))
    for n in range(8):  # periodic beacon: a fresh connection every 10 s
        tail.append((t + 6 + n * 10, _eth(ipv4(tcp(sport=42000 + n, dport=8443, flags=0x02), 6, "192.168.1.72",
                                               "93.184.216.35"))))
    return records + tail


def _canonical(value):
    if isinstance(value, bytes | bytearray | memoryview):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_canonical(v) for v in value]
    if isinstance(value, str):
        return UUID.sub("<uuid>", value)
    return value


def parsed_events():
    events = []
    for stamp, frame in frames():
        result = parse_ethernet_frame(frame, stamp, ja3_fingerprint)
        events.append(None if result is None else [result[0], _canonical(result[1])])
    return events


def _drain(q):
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            return items


def core_outputs(tmp_path):
    config = dict(worker_config(tmp_path), GC_INTERVAL_SEC=10**9, DEVICE_SAVE_INTERVAL_SEC=10**9,
                  BASELINE_WINDOW_SEC=10**9, EXFIL_THRESHOLD_BYTES=300_000, UDP_FLOOD_THRESHOLD=100,
                  SENSOR_ID="golden")
    events = []
    for stamp, frame in frames():  # exactly what process_frame ships to the core
        result = parse_ethernet_frame(frame, stamp, ja3_fingerprint)
        if result is None or result[0] != "packet":
            continue
        data = result[1]
        data["sensor_id"], data["interface"] = "golden", "eq0"
        data.pop("control_payload", None)
        events.append(data)
    ingest = queue.Queue()
    first_get = threading.Event()
    real_get = ingest.get

    def get(*args, **kwargs):
        first_get.set()
        return real_get(*args, **kwargs)

    ingest.get = get
    qs = {name: queue.Queue() for name in ("render", "alert", "policy", "db", "evidence", "status", "inventory")}
    stop = threading.Event()
    thread = threading.Thread(target=netwatch_workers.dod_core_process, daemon=True, args=(
        ingest, qs["render"], qs["alert"], qs["policy"], qs["db"], qs["evidence"], config, qs["status"], qs["inventory"], stop))
    thread.start()
    assert first_get.wait(20)
    time.sleep(0.3)  # the signature loader thread has read its file before the first packet
    for start in range(0, len(events), 512):
        ingest.put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": events[start:start + 512]}))
    deadline = time.time() + 60
    while time.time() < deadline and not ingest.empty():
        time.sleep(0.05)
    time.sleep(1.5)  # one more DB commit tick after the last batch
    stop.set()
    thread.join(20)
    assert not thread.is_alive()

    render, observations = [], []
    for message in _drain(qs["render"]):
        for event in message["data"]["events"]:
            event = dict(event)
            assert event.pop("time_str") == datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
            event.pop("event_id")
            render.append(event)
        # time_str is local-time text of the timestamp (checked above for render): drop it so the golden is timezone-independent.
        observations.extend({k: v for k, v in o.items() if k != "time_str"} for o in message["data"]["observations"])
    # DB batch boundaries follow the wall clock, so compare per-key totals, not batches.
    ledger = {}
    for message in _drain(qs["db"]):
        for row in message["data"]["rows"]:
            key = json.dumps(_canonical([int(row[1]), *row[2:8], row[9], row[11], row[12], *row[14:]]))
            flags, size, count = ledger.get(key, ("", 0, 0))
            ledger[key] = ("".join(sorted(set(flags + row[8]))), size + row[10], count + row[13])
    alerts = [[m["action"], m["source"], m["target_id"], m["data"]]
              for m in _drain(qs["alert"]) if m["action"] in PACKET_ACTIONS]
    return _canonical({"render": render, "observations": observations, "ledger": sorted(ledger.items()),
                       "alerts": alerts, "policy": [m["data"] for m in _drain(qs["policy"])]})


def _golden():
    return json.loads(gzip.decompress(GOLDEN.read_bytes()))


def _record(section, value):
    golden = _golden() if GOLDEN.exists() else {}
    golden[section] = value
    GOLDEN.write_bytes(gzip.compress(json.dumps(golden, sort_keys=True).encode(), 9, mtime=0))


def _assert_same(section, actual):
    if os.environ.get("NETWATCH_REGEN_GOLDEN"):
        _record(section, actual)
    expected = _golden()[section]
    actual = json.loads(json.dumps(actual))  # tuples and key order as the golden stores them
    if actual != expected:
        if isinstance(expected, dict):
            bad = [key for key in expected if actual.get(key) != expected[key]]
            first = {key: next(((i, a, e) for i, (a, e) in enumerate(zip(actual[key], expected[key], strict=False))
                                if a != e), (len(actual[key]), len(expected[key]))) for key in bad}
            raise AssertionError(f"{section} differs in {bad}: first difference {first}")
        index = next(i for i, (a, e) in enumerate(zip(actual, expected, strict=False)) if a != e)
        raise AssertionError(f"{section} differs at frame {index}: {actual[index]} != {expected[index]}")


def test_fixture_covers_every_packet_family():
    kinds = {(kind, data.get("protocol"), data.get("control_type"), bool(data.get("vlan_ids")),
              len(bytes.fromhex(data["src_ip"]["$bytes"])) if "src_ip" in data else 0)
             for kind, data in filter(None, parsed_events())}
    assert {("arp", None, None, False, 0), ("packet", "TCP", None, True, 4), ("packet", "TCP", None, False, 16),
            ("packet", "ICMPv6", "ipv6_ns", False, 16), ("packet", "UDP", "dhcp", False, 4),
            ("packet", "ICMP", "icmp", False, 4)} <= kinds
    hashed = [data for kind, data in filter(None, parsed_events()) if kind == "packet"]
    assert any(d["ja3"] for d in hashed) and any(d["ja3s"] for d in hashed) and any(d["dns_qr"] for d in hashed)


def test_parser_output_matches_golden():
    _assert_same("parser", parsed_events())


def test_core_output_matches_golden(tmp_path):
    outputs = core_outputs(tmp_path)
    assert {a[0] for a in outputs["alerts"]} >= {"ALERT", "BEACON_ANOMALY", "DNS_ANOMALY", "DEVICE_NEW"}
    assert {"PORT SCAN", "UDP FLOOD", "EXFIL", "THREAT PORT", "THREAT DOMAIN"} <= {
        msg for a in outputs["alerts"] for msg in ("PORT SCAN", "UDP FLOOD", "EXFIL", "THREAT PORT", "THREAT DOMAIN")
        if msg in a[3]["message"]}
    _assert_same("core", outputs)


def test_golden_is_reproducible(tmp_path):
    # The core is wall-clock driven in places; the normalisation above must make two runs identical.
    first = hashlib.sha256(json.dumps(core_outputs(tmp_path / "a"), sort_keys=True).encode()).hexdigest()
    second = hashlib.sha256(json.dumps(core_outputs(tmp_path / "b"), sort_keys=True).encode()).hexdigest()
    assert first == second


def test_geo_lookup_runs_once_per_destination(tmp_path, monkeypatch):
    import maxminddb

    calls = []

    class Reader:
        def get(self, ip):
            calls.append(ip)
            octet = int(ipaddress.ip_address(ip).packed[0])
            return {"country": {"iso_code": f"C{octet % 7}"}} if octet % 3 else None

    monkeypatch.setattr(maxminddb, "open_database", lambda *_args: Reader())
    render = core_outputs(tmp_path)["render"]
    for event in render:
        dst = bytes.fromhex(event["dst"]["$bytes"])
        assert event["country"] == (f"C{dst[0] % 7}" if dst[0] % 3 else "--")
    assert len(calls) == len(set(calls)) == len({event["dst"]["$bytes"] for event in render})
