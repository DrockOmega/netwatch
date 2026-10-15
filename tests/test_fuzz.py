"""Seeded robustness tests for every parser fed attacker-controlled bytes or JSON.

Each test runs a bounded number of deterministic mutations (see ``tests/fuzzing.py``) so CI stays fast.
The contract under test is the one each parser documents: the capture parser and TLS fingerprinter never
raise; normalizers return JSON-encodable, bounded envelopes; native collectors never stall on one record;
the control collector always records a frame; the service API answers bad input with 400, never 500.
"""

import http.client
import json
import re
import struct
from types import SimpleNamespace

import pytest

from netwatch_api import ServiceAPI, load_secret
from netwatch_capture import parse_ethernet_frame
from netwatch_control import ControlCollector
from netwatch_core import is_message_payload
from netwatch_ja3 import fingerprint
from netwatch_security_store import DurableIncidentStore, _encode, _event_time
from netwatch_suricata import EveCollector, normalize_eve_event, normalize_eve_record
from tests.fuzzing import json_roundtrip, mutate_bytes, mutate_json, rng_for
from tests.test_capture import SRC_MAC, dns_query, ethernet, ipv4, ipv6, tcp, udp
from tests.test_control import dhcp6_frame, dhcp_frame, ra_frame
from tests.test_ja3 import build_client_hello, build_server_hello

CLIENT_HELLO = build_client_hello()
SERVER_HELLO = build_server_hello()
ARP = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, SRC_MAC, bytes([10, 0, 0, 1]), b"\0" * 6, bytes([10, 0, 0, 2]))
FRAMES = [
    ethernet(ipv4(tcp(CLIENT_HELLO), 6)),
    ethernet(ipv4(tcp(SERVER_HELLO, sport=443, dport=50000), 6)),
    ethernet(ipv4(udp(dns_query()), 17)),
    ethernet(ipv6(udp(dns_query()), 17), 0x86DD),
    ethernet(ipv4(tcp(struct.pack("!H", len(dns_query())) + dns_query(), dport=53), 6)),
    ethernet(struct.pack("!HH", 7, 0x0800) + ipv4(tcp(CLIENT_HELLO), 6), 0x8100),
    ethernet(ipv6(bytes([6, 0]) + b"\0" * 6 + tcp(CLIENT_HELLO), 0), 0x86DD),  # hop-by-hop then TCP
    ethernet(ARP, 0x0806),
    ethernet(ipv4(bytes([8, 0, 0, 0, 0, 0, 0, 0]), 1)),
    ra_frame(), dhcp_frame(), dhcp6_frame()[0],
    ethernet(b"\x02\x01\x00\x00", 0x888e),
]
EVE_SEEDS = [
    {"timestamp": "2026-10-08T00:00:00.000000+0000", "flow_id": 1, "event_type": "alert", "src_ip": "10.0.0.2",
     "src_port": 1, "dest_ip": "8.8.8.8", "dest_port": 443, "proto": "TCP", "community_id": "1:" + "A" * 27 + "=",
     "alert": {"signature": "x", "signature_id": 1, "rev": 1, "severity": 1, "action": "allowed", "category": "c"},
     "vlan": [1]},
    {"event_type": "stats", "timestamp": 1, "stats": {"capture": {"kernel_drops": 1}}},
    {"event_type": "flow", "src_ip": "::1", "dest_ip": "fe80::1", "src_port": 5, "dest_port": 6},
    {"event_type": "anomaly", "anomaly": {"event": "x"}},
    {"event_type": "drop", "verdict": {"action": "drop"}},
]
LOCAL = ("10.0.0.0/8", "2001:db8::/32")
HEX32 = re.compile(r"[0-9a-f]{32}")
JA4 = re.compile(r"t[0-9a-z]{2}[di]\d{4}[0-9a-zA-Z]{2}_[0-9a-f]{12}_[0-9a-f]{12}")
# Lines that each stalled a native collector before the fixes they name.
POISON_LINES = [
    '{"event_type":"alert","x":' + "[" * 100_000 + "]" * 100_000 + "}",  # RecursionError in json.loads
    '{"event_type":"alert","x":' + "[" * 100 + "]" * 100 + "}",  # parses, too deep to re-encode safely
    '{"event_type":"alert","timestamp":1' + "0" * 400 + ',"ts":1' + "0" * 400 + "}",  # float() OverflowError
    '{"event_type":"alert","x":"\\ud800"}',  # lone surrogate: store's UTF-8 encode failed
    '{"event_type":[],"_path":"conn"}',  # unhashable event_type
]


def _port(value):
    return value is None or 0 <= value <= 65535


def test_ethernet_frame_parser_never_raises_and_stays_bounded():
    rng = rng_for("capture")
    for _ in range(3000):
        frame = mutate_bytes(rng, rng.choice(FRAMES))
        result = parse_ethernet_frame(frame, timestamp=1.0, tls_fingerprint=fingerprint)
        if result is None:
            continue
        kind, data = result
        assert kind in {"packet", "arp", "control"}
        assert len(data["vlan_ids"]) <= 2 and all(0 <= vid <= 4095 for vid in data["vlan_ids"])
        if kind != "packet":
            continue
        assert len(data["src_ip"]) == len(data["dst_ip"]) and len(data["src_ip"]) in (4, 16)
        assert _port(data["port"]) and _port(data["source_port"]) and 0 <= data["ttl"] <= 255
        assert data["size_bytes"] == len(frame) and len(data["control_payload"]) <= len(frame)
        assert data["dns_qname"] is None or len(data["dns_qname"]) <= 64 * 64
        assert data["icmp_type"] is None or 0 <= data["icmp_type"] <= 255
        assert data["ja3"] is None or HEX32.fullmatch(data["ja3"])
        assert data["ja3s"] is None or HEX32.fullmatch(data["ja3s"])


def test_tls_fingerprint_never_raises_and_returns_canonical_hashes():
    rng = rng_for("ja3")
    for _ in range(3000):
        result = fingerprint(mutate_bytes(rng, rng.choice([CLIENT_HELLO, SERVER_HELLO])))
        if result is None:
            continue
        assert result["kind"] in {"ja3", "ja3s"} and HEX32.fullmatch(result["hash"])
        assert result["sni"] is None or isinstance(result["sni"], str)
        if result["kind"] == "ja3":
            assert JA4.fullmatch(result["ja4"]), result["ja4"]
        json.dumps(result)


def _check_envelope(normalized):
    _encode(normalized)  # the store's encoder: no NaN, no unencodable types
    assert _port(normalized["source_port"]) and _port(normalized["destination_port"])
    assert isinstance(normalized["event_time"], float)
    assert normalized["direction"] in {"egress", "ingress", "lateral", "ambiguous"}


def _check_detection(message):
    assert is_message_payload(message)
    assert message["target_id"] == "SYSTEM" or len(message["target_id"]) in (4, 16)
    assert message["data"]["containment_eligible"] == (message["target_id"] != "SYSTEM")
    _encode(message)


def test_eve_normalizers_tolerate_hostile_records():
    rng = rng_for("eve")
    for _ in range(1500):
        event = json_roundtrip(mutate_json(rng, rng.choice(EVE_SEEDS)))
        if not isinstance(event, dict):
            continue
        _check_envelope(normalize_eve_record(event, event_id="e", sensor_id="s", reference={},
                                             received_at=1.0, local_networks=LOCAL))
        detection = normalize_eve_event(event, LOCAL)
        if detection is not None:
            _check_detection(detection)



def test_event_time_rejects_integers_beyond_float_range():
    assert _event_time(10**400, "fallback") == "fallback"
    assert _event_time(-(10**400), None) is None


def test_native_collector_never_stalls_on_hostile_lines(tmp_path):
    rng = rng_for("lines-SURICATA")
    lines = list(POISON_LINES)
    for _ in range(120):
        if rng.random() < 0.5:
            lines.append(json.dumps(mutate_json(rng, rng.choice(EVE_SEEDS))))
        else:
            raw = mutate_bytes(rng, json.dumps(rng.choice(EVE_SEEDS)).encode()).replace(b"\n", b" ")
            lines.append(raw.decode("utf-8", errors="replace"))
    path = tmp_path / "eve.json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="fuzz")
    collector = EveCollector(store, {"SURICATA_EVE_PATH": str(path), "DISK_MIN_FREE_BYTES": 0,
                                     "LOCAL_PREFIXES": ["10.0.0.0/8"]})
    try:
        consumed = sum(collector.poll() for _ in range(3))  # a stalled record raises here
        assert consumed == len(lines)
        records = store.source_events("SURICATA", limit=1000)
        assert len(records) == len(lines)
        rejected = [r for r in records if r["native"].get("reason") == "invalid_native_json"]
        assert len(rejected) >= 3  # the deep, too-deep and surrogate poison lines are kept as errors
    finally:
        collector.close()
        store.close()


def test_control_collector_records_every_mutated_control_frame(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    rng = rng_for("control")
    controls = [frame for frame in FRAMES[7:]]
    processed = 0
    try:
        for index in range(400):
            frame = mutate_bytes(rng, rng.choice(controls))
            parsed = parse_ethernet_frame(frame, timestamp=1.0)
            if parsed is None or not (parsed[0] in {"arp", "control"} or parsed[1].get("control_type")):
                continue
            normalized = collector.process(frame, parsed[1], event_id=f"fuzz-{index}", received_at=2.0)
            assert normalized["capture_bytes"] == len(frame)
            assert len(_encode(normalized)) < 1_048_576
            processed += 1
        assert processed > 100
    finally:
        store.close()


@pytest.fixture
def api(tmp_path):
    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence")}
    store = DurableIncidentStore(config["INCIDENT_DB"])
    secret = load_secret(tmp_path / "api.secret", create=True)
    service = ServiceAPI(SimpleNamespace(store=store, runtime=SimpleNamespace(config=config)), secret, port=0).start()

    def send(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", service.server.server_port, timeout=5)
        try:
            conn.request(method, path, body=body, headers={"Authorization": "Bearer " + secret.hex(),
                                                           "Content-Type": "application/json"})
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    yield send
    service.close()
    store.close()


def test_service_api_answers_hostile_requests_without_server_errors(api):
    rng = rng_for("api")
    writes = [("/v1/cases", {"case": "x", "status": "Investigating", "note": "n", "acknowledge": True}),
              ("/v1/actions", {"op": "request", "kind": "block_ip", "target": "203.0.113.5", "reason": "r",
                               "expires_at": 4e9, "case": "c"}),
              ("/v1/actions", {"op": "approve", "id": "abc"})]
    reads = ["/v1/health", "/v1/actions?state=requested&case=x", "/v1/detections?case=x", "/v1/workflow?case=x",
             "/v1/flows/1%3A" + "A" * 27 + "%3D", "/v1/gaps", "/v1/sources",
             "/v1/feed?after=" + "9" * 40, "/v1/feed?after=1:2&limit=-5", "/v1/feed?limit=x"]
    for index in range(240):
        if index % 3 == 2:
            mutated = mutate_bytes(rng, rng.choice(reads).encode()).decode("latin-1")
            status = api("GET", "/" + "".join(ch for ch in mutated if 0x21 <= ord(ch) < 0x7F))
        else:
            path, body = rng.choice(writes)
            raw = (json.dumps(mutate_json(rng, body)).encode() if rng.random() < 0.5
                   else mutate_bytes(rng, json.dumps(body).encode()))
            status = api("POST", path, raw[:65536] or b"{}")
        assert status in (200, 400)
    assert api("GET", "/v1/health") == 200


def test_service_api_rejects_nesting_bomb_as_bad_request(api):
    # Python 3.12's json raises RecursionError here; it used to escape as a 500.
    assert api("POST", "/v1/cases", b"[" * 32_000 + b"]" * 32_000) == 400
    assert api("POST", "/v1/cases", b'{"case":' + b"[" * 32_000 + b"]" * 32_000 + b"}") == 400
    assert api("GET", "/v1/health") == 200
