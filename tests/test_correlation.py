"""Cross-source correlation rules, saved hunts and per-rule false-positive counts."""

import copy
import json
import sqlite3
from pathlib import Path

import pytest

from netwatch_core import make_message
from netwatch_incidents import IncidentStore, load_rule_pack, validate_rule_pack
from netwatch_security_store import DurableIncidentStore, security_store_from_config

ROOT = Path(__file__).resolve().parent.parent
PACK = load_rule_pack(ROOT / "correlation_rules.json")
FIXTURES = ROOT / "tests" / "fixtures" / "correlation"
LOCAL = ("192.168.1.0/24",)
CID = "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def fixture(rule_id):
    return json.loads((FIXTURES / f"{rule_id}.json").read_text(encoding="utf-8"))


def detection(source, action, target, **data):
    data.setdefault("source_event_id", f"{source}-{action}-{len(data)}-{data.get('message', '')}")
    data.setdefault("message", f"{action}: finding")
    return make_message(source, action, target, data)


def suricata(event_id, **extra):
    data = {"severity": "alert", "src_ip": "192.168.1.20", "dst_ip": "203.0.113.9", "community_id": CID} | extra
    return detection("SURICATA", "SURICATA_ALERT", "203.0.113.9", source_event_id=event_id, **data)


def beacon(event_id, **extra):
    data = {"severity": "alert", "src_ip": "192.168.1.20", "dst_ip": "203.0.113.9", "community_id": CID} | extra
    return detection("DOD_CORE", "BEACON_ANOMALY", "203.0.113.9", source_event_id=event_id, **data)


@pytest.fixture
def store(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db", rule_pack=PACK, local_networks=LOCAL)
    yield store
    store.close()


def correlations(store, case_id):
    return [row["body"] for row in store.audit(case_id) if row["operation"] == "correlation"]


def test_every_shipped_rule_has_a_fixture_and_no_unproven_attack_claim():
    assert validate_rule_pack(json.loads((ROOT / "correlation_rules.json").read_text())) == PACK
    assert sorted(path.stem for path in FIXTURES.glob("*.json")) == sorted(rule["id"] for rule in PACK["rules"])
    for rule in PACK["rules"]:
        proven = set(fixture(rule["id"])["attack_demonstrated"])
        for mapping in rule.get("attack", []):
            # A technique may be marked demonstrated only when its fixture names it.
            assert not mapping["demonstrated"] or mapping["technique"] in proven, (rule["id"], mapping)
        assert proven <= {mapping["technique"] for mapping in rule.get("attack", [])}


@pytest.mark.parametrize("rule_id", [rule["id"] for rule in PACK["rules"]])
def test_rule_fixture_joins_two_sources_into_one_case(tmp_path, rule_id):
    case = fixture(rule_id)
    store = DurableIncidentStore(tmp_path / "security.db", rule_pack=PACK, local_networks=case["local_networks"])
    results = [store.add(make_message(item["source"], item["action"], item["target_id"], item["data"]),
                         now=1_700_000_000 + item["offset_sec"]) for item in case["detections"]]
    assert len(store.snapshot()) == 1
    joined = results[-1]
    assert joined["incident_id"] == results[0]["incident_id"]
    assert joined["rules"] == [rule_id]
    assert joined["sources"] == [item["source"] for item in case["detections"]]
    [audit] = correlations(store, joined["incident_id"])
    assert audit["rule"] == rule_id and audit["reason"].startswith(f"{rule_id} v1:")
    assert audit["confidence"] == {"from": "Observed", "to": "Low",
                                   "reason": f"independent corroboration by {case['detections'][-1]['source']}"}
    assert joined["confidence"] == "Low"
    assert len(store.detections(joined["incident_id"])) == 2
    store.close()


def test_rule_pack_validation_rejects_malformed_rules():
    rule = PACK["rules"][0]
    for broken in ({**rule, "sources": ["SURICATA"]}, {**rule, "join": "message"}, {**rule, "window_sec": 0},
                   {**rule, "extra": 1}, {**rule, "attack": [{"technique": "T1071"}]},
                   {**rule, "attack": [{"technique": "1071", "demonstrated": False}]},
                   {**rule, "match": {"action": []}}):
        with pytest.raises(ValueError):
            validate_rule_pack({"version": 1, "rules": [broken]})
    with pytest.raises(ValueError, match="duplicated"):
        validate_rule_pack({"version": 1, "rules": [rule, rule]})
    with pytest.raises(ValueError):
        validate_rule_pack({"version": 2, "rules": []})


def test_community_id_join_steps_confidence_once_per_new_source_and_never_severity(store):
    first = store.add(suricata("eve-1", severity="anomaly"), now=100)
    joined = store.add(beacon("beacon-1", severity="anomaly"), now=110)
    assert joined["incident_id"] == first["incident_id"]
    assert joined["severity"] == "anomaly" and joined["confidence"] == "Low"  # corroboration is not severity
    # A second finding from the same source joins but is not new corroboration.
    again = store.add(beacon("beacon-2", note="other"), now=120)
    assert again["incident_id"] == first["incident_id"] and again["confidence"] == "Low"
    assert [body.get("confidence") is not None for body in correlations(store, first["incident_id"])] == [True, False]
    # Severity is the highest member's own (beacon-2 is alert), never above it.
    assert again["severity"] == "alert" and again["sources"] == ["SURICATA", "DOD_CORE"]
    # A later uncorroborated Suricata detection of the same key does not undo the step.
    assert store.add(suricata("eve-2", severity="anomaly"), now=140)["confidence"] == "Low"


def test_asset_window_and_source_bounds(store):
    core = detection("DOD_CORE", "ALERT", "192.168.1.30", source_event_id="core-1", message="UDP_FLOOD: x")
    first = store.add(core, now=1000)
    late = store.add(suricata("eve-late", src_ip="192.168.1.30", community_id=None), now=1000 + 601)
    assert late["incident_id"] != first["incident_id"]  # outside XS-004's 600 s window
    # Same source never corroborates itself.
    other_core = detection("DOD_CORE", "BASELINE_ANOMALY", "192.168.1.30", source_event_id="core-2",
                           severity="alert")
    assert store.add(other_core, now=1001)["incident_id"] != first["incident_id"]


def test_closed_case_never_absorbs_a_new_source(store):
    first = store.add(detection("DOD_CORE", "ALERT", "192.168.1.31", source_event_id="core-1"), now=1000)
    store.update_case(first["incident_id"], actor="test", status="Resolved", closure_reason="done")
    later = store.add(detection("SURICATA", "SURICATA_ALERT", "198.51.100.1", source_event_id="eve-9",
                                severity="alert", src_ip="192.168.1.31", dst_ip="198.51.100.1"), now=1001)
    assert later["incident_id"] != first["incident_id"] and later["rules"] == []
    assert store.get(first["incident_id"])["status"] == "Resolved"


def test_without_a_rule_pack_sources_stay_separate(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db", local_networks=LOCAL)
    assert store.add(suricata("eve-1"), now=1)["incident_id"] != store.add(beacon("beacon-1"), now=2)["incident_id"]
    assert store.rule_stats() == {"pack_version": None, "rules": []}
    store.close()


def test_pure_correlator_uses_the_same_rules():
    pure = IncidentStore(rules=PACK["rules"], local_networks=LOCAL)
    first = pure.add(suricata("eve-1"), now=1)
    joined = pure.add(beacon("beacon-1"), now=2)
    assert joined["incident_id"] == first["incident_id"] and joined["rules"] == ["XS-002"]
    assert pure.last_correlation["rule"] == "XS-002" and len(pure._incidents) == 1


def test_cases_written_before_sources_existed_still_join(store):
    first = store.add(suricata("eve-1"), now=1)
    with store._transaction():
        body = json.loads(store.conn.execute("SELECT body FROM security_incidents").fetchone()[0])
        del body["sources"], body["rules"]
        store.conn.execute("UPDATE security_incidents SET body=?", (json.dumps(body),))
    joined = store.add(beacon("beacon-1"), now=2)
    assert joined["incident_id"] == first["incident_id"]
    assert joined["sources"] == ["SURICATA", "DOD_CORE"] and joined["confidence"] == "Low"


def test_closed_correlated_case_is_pruned_with_its_keys(store):
    first = store.add(suricata("eve-1"), now=1)
    store.add(beacon("beacon-1"), now=2)
    store.update_case(first["incident_id"], actor="test", status="Resolved", closure_reason="done")
    store.prune_metadata(retention_days=0, case_retention_days=1, now=10 * 86400)
    assert store.get(first["incident_id"]) is None
    assert store._read("SELECT COUNT(*) FROM security_correlation_keys")[0][0] == 0


def test_false_positive_counters_per_rule(store):
    first = store.add(suricata("eve-1"), now=1)
    store.add(beacon("beacon-1"), now=2)
    other = store.add(detection("DOD_CORE", "ALERT", "192.168.1.40", source_event_id="core-1"), now=3)
    store.add(detection("SURICATA", "SURICATA_ALERT", "198.51.100.2", source_event_id="eve-9", severity="alert",
                        src_ip="192.168.1.40", dst_ip="198.51.100.2"), now=4)
    store.update_case(first["incident_id"], actor="test", status="Dismissed",
                      closure_reason="False positive: lab scanner")
    store.update_case(other["incident_id"], actor="test", status="Resolved", closure_reason="true positive, fixed")
    stats = {rule["id"]: rule for rule in store.rule_stats()["rules"]}
    assert store.rule_stats()["pack_version"] == 1
    assert (stats["XS-002"]["matches"], stats["XS-002"]["false_positive_closures"]) == (1, 1)
    assert (stats["XS-004"]["matches"], stats["XS-004"]["false_positive_closures"]) == (1, 0)
    assert stats["XS-003"]["matches"] == 0 and stats["XS-002"]["attack"][0]["demonstrated"] is False


def test_store_from_config_loads_the_pack_and_locality(tmp_path):
    config = {"INCIDENT_DB": str(tmp_path / "a.db"), "CORRELATION_RULES": str(ROOT / "correlation_rules.json"),
              "LOCAL_PREFIXES": LOCAL, "LOCAL_PREFIXES6": ()}
    store = security_store_from_config(config)
    assert [rule["id"] for rule in store.rules] == ["XS-002", "XS-003", "XS-004"]
    assert store.local_networks == LOCAL
    store.close()
    missing = security_store_from_config({**config, "INCIDENT_DB": str(tmp_path / "b.db"),
                                          "CORRELATION_RULES": str(tmp_path / "absent.json")})
    assert missing.rules == []
    missing.close()
    (tmp_path / "bad.json").write_text('{"version": 1, "rules": [{"id": "x"}]}')
    with pytest.raises(ValueError):
        security_store_from_config({**config, "CORRELATION_RULES": str(tmp_path / "bad.json")})


def test_core_flow_detections_carry_the_ledger_community_id():
    from netwatch_capture import parse_ethernet_frame
    from netwatch_db import row_community_id
    from netwatch_workers import detection_community_id
    from tests.test_capture import ethernet, ipv4, tcp
    from tests.test_community_id import ledger_row

    frame = ethernet(ipv4(tcp(sport=34855, dport=80), 6, "128.232.110.120", "66.35.250.204"))
    _, event = parse_ethernet_frame(frame, timestamp=10.5)
    cid = detection_community_id(event, event["src_ip"], event["dst_ip"])
    assert cid == row_community_id(ledger_row(frame)) == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert detection_community_id({**event, "source_port": None}, event["src_ip"], event["dst_ip"]) is None


# --- saved hunts -------------------------------------------------------------

def seed_sources(store):
    for event_id, src, cid in (("a", "192.168.1.20", CID), ("b", "192.168.1.21", None)):
        normalized = {"event_id": event_id, "source": "SURICATA", "sensor_id": "s", "event_type": "conn",
                      "event_time": 50.0, "received_at": 50.0, "src_ip": src, "dst_ip": "203.0.113.9",
                      "destination_port": 443, "community_id": cid}
        store.accept_source_record("SURICATA:test", {"offset": event_id}, normalized, {"flow_id": event_id})


def test_hunts_are_bound_parameters_with_one_audit_row_per_run(store, tmp_path):
    seed_sources(store)
    hunt = store.create_hunt("conn-by-src", "source_events", {"event_type": "conn", "src_ip": "192.168.1.20"},
                             actor="tester", limit=10, description="one host")
    assert store.list_hunts() == [hunt]
    assert [row["event_id"] for row in store.run_hunt("conn-by-src", actor="tester")["rows"]] == ["a"]
    overridden = store.run_hunt("conn-by-src", {"src_ip": "192.168.1.21"}, actor="tester")
    assert [row["event_id"] for row in overridden["rows"]] == ["b"]
    # Injection attempts: values are bound, so they match nothing and alter nothing.
    for value in ("' OR 1=1 --", "192.168.1.20' OR '1'='1", "x'); DROP TABLE security_hunts; --"):
        assert store.run_hunt("conn-by-src", {"src_ip": value}, actor="tester")["rows"] == []
    assert len(store.list_hunts()) == 1
    runs = store.hunt_runs("conn-by-src")
    assert len(runs) == 5 and runs[0]["actor"] == "tester" and runs[0]["body"]["rows"] == 0
    assert runs[-1]["body"] == {"filters": {"event_type": "conn", "src_ip": "192.168.1.20"}, "rows": 1}
    for name, target, filters, limit in (
            ("x; DROP TABLE security_hunts", "source_events", {}, 10),
            ("ok", "security_incidents", {}, 10),
            ("ok", "source_events", {"1=1 OR source": "x"}, 10),
            ("ok", "source_events", {"src_ip": {"$ne": 1}}, 10),
            ("ok", "source_events", {"src_ip": "x" * 257}, 10),
            ("ok", "source_events", {}, 501),
            ("conn-by-src", "source_events", {}, 10)):
        with pytest.raises(ValueError):
            store.create_hunt(name, target, filters, actor="tester", limit=limit)
    with pytest.raises(ValueError):
        store.run_hunt("conn-by-src", {"source = 'SURICATA' OR 1": 1}, actor="tester")
    with pytest.raises(ValueError):
        store.run_hunt("missing", actor="tester")
    assert len(store.hunt_runs("conn-by-src")) == 5


def test_ledger_hunt_reuses_the_history_filters(store, tmp_path):
    ledger = tmp_path / "packets.db"
    with sqlite3.connect(ledger) as conn:
        conn.execute("CREATE TABLE network_events (uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, "
                     "mac_dst TEXT, src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER, tcp_flags TEXT, "
                     "ttl INTEGER, size_bytes INTEGER, sni_domain TEXT, country TEXT)")
        conn.executemany("INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            ("u1", 1.0, "m", "m", "192.168.1.20", "203.0.113.9", "TCP", 443, "", 64, 60, "example.com", "US"),
            ("u2", 2.0, "m", "m", "192.168.1.21", "203.0.113.9", "TCP", 80, "", 64, 60, "example.org", "US")])
    store.create_hunt("https", "ledger", {"port": 443}, actor="tester")
    result = store.run_hunt("https", actor="tester", ledger_path=str(ledger))
    assert [row["uuid"] for row in result["rows"]] == ["u1"]
    assert store.run_hunt("https", {"src": "' OR 1=1 --"}, actor="tester", ledger_path=str(ledger))["rows"] == []
    with pytest.raises(ValueError):
        store.run_hunt("https", {"port": "443 OR 1=1"}, actor="tester", ledger_path=str(ledger))
    with pytest.raises(ValueError):
        store.create_hunt("bad", "ledger", {"community_id = '' OR 1": 1}, actor="tester")


# --- API -----------------------------------------------------------------

@pytest.fixture
def service(tmp_path):
    from types import SimpleNamespace

    from netwatch_api import ServiceAPI, load_secret
    from netwatch_client import ServiceClient

    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence"), "LOG_DIR": str(tmp_path / "logs"),
              "LOG_TO_CONSOLE": False, "DEVICE_LEDGER": str(tmp_path / "devices.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json")}
    store = DurableIncidentStore(config["INCIDENT_DB"], rule_pack=copy.deepcopy(PACK), local_networks=LOCAL)
    supervisor = SimpleNamespace(store=store, runtime=SimpleNamespace(config=config))
    secret = load_secret(tmp_path / "api.secret", create=True)
    api = ServiceAPI(supervisor, secret, port=0).start()
    yield api, ServiceClient(f"http://127.0.0.1:{api.server.server_port}", secret, timeout=1)
    api.close()
    store.close()


def test_api_rules_and_hunts_require_auth_and_validate(service):
    from urllib.error import HTTPError
    from urllib.request import ProxyHandler, Request, build_opener

    api, client = service
    for endpoint in ("rules", "hunts"):
        with pytest.raises(HTTPError) as rejected:
            build_opener(ProxyHandler({})).open(Request(client.url + "/v1/" + endpoint))
        assert rejected.value.code == 401
    with pytest.raises(HTTPError) as rejected:
        build_opener(ProxyHandler({})).open(Request(client.url + "/v1/hunts", method="POST", data=b"{}",
                                                    headers={"Authorization": "Bearer " + "00" * 32}))
    assert rejected.value.code == 401

    first = api.store.add(suricata("eve-1"), now=1)
    api.store.add(beacon("beacon-1"), now=2)
    api.store.update_case(first["incident_id"], actor="t", status="Dismissed", closure_reason="false positive")
    rules = {rule["id"]: rule for rule in client.request("rules")["data"]["rules"]}
    assert rules["XS-002"]["matches"] == 1 and rules["XS-002"]["false_positive_closures"] == 1

    seed_sources(api.store)
    created = client.request("hunts", {"op": "create", "name": "by-cid", "target": "source_events",
                                       "filters": {"community_id": CID}})["data"]
    assert created["created_by"] == "authenticated-console"
    assert client.request("hunts")["data"] == [created]
    ran = client.request("hunts", {"op": "run", "name": "by-cid"})["data"]
    assert [row["event_id"] for row in ran["rows"]] == ["a"]
    assert api.store.hunt_runs("by-cid")[0]["actor"] == "authenticated-console"
    for bad in ({"op": "run", "name": "by-cid", "params": {"src_ip; --": 1}},
                {"op": "create", "name": "x", "target": "source_events", "filters": {}, "actor": "me"},
                {"op": "drop", "name": "by-cid"}, {"op": "run", "name": "nope"}):
        with pytest.raises(HTTPError) as rejected:
            client.request("hunts", bad)
        assert rejected.value.code == 400
