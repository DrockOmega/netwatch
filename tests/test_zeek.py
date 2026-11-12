import json
import queue
import threading
import time

from netwatch_config import DEFAULTS
from netwatch_security_store import DurableIncidentStore
from netwatch_zeek import ZeekCollector, normalize_zeek_notice, normalize_zeek_record, zeek_log_process, zeek_log_type

LOCAL = ("10.0.0.0/8", "2001:db8:1::/64")


def conn_id(orig="10.0.0.12", resp="8.8.8.8", orig_p=51515, resp_p=443):
    return {"id.orig_h": orig, "id.orig_p": orig_p, "id.resp_h": resp, "id.resp_p": resp_p}


FIXTURES = {
    "conn": {"ts": 1700000000.25, "uid": "CAbc1", **conn_id(), "proto": "tcp", "service": "ssl",
             "duration": 1.5, "conn_state": "SF", "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg="},
    "dns": {"ts": 1700000001.0, "uid": "CDns1", **conn_id(resp="8.8.4.4", resp_p=53), "proto": "udp",
            "query": "example.com", "qtype_name": "A", "rcode_name": "NOERROR"},
    "http": {"ts": 1700000002.0, "uid": "CHttp1", **conn_id(resp_p=80), "method": "GET",
             "host": "example.com", "uri": "/", "status_code": 200},
    "ssl": {"ts": 1700000003.0, "uid": "CSsl1", **conn_id(), "version": "TLSv13", "server_name": "example.com"},
    "files": {"ts": 1700000004.0, "fuid": "FAbc1", "uid": "CHttp1", **conn_id(resp_p=80),
              "source": "HTTP", "mime_type": "text/html", "sha256": "00" * 32},
    "weird": {"ts": 1700000005.0, "uid": "CW1", **conn_id(), "name": "bad_TCP_checksum", "notice": False},
    "notice": {"ts": 1700000006.0, "uid": "CN1", **conn_id(orig="203.0.113.9", resp="10.0.0.12", resp_p=22),
               "proto": "tcp", "note": "SSH::Password_Guessing", "msg": "203.0.113.9 guessed passwords",
               "src": "203.0.113.9", "dst": "10.0.0.12", "actions": ["Notice::ACTION_LOG"]},
}
CATEGORIES = {"conn": "network_session", "dns": "network_protocol", "http": "network_protocol",
              "ssl": "network_protocol", "files": "network_protocol", "weird": "network_protocol",
              "notice": "detection"}


def normalize(native, log_type, **kwargs):
    return normalize_zeek_record(native, log_type, event_id="e1", sensor_id="sensor-a",
                                 reference={"path": f"/x/{log_type}.log"}, received_at=1800000000.0,
                                 local_networks=LOCAL, **kwargs)


def append(path, *records):
    with path.open("ab") as handle:
        for event in records:
            handle.write(json.dumps(event).encode() + b"\n")


def collector(tmp_path, **config):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    return store, ZeekCollector(store, {"ZEEK_LOG_PATHS": [str(tmp_path / "*.log")],
                                        "LOCAL_PREFIXES": ["10.0.0.0/8"], **config})


def test_each_log_type_normalizes_to_the_common_envelope():
    for log_type, native in FIXTURES.items():
        row = normalize(native, log_type)
        assert row["source"] == "ZEEK" and row["schema_version"] == 1
        assert row["event_type"] == log_type
        assert row["category"] == CATEGORIES[log_type]
        assert row["event_time"] == native["ts"] and row["integrity_flags"] == []
        assert row["flow_id"] == native["uid"]
        assert row["src_ip"] == native["id.orig_h"] and row["dst_ip"] == native["id.resp_h"]
        assert row["source_port"] == native["id.orig_p"] and row["destination_port"] == native["id.resp_p"]
        assert row["address_family"] == 4
    conn = normalize(FIXTURES["conn"], "conn")
    assert conn["community_id"] == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert (conn["protocol"], conn["application"], conn["direction"]) == ("TCP", "ssl", "egress")
    assert normalize(FIXTURES["dns"], "dns")["application"] == "dns"
    assert normalize(FIXTURES["notice"], "notice")["rule_id"] == "SSH::Password_Guessing"
    assert normalize(FIXTURES["notice"], "notice")["direction"] == "ingress"


def test_ipv6_iso_time_and_missing_fields_are_not_invented():
    native = {"ts": "2023-11-14T22:13:20.000000Z", "uid": "C6",
              **conn_id(orig="2001:db8:1::5", resp="2606:4700::1111", orig_p=40000, resp_p=443),
              "proto": "udp", "community_id": "1:v6"}
    row = normalize(native, "conn")
    assert row["address_family"] == 6 and row["direction"] == "egress"
    assert row["src_ip"] == "2001:db8:1::5" and row["community_id"] == "1:v6"
    assert row["event_time"] == 1700000000.0
    bare = normalize({"note": "x", "id.orig_p": True}, "notice")
    assert bare["src_ip"] is None and bare["source_port"] is None and bare["address_family"] is None
    assert bare["event_time"] == 1800000000.0 and bare["integrity_flags"] == ["receipt-time-fallback"]


def test_log_type_comes_from_path_including_rotated_names():
    assert zeek_log_type({}, "/zeek/conn.log") == "conn"
    assert zeek_log_type({}, "/zeek/conn.2026-10-08-12-00-00.log") == "conn"
    assert zeek_log_type({"_path": "notice"}, "/zeek/stream.log") == "notice"
    assert zeek_log_type({"event_type": "collector_gap"}, "/zeek/conn.log") == "collector_gap"


def test_notice_containment_only_with_unambiguous_offender():
    inbound = normalize_zeek_notice(FIXTURES["notice"], LOCAL)
    assert inbound["action"] == "ZEEK_NOTICE" and inbound["data"]["severity"] == "alert"
    assert inbound["target_id"] == bytes([203, 0, 113, 9])
    assert inbound["data"]["containment_eligible"] is True
    # A scan notice names only its source: no single target is proven.
    scan = normalize_zeek_notice({"note": "Scan::Port_Scan", "src": "203.0.113.9"}, LOCAL)
    assert scan["target_id"] == "SYSTEM" and scan["data"]["containment_eligible"] is False
    external = normalize_zeek_notice({"note": "X", "src": "198.51.100.1", "dst": "203.0.113.9"}, LOCAL)
    assert external["data"]["direction"] == "ambiguous" and external["data"]["containment_eligible"] is False


def test_notice_becomes_one_committed_detection_and_restart_does_not_duplicate(tmp_path):
    append(tmp_path / "notice.log", FIXTURES["notice"])
    append(tmp_path / "conn.log", FIXTURES["conn"])
    store, source = collector(tmp_path)
    notifications = []
    assert source.poll(notifications.append, now=1700000010) == 2
    assert [n["action"] for n in notifications] == ["ZEEK_NOTICE"]
    case = store.snapshot()[0]
    assert case["action"] == "ZEEK_NOTICE" and case["count"] == 1
    assert store.detections(case["incident_id"])[0]["payload"]["data"]["source_event_id"] == \
        store.source_events("ZEEK", event_type="notice")[0]["event_id"]
    source.close()
    store.close()
    store, source = collector(tmp_path)
    assert source.poll(notifications.append, now=1700000020) == 0
    assert len(notifications) == 1 and store.get(case["incident_id"])["count"] == 1
    assert {row["event_type"] for row in store.source_events("ZEEK")} == {"notice", "conn"}
    source.close()
    store.close()


def test_rotation_and_restart_collect_every_record_once(tmp_path):
    path = tmp_path / "conn.log"
    append(path, FIXTURES["conn"])
    store, source = collector(tmp_path)
    assert source.poll(now=1700000010) == 1
    rotated = tmp_path / "conn.2026-10-08-12-00-00.log"
    path.rename(rotated)
    append(rotated, {**FIXTURES["conn"], "uid": "C2"})
    append(path, {**FIXTURES["conn"], "uid": "C3"})
    assert source.poll(now=1700000010) == 2
    source.close()
    append(path, {**FIXTURES["conn"], "uid": "C4"})
    source = ZeekCollector(store, {"ZEEK_LOG_PATHS": [str(tmp_path / "*.log")]})
    assert source.poll(now=1700000010) == 1
    assert source.poll(now=1700000010) == 0
    assert sorted(row["normalized"]["flow_id"] for row in store.source_events("ZEEK")) == ["C2", "C3", "C4", "CAbc1"]
    source.close()
    store.close()


def test_partial_line_waits_and_separate_path_entries_each_get_a_reader(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    line = json.dumps(FIXTURES["dns"]).encode()
    (tmp_path / "a" / "dns.log").write_bytes(line[:20])
    append(tmp_path / "b" / "http.log", FIXTURES["http"])
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    source = ZeekCollector(store, {"ZEEK_LOG_PATHS": [str(tmp_path / "a" / "dns.log"), str(tmp_path / "b" / "*.log")]})
    assert len(source.readers) == 2
    assert source.poll(now=1700000010) == 1
    assert source.health(1700000010)["status"] == "PARTIAL_WRITE"
    with (tmp_path / "a" / "dns.log").open("ab") as handle:
        handle.write(line[20:] + b"\n")
    assert source.poll(now=1700000010) == 1
    assert {row["event_type"] for row in store.source_events("ZEEK")} == {"dns", "http"}
    source.close()
    store.close()


def test_health_waiting_fresh_stale_degraded_from_conn_freshness(tmp_path):
    store, source = collector(tmp_path, ZEEK_SOURCE_TIMEOUT_SEC=60)
    source.poll(now=1700000000)
    assert source.health(1700000000)["status"] == "WAITING"
    append(tmp_path / "dns.log", FIXTURES["dns"])
    source.poll(now=1700000010)
    assert source.health(1700000010)["status"] == "UNVERIFIED"  # no conn.log record yet
    append(tmp_path / "conn.log", FIXTURES["conn"])
    source.poll(now=1700000010)
    health = source.health(1700000010)
    assert health["status"] == "FRESH" and health["engine_fresh"] and health["conn_age_sec"] == 9.75
    assert source.health(1700000100)["status"] == "STALE"
    source.close()
    source = ZeekCollector(store, {"ZEEK_LOG_PATHS": [str(tmp_path / "*.log")]})
    assert source.last_conn_time == FIXTURES["conn"]["ts"]  # restored from the durable store
    with (tmp_path / "conn.log").open("ab") as handle:
        handle.write(b"{not json}\n")
    source.poll(now=1700000010)
    assert source.health(1700000010)["status"] == "DEGRADED"
    assert store.source_events("ZEEK", event_type="collector_error")
    source.close()
    store.close()


def test_worker_commits_records_and_health_and_stops_cleanly(tmp_path):
    append(tmp_path / "conn.log", {**FIXTURES["conn"], "ts": time.time()})
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "ZEEK_LOG_PATHS": [str(tmp_path / "*.log")],
              "SENSOR_ID": "test-sensor", "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    status = queue.Queue()
    shutdown = threading.Event()
    worker = threading.Thread(target=zeek_log_process, args=(queue.Queue(), config, status, shutdown))
    worker.start()
    try:
        heartbeat = status.get(timeout=5)
        assert heartbeat["source"] == "ZEEK" and heartbeat["data"]["status"] == "FRESH"
    finally:
        shutdown.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    store = DurableIncidentStore(config["INCIDENT_DB"], sensor_id="test-sensor")
    assert len(store.source_events("ZEEK")) == 1
    assert store.source_health("SOURCE:ZEEK:test-sensor")["status"] == "FRESH"
    store.close()


def test_config_defaults_disable_zeek_and_resolve_relative_globs(tmp_path, monkeypatch):
    from netwatch_config import build_config

    assert DEFAULTS["ZEEK_LOGS_ENABLED"] is False
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    config, _ = build_config(str(tmp_path), hostname="nohost")
    assert config["ZEEK_LOG_PATHS"] == [str(tmp_path / "zeek" / "*.log")]
