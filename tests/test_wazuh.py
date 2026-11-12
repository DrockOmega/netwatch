import json
import queue
import threading
import time

from netwatch_config import DEFAULTS
from netwatch_core import community_id_v1
from netwatch_security_store import DurableIncidentStore
from netwatch_wazuh import WazuhCollector, normalize_wazuh_record, wazuh_alert_process

LOCAL = ("10.0.0.0/8",)
AGENT = {"id": "002", "name": "sensor1", "ip": "10.0.0.20"}
FIXTURES = {
    "sudo": {"timestamp": "2026-10-08T08:34:39.100+0000", "agent": {"id": "000", "name": "netwatch-sensor"},
             "rule": {"level": 3, "id": "5402", "description": "Successful sudo to ROOT executed.",
                      "groups": ["syslog", "sudo"], "mitre": {"id": ["T1548.003"]}},
             "data": {"srcuser": "netadmin", "dstuser": "root"}},
    "process": {"timestamp": "2026-10-08T08:35:00.000+0000", "agent": AGENT,
                "rule": {"level": 12, "id": "92052", "description": "Suspicious cmd.exe",
                         "groups": ["sysmon"], "mitre": {"id": ["T1059.003"]}},
                "data": {"win": {"system": {"eventID": "1"}, "eventdata": {
                    "image": "C:\\Windows\\System32\\cmd.exe", "commandLine": "cmd /c whoami", "user": "SENSOR\\d",
                    "processId": "4242", "hashes": "SHA1=aa,MD5=bb,SHA256=cc,IMPHASH=dd"}}}},
    "network": {"timestamp": "2026-10-08T08:36:00.000+0000", "agent": AGENT,
                "rule": {"level": 8, "id": "92100", "description": "Sysmon network connection",
                         "groups": ["sysmon"], "mitre": {"id": ["T1071"]}},
                "data": {"win": {"system": {"eventID": "3"}, "eventdata": {
                    "image": "C:\\x\\a.exe", "sourceIp": "10.0.0.20", "sourcePort": "51515",
                    "destinationIp": "198.51.100.7", "destinationPort": "443", "protocol": "tcp"}}}},
}


def normalize(native, **kwargs):
    return normalize_wazuh_record(native, event_id="e1", sensor_id="s", reference={}, received_at=1.0,
                                  local_networks=LOCAL, **kwargs)


def append(path, *records):
    with path.open("ab") as handle:
        for event in records:
            handle.write((event if isinstance(event, bytes) else json.dumps(event).encode()) + b"\n")


def collector(tmp_path, **config):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="s")
    return store, WazuhCollector(store, {"WAZUH_ALERTS_PATH": str(tmp_path / "alerts.json"),
                                         "LOCAL_PREFIXES": ["10.0.0.0/8"], **config})


def test_normalization_keeps_agent_rule_process_and_joins_network_by_community_id():
    row = normalize(FIXTURES["process"])
    assert row["source"] == "WAZUH" and row["category"] == "detection" and row["event_time"] == 1791448500.0
    assert row["agent"] == {**AGENT, "address": "10.0.0.20"} and row["rule"]["level"] == 12 and row["rule"]["mitre_ids"] == ["T1059.003"]
    assert row["process"]["command_line"] == "cmd /c whoami"
    assert row["process"]["hashes"] == {"sha1": "aa", "md5": "bb", "sha256": "cc", "imphash": "dd"}
    net = normalize(FIXTURES["network"])
    assert net["community_id"] == community_id_v1(6, "10.0.0.20", 51515, "198.51.100.7", 443)
    assert (net["src_ip"], net["destination_port"], net["direction"], net["protocol"]) == \
        ("10.0.0.20", 443, "egress", "TCP")
    sudo = normalize(FIXTURES["sudo"])
    assert sudo["category"] == "endpoint_event" and sudo["process"] is None and sudo["community_id"] is None
    assert normalize(FIXTURES["sudo"], min_level=3)["category"] == "detection"


def test_hostile_fields_are_bounded_not_trusted():
    row = normalize({"timestamp": "x", "rule": {"level": True, "id": "9" * 9999, "groups": "no", "mitre": []},
                     "agent": [], "data": {"win": {"eventdata": {"image": "i" * 99999, "hashes": "A=" + "b" * 999}}}})
    assert row["rule"]["level"] == 0 and len(row["rule"]["id"]) == 64 and row["rule"]["groups"] == []
    assert len(row["process"]["image"]) == 4096 and row["process"]["hashes"] == {}
    assert row["integrity_flags"] == ["receipt-time-fallback"] and row["agent"]["name"] is None


def test_only_high_level_alerts_raise_one_detection_and_restart_does_not_duplicate(tmp_path):
    append(tmp_path / "alerts.json", FIXTURES["sudo"], FIXTURES["process"], FIXTURES["network"])
    store, source = collector(tmp_path)
    seen = []
    assert source.poll(seen.append, now=1791448600) == 3
    assert [m["data"]["rule_id"] for m in seen] == ["92052", "92100"]
    assert seen[0]["data"]["severity"] == "critical" and seen[1]["data"]["severity"] == "alert"
    assert len(store.snapshot()) == 2 and len(store.source_events("WAZUH")) == 3
    source.close()
    store.close()
    store, source = collector(tmp_path, WAZUH_MIN_ALERT_LEVEL=3)
    assert source.poll(seen.append, now=1791448600) == 0 and len(seen) == 2
    source.close()
    store.close()


def test_rotation_truncation_and_malformed_line_are_survived_and_counted(tmp_path):
    path = tmp_path / "alerts.json"
    append(path, FIXTURES["sudo"])
    store, source = collector(tmp_path)
    assert source.poll(now=1791448600) == 1
    path.rename(tmp_path / "alerts.json.1")
    append(tmp_path / "alerts.json.1", b"{not json", FIXTURES["process"])
    append(path, FIXTURES["network"])
    assert source.poll(now=1791448600) == 3
    health = source.health(1791448600)
    assert health["status"] == "DEGRADED" and health["invalid_records"] == 1
    assert store.source_events("WAZUH", event_type="collector_error")
    assert source.poll(now=1791448600) == 0
    path.write_bytes(b"")  # truncated in place
    append(path, FIXTURES["sudo"])
    assert source.poll(now=1791448600) == 1  # the new alert; the gap diagnostic is not counted
    assert store.source_events("WAZUH", event_type="collector_gap")
    source.close()
    store.close()


def test_health_waiting_fresh_stale(tmp_path):
    store, source = collector(tmp_path, WAZUH_SOURCE_TIMEOUT_SEC=60)
    assert source.health(1791448600)["status"] == "WAITING"
    append(tmp_path / "alerts.json", FIXTURES["sudo"])
    source.poll(now=1791448500)
    assert source.health(1791448500)["status"] == "FRESH"
    assert source.health(1791448900)["status"] == "STALE"
    source.close()
    store.close()


def test_worker_commits_records_and_health_and_stops_cleanly(tmp_path):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime())
    append(tmp_path / "alerts.json", {**FIXTURES["process"], "timestamp": stamp})
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "WAZUH_ALERTS_PATH": str(tmp_path / "alerts.json"),
              "SENSOR_ID": "test-sensor", "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    alerts, status, shutdown = queue.Queue(), queue.Queue(), threading.Event()
    worker = threading.Thread(target=wazuh_alert_process, args=(alerts, config, status, shutdown))
    worker.start()
    try:
        assert status.get(timeout=5)["data"]["status"] == "FRESH"
        assert alerts.get(timeout=5)["action"] == "WAZUH_ALERT"
    finally:
        shutdown.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    store = DurableIncidentStore(config["INCIDENT_DB"], sensor_id="test-sensor")
    assert store.source_health("SOURCE:WAZUH:test-sensor")["status"] == "FRESH"
    store.close()


def test_config_defaults_disable_wazuh_with_level_seven():
    assert DEFAULTS["WAZUH_ALERTS_ENABLED"] is False and DEFAULTS["WAZUH_MIN_ALERT_LEVEL"] == 7


def test_loopback_or_any_agent_ip_uses_configured_address_and_keeps_reported_value():
    mapping = {"sensor1": "10.0.0.12"}
    for reported in ("127.0.0.1", "any", "0.0.0.0", "::1"):
        native = {**FIXTURES["process"], "agent": {**AGENT, "ip": reported}}
        agent = normalize(native, agent_addresses=mapping)["agent"]
        assert (agent["ip"], agent["address"]) == (reported, "10.0.0.12")
    assert normalize(FIXTURES["process"], agent_addresses=mapping)["agent"]["address"] == "10.0.0.20"
    loopback = {**FIXTURES["process"], "agent": {**AGENT, "ip": "127.0.0.1"}}
    assert normalize(loopback)["agent"]["address"] == "127.0.0.1"  # unmapped agent: nothing invented


def test_health_separates_lagging_collector_from_stopped_engine(tmp_path):
    store, source = collector(tmp_path, WAZUH_SOURCE_TIMEOUT_SEC=60)
    path = tmp_path / "alerts.json"
    append(path, FIXTURES["sudo"], FIXTURES["sudo"])
    source.poll(now=1791448500)
    append(path, FIXTURES["process"])  # written but not yet read: the collector is behind
    now = path.stat().st_mtime + 1
    source.last_event_time = now - 600
    health = source.health(now)
    assert health["status"] == "LAGGING" and not health["engine_fresh"]
    assert health["lag_bytes"] > 0 and health["file_growing"] and health["lag_sec"] > 60
    stopped = source.health(now + 120)  # same backlog, but the file stopped growing
    assert stopped["status"] == "STALE" and stopped["file_growing"] is False
    source.close()
    store.close()
