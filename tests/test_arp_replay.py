import ipaddress
import sqlite3
import struct

import pytest

from netwatch_arp import DurableArpAnalyzer
from netwatch_capture import parse_ethernet_frame
from netwatch_control import ControlCollector
from netwatch_security_store import DurableIncidentStore
from tests.test_capture import DST_MAC, ethernet

A = bytes.fromhex("80dac222fa03")
B = bytes.fromhex("deadbeef0001")


def record(collector, mac, timestamp, tag=None, received=100, ip="10.0.0.1"):
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, mac,
                       ipaddress.ip_address(ip).packed, DST_MAC, ipaddress.ip_address("10.0.0.15").packed)
    frame = ethernet(body, 0x0806) if tag is None else ethernet(struct.pack("!HH", tag, 0x0806) + body, 0x8100)
    return collector.process(frame, parse_ethernet_frame(frame, timestamp)[1], received_at=received)


def test_pending_confirmation_and_replay_position_survive_restart(tmp_path):
    path = tmp_path / "security.db"
    store = DurableIncidentStore(path)
    collector = ControlCollector(store, {})
    record(collector, A, 1, received=500)
    record(collector, B, 2, received=400)  # Receipt clocks do not define replay order.
    analyzer = DurableArpAnalyzer(store, {"GATEWAY_IP": "10.0.0.1"})
    assert analyzer.poll() == 2
    assert store.open_count() == 0
    store.close()
    store = DurableIncidentStore(path)
    collector = ControlCollector(store, {})
    record(collector, B, 3)
    confirmed = record(collector, B, 4)
    notifications = []
    analyzer = DurableArpAnalyzer(store, {"GATEWAY_IP": "10.0.0.1"}, notifications.append)
    assert analyzer.poll() == 2
    assert analyzer.poll() == 0
    assert len(notifications) == 1
    case = store.snapshot()[0]
    assert case["severity"] == "critical" and case["count"] == 1
    assert store.detections(case["incident_id"])[0]["payload"]["data"]["native_event_id"] == confirmed["event_id"]
    store.close()


def test_rebind_payload_carries_attackers_other_bound_ip(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    record(collector, A, 1)
    record(collector, B, 2, ip="10.0.0.77")
    for timestamp in (3, 4, 5):
        record(collector, B, timestamp)
    notifications = []
    DurableArpAnalyzer(store, {"GATEWAY_IP": "10.0.0.1"}, notifications.append).poll()
    data = notifications[0]["data"]
    assert data["offender_ip"] == "10.0.0.1" and data["offender_owned_ips"] == ["10.0.0.77"]
    store.close()


def test_analysis_fault_rolls_back_state_position_and_findings(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    record(collector, A, 1)
    record(collector, B, 2)
    record(collector, B, 3)
    record(collector, B, 4)
    analyzer = DurableArpAnalyzer(store, {})
    store.conn.execute("""CREATE TRIGGER fail_analysis BEFORE INSERT ON security_detections
                          BEGIN SELECT RAISE(ABORT, 'simulated storage fault'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        analyzer.poll()
    assert store.cursor(analyzer.cursor_key) is None
    assert store.open_count() == 0
    assert not store.conn.execute("SELECT 1 FROM security_source_cursors WHERE source_key LIKE 'ARP_STATE:%'").fetchall()
    store.conn.execute("DROP TRIGGER fail_analysis")
    assert analyzer.poll() == 4 and store.open_count() == 1
    assert analyzer.poll() == 0
    store.close()


def test_vlan_scopes_do_not_merge_owners_or_rebinding_cases(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    record(collector, A, 1, tag=10)
    record(collector, B, 1, tag=20)
    for timestamp in (2, 3, 4):
        record(collector, B, timestamp, tag=10)
        record(collector, A, timestamp, tag=20)
    analyzer = DurableArpAnalyzer(store, {})
    assert analyzer.poll() == 8
    assert len(store.snapshot()) == 2
    assert {tuple(row["payload"]["data"]["vlan_ids"]) for case in store.snapshot()
            for row in store.detections(case["incident_id"])} == {(10,), (20,)}
    store.close()


def test_source_commit_sequence_is_stable_after_database_vacuum(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    first = record(collector, A, 1)
    second = record(collector, B, 2)
    rows = store.source_stream("CONTROL", "arp")
    sequences = [row["sequence"] for row in rows]
    assert [row["event_id"] for row in rows] == [first["event_id"], second["event_id"]]
    store.conn.execute("VACUUM")
    assert [row["sequence"] for row in store.source_stream("CONTROL", "arp")] == sequences
    store.close()


def test_empty_arp_poll_never_takes_the_writer_lock(tmp_path):
    """An empty poll every 0.5 s waited out other writers and stalled the core loop on the sensor VM."""
    store = DurableIncidentStore(tmp_path / "security.db")
    analyzer = DurableArpAnalyzer(store, {})
    begins = []
    store.conn.set_trace_callback(lambda sql: sql == "BEGIN IMMEDIATE" and begins.append(sql))
    assert analyzer.poll() == 0 and begins == []
    store.close()


def test_unreplayable_arp_record_is_skipped_and_counted(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    record(collector, A, 1)
    store.accept_source_record("CONTROL:test", {"n": "bad"}, {
        "event_id": "bad", "source": "CONTROL", "sensor_id": "s", "event_type": "arp",
        "event_time": 2, "received_at": 2}, {"frame": "zz"})
    record(collector, B, 3)
    analyzer = DurableArpAnalyzer(store, {"GATEWAY_IP": "10.0.0.1"})
    assert analyzer.poll() == 2
    assert analyzer.skipped == 1 and analyzer.health()["skipped_records"] == 1
    assert analyzer.poll() == 0  # Cursor passed the bad row.
    store.close()


def test_new_scopes_past_cap_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("netwatch_arp.MAX_SCOPES", 2)
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    for i, tag in enumerate((1, 2, 3)):
        record(collector, A, i + 1, tag=tag)
    analyzer = DurableArpAnalyzer(store, {"GATEWAY_IP": "10.0.0.1"})
    analyzer.poll()
    count = store.conn.execute(
        "SELECT COUNT(*) FROM security_source_cursors WHERE source_key LIKE 'ARP_STATE:v1:%'").fetchone()[0]
    assert count == 2 and analyzer.scope_overflow == 1
    assert analyzer.health()["status"] == "DEGRADED"
    assert analyzer.poll() == 0  # Cursor advanced past the skipped frame.
    store.close()


def test_notify_failure_is_counted(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    record(collector, A, 1)
    for timestamp in (2, 3, 4):
        record(collector, B, timestamp)

    def boom(payload):
        raise RuntimeError("queue closed")

    analyzer = DurableArpAnalyzer(store, {"GATEWAY_IP": "10.0.0.1"}, boom)
    analyzer.poll()
    assert store.open_count() == 1  # the finding is committed despite the failed notify
    assert analyzer.health()["notify_failures"] == 1
    store.close()
