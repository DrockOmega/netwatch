import json
import queue
import sqlite3
import threading
import time
from datetime import UTC, datetime

import pytest

from netwatch_security_store import DurableIncidentStore
from netwatch_suricata import EveCollector, suricata_eve_process


def record(kind="alert", timestamp=100, **fields):
    return {"event_type": kind, "timestamp": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            "src_ip": "10.0.0.12", "dest_ip": "8.8.8.8", "src_port": 12345,
            "dest_port": 443, "proto": "TCP", "app_proto": "tls", **fields}


def append(path, *records):
    with path.open("ab") as handle:
        for event in records:
            handle.write(json.dumps(event).encode() + b"\n")


def collector(tmp_path, path=None, **config):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    return store, EveCollector(store, {"SURICATA_EVE_PATH": str(path or tmp_path / "eve.json"),
                                      "LOCAL_PREFIXES": ["10.0.0.0/8"], **config})


def test_all_native_families_retain_tuple_and_source_fields_without_incidents(tmp_path):
    path = tmp_path / "eve.json"
    kinds = ["flow", "dns", "http", "tls", "ssh", "smb", "fileinfo", "stats", "future_protocol"]
    append(path, *(record(kind, community_id="1:reference", vlan=[42], in_iface="eth0",
                         future_field={"preserved": True}) for kind in kinds))
    store, source = collector(tmp_path)
    assert source.poll(now=100) == len(kinds)
    native = store.source_events("SURICATA")
    assert {row["event_type"] for row in native} == set(kinds)
    assert store.open_count() == 0
    assert native[0]["normalized"]["source_port"] == 12345
    assert native[0]["normalized"]["direction"] == "egress"
    assert native[0]["normalized"]["vlan_ids"] == [42]
    assert native[0]["normalized"]["community_id"] == "1:reference"
    assert all(row["native"]["future_field"]["preserved"] for row in native)
    source.close()
    store.close()


def test_partial_write_then_restart_keeps_byte_checkpoint_and_exact_counts(tmp_path):
    path = tmp_path / "eve.json"
    line = json.dumps(record()).encode()
    path.write_bytes(line[:40])
    store, source = collector(tmp_path)
    assert source.poll(now=100) == 0
    assert source.health(100)["status"] == "PARTIAL_WRITE"
    assert store.source_events("SURICATA") == []
    source.close()
    with path.open("ab") as handle:
        handle.write(line[40:] + b"\n")
        handle.write(line + b"\n")  # Separate identical native events keep separate offsets.
    source = EveCollector(store, {"SURICATA_EVE_PATH": str(path)})
    assert source.poll(now=100) == 2
    case = store.snapshot()[0]
    assert case["count"] == 2
    assert len(store.source_events("SURICATA")) == 2
    source.close()
    source = EveCollector(store, {"SURICATA_EVE_PATH": str(path)})
    assert source.poll(now=100) == 0
    assert store.get(case["incident_id"])["count"] == 2
    source.close()
    store.close()


def test_expanding_file_pattern_does_not_replay_already_committed_file(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record())
    store, source = collector(tmp_path)
    source.poll(now=100)
    source.close()
    source = EveCollector(store, {"SURICATA_EVE_PATH": str(tmp_path / "eve*.json")})
    assert source.poll(now=100) == 0
    assert store.snapshot()[0]["count"] == 1
    source.close()
    store.close()


def test_rename_rotation_drains_old_descriptor_and_reads_new_file_after_restart(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record())
    store, source = collector(tmp_path)
    assert source.poll(now=100) == 1
    rotated = tmp_path / "eve.json.1"
    path.rename(rotated)
    append(rotated, record("dns", timestamp=101))
    append(path, record("flow", timestamp=102))
    assert source.poll(now=102) == 2
    source.close()
    append(rotated, record("tls", timestamp=103))
    append(path, record(timestamp=104))
    source = EveCollector(store, {"SURICATA_EVE_PATH": str(path)})
    assert source.poll(now=104) == 2
    assert len(store.source_events("SURICATA")) == 5
    source.close()
    store.close()


def test_truncate_and_regrow_beyond_checkpoint_reports_gap_and_reads_new_generation(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record("flow"))
    store, source = collector(tmp_path)
    source.poll(now=100)
    path.write_bytes((json.dumps(record("dns", timestamp=101, padding="x" * 1000)) + "\n").encode())
    assert source.poll(now=101) == 1
    rows = store.source_events("SURICATA")
    assert {row["event_type"] for row in rows} == {"flow", "dns", "collector_gap"}
    assert source.health(101)["status"] == "DEGRADED"
    source.close()
    store.close()


def test_failed_native_commit_never_advances_cursor_or_notifies(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record())
    store, source = collector(tmp_path)
    store.conn.execute("""CREATE TRIGGER reject_native BEFORE INSERT ON security_source_events
                          BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")
    notifications = []
    with pytest.raises(sqlite3.IntegrityError):
        source.poll(notifications.append, now=100)
    key = next(iter(source.reader.handles))
    assert store.cursor(key)["offset"] == 0
    assert store.open_count() == 0
    assert not notifications
    assert source.health(100)["status"] == "DEGRADED"
    store.conn.execute("DROP TRIGGER reject_native")
    assert source.poll(notifications.append, now=100) == 1
    assert len(notifications) == 1
    assert store.cursor(key)["offset"] == path.stat().st_size
    source.close()
    store.close()


def test_initial_history_skip_is_explicit_and_glob_collects_thread_files(tmp_path):
    for name in ("eve.1.json", "eve.2.json"):
        append(tmp_path / name, record())
    store, source = collector(tmp_path, path=tmp_path / "eve.*.json", SURICATA_EVE_START_AT_END=True)
    assert source.poll(now=100) == 0
    gaps = store.source_events("SURICATA", event_type="collector_gap")
    assert len(gaps) == 2
    assert all(row["native"]["skipped_bytes"] > 0 for row in gaps)
    append(tmp_path / "eve.1.json", record("flow", timestamp=101))
    assert source.poll(now=101) == 1
    source.close()
    store.close()


def test_bad_and_oversized_records_become_visible_loss_records(tmp_path):
    path = tmp_path / "eve.json"
    path.write_bytes(b'{"event_type":"stats","bad":NaN}\n' + b'x' * 1_048_600 + b'\n')
    append(path, record("dns"))
    store, source = collector(tmp_path)
    assert source.poll(now=100) == 3
    rows = store.source_events("SURICATA")
    assert [row["native"]["reason"] for row in rows if row["event_type"] == "collector_error"] == [
        "invalid_native_json", "record_size_limit"]
    assert source.health(100)["status"] == "DEGRADED"
    assert len(store.source_events("SURICATA", event_type="dns")) == 1
    source.close()
    store.close()


def test_fresh_reader_does_not_make_stale_or_undated_engine_stats_healthy(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record("flow"))
    store, source = collector(tmp_path)
    source.poll(now=100)
    assert source.health(100)["status"] == "UNVERIFIED"
    append(path, record("stats", timestamp=10, stats={"capture": {"kernel_packets": 100, "kernel_drops": 0}}))
    source.poll(now=100)
    assert source.health(100)["status"] == "STALE"
    append(path, record("stats", timestamp=100, stats={"capture": {"kernel_packets": 110, "kernel_drops": 0}}))
    source.poll(now=100)
    assert source.health(100)["status"] == "FRESH"
    assert source.health(100)["capture_deltas"]["kernel_packets"] == 10
    assert source.health(161)["status"] == "STALE"
    append(path, record("stats", timestamp=101, stats={"capture": {"kernel_packets": 120, "kernel_drops": 2}}))
    source.poll(now=101)
    assert source.health(101)["status"] == "DEGRADED"
    append(path, record("stats", timestamp=102, stats={"capture": {"kernel_packets": 0, "kernel_drops": 0}}))
    source.poll(now=102)
    assert source.health(102)["counter_reset"] is True
    append(path, {"event_type": "stats", "stats": {}})
    source.poll(now=103)
    assert source.health(103)["status"] == "UNVERIFIED"
    append(path, {"event_type": "stats", "timestamp": 1e308, "stats": {}})
    source.poll(now=104)
    assert source.health(104)["status"] == "UNVERIFIED"
    assert store.source_events("SURICATA", limit=1)[0]["normalized"]["integrity_flags"] == ["receipt-time-fallback"]
    source.close()
    store.close()


def test_many_completed_rotation_files_are_deferred_without_losing_records(tmp_path):
    for index in range(70):
        append(tmp_path / f"eve.{index}.json", record("flow", timestamp=100 + index))
    store, source = collector(tmp_path, path=tmp_path / "eve.*.json")
    assert source.poll(now=170) == 64
    assert source.health(170)["status"] == "DEGRADED"
    assert source.poll(now=170) == 6
    assert len(store.source_events("SURICATA")) == 70
    assert len(source.reader.handles) == 0
    source.close()
    store.close()


def test_worker_commits_native_records_and_source_health_and_stops_cleanly(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record("stats", timestamp=time.time(), stats={"capture": {"kernel_packets": 1}}))
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "SURICATA_EVE_PATH": str(path),
              "EVIDENCE_CAPTURE_ENABLED": False, "SENSOR_ID": "test-sensor",
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    status = queue.Queue()
    shutdown = threading.Event()
    worker = threading.Thread(target=suricata_eve_process,
                              args=(queue.Queue(), queue.Queue(), config, status, shutdown))
    worker.start()
    try:
        heartbeat = status.get(timeout=5)
        assert heartbeat["data"]["status"] == "FRESH"
        assert heartbeat["data"]["reader_alive"] is True
    finally:
        shutdown.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    store = DurableIncidentStore(config["INCIDENT_DB"], sensor_id="test-sensor")
    assert len(store.source_events("SURICATA")) == 1
    channel = store.conn.execute("SELECT source_key FROM security_source_health").fetchone()[0]
    assert store.source_health(channel)["status"] == "FRESH"
    store.close()


def test_start_at_end_skips_only_first_discovery_not_rotated_in_file(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record())
    store, source = collector(tmp_path, SURICATA_EVE_START_AT_END=True)
    assert source.poll(now=100) == 0
    path.rename(tmp_path / "eve.json.1")
    append(path, record("flow", timestamp=101))
    assert source.poll(now=101) == 1
    assert not store.source_events("SURICATA", event_type="collector_gap")[1:]
    source.close()
    store.close()


def test_failed_batch_rolls_back_whole_and_retry_accepts_each_record_once(tmp_path):
    path = tmp_path / "eve.json"
    for n in range(3):
        append(path, record("flow", timestamp=100 + n))
    store, source = collector(tmp_path)
    store.conn.execute("""CREATE TRIGGER reject_third BEFORE INSERT ON security_source_events
                          WHEN (SELECT COUNT(*) FROM security_source_events WHERE source='SURICATA') >= 2
                          BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        source.poll(now=100)
    assert store.source_events("SURICATA") == []  # the two earlier records rolled back with the batch
    store.conn.execute("DROP TRIGGER reject_third")
    assert source.poll(now=100) == 3
    assert len(store.source_events("SURICATA")) == 3
    assert source.poll(now=100) == 0
    source.close()
    store.close()


def test_live_file_is_read_before_a_rotated_backlog(tmp_path):
    path = tmp_path / "eve.json"
    for n in range(5):
        append(path, record("flow", timestamp=100 + n))
    store, source = collector(tmp_path)
    assert source.poll(now=100) == 5
    path.rename(tmp_path / "eve.json.1")  # rotated, with a backlog still unread
    for n in range(5):
        append(tmp_path / "eve.json.1", record("flow", timestamp=200 + n))
    append(path, record("alert", timestamp=300))
    seen = []
    source.reader.poll(lambda key, cursor, native, reference: seen.append(reference["path"]), limit=1)
    assert seen == [str(path)]  # budget for one record: the live file gets it
    source.close()
    store.close()


@pytest.mark.parametrize("source,event_type", [("SURICATA", None), ("SURICATA", "stats"), ("CONTROL", "arp")])
def test_collector_startup_latest_record_lookup_is_one_index_seek(tmp_path, source, event_type):
    # Collectors read the newest record at startup; a scan+sort here held a read for hours on a 6 GB store.
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    traced = []
    store.conn.set_trace_callback(traced.append)
    store.source_events(source, sensor_id=store.sensor_id, event_type=event_type, limit=1)
    store.conn.set_trace_callback(None)
    plan = str([tuple(row) for row in store._read("EXPLAIN QUERY PLAN " + traced[-1])])
    assert "USING INDEX idx_source_events_" in plan and "TEMP B-TREE" not in plan and "SCAN" not in plan
    store.close()


def test_unterminated_giant_record_is_bounded_per_poll(tmp_path, monkeypatch):
    import netwatch_sources

    monkeypatch.setattr(netwatch_sources, "OVERSIZE_SCAN_READS", 4)
    path = tmp_path / "eve.json"
    path.write_bytes(b"x" * (10 * 1_048_577))  # still being written: no newline yet
    store, source = collector(tmp_path)
    source.poll(now=100)  # files each 5 MiB run as a loss and moves on instead of rewinding to 0
    reasons = [row["native"]["reason"] for row in store.source_events("SURICATA", event_type="collector_error")]
    assert reasons and set(reasons) == {"record_size_limit"}
    with path.open("ab") as handle:
        handle.write(b"\n")
    append(path, record("dns"))
    for now in range(101, 106):
        source.poll(now=now)
    assert len(store.source_events("SURICATA", event_type="dns")) == 1
    source.close()
    store.close()
