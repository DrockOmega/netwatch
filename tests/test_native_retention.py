import json
import sqlite3
import time

import pytest

from netwatch_arp import DurableArpAnalyzer
from netwatch_control import ControlCollector
from netwatch_security_store import DurableIncidentStore
from tests.test_arp_replay import A, B, record


def test_retention_pins_pending_analysis_holds_and_findings(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    first = record(collector, A, 1)
    second = record(collector, A, 2)
    third = record(collector, B, 3)
    record(collector, B, 4)
    confirmation = record(collector, B, 5)
    extra = record(collector, B, 6)
    report = store.prune_control_records(max_rows=1, retention_days=0, now=200)
    assert report["pruned"] == 0 and report["protected_or_pending"]
    store.native_hold(second["event_id"], actor="analyst", reason="Keep the stable observation")
    assert DurableArpAnalyzer(store, {}).poll() == 6
    report = store.prune_control_records(max_rows=1, retention_days=0, now=200)
    assert report["pruned"] == 1 and report["over_quota"]
    remaining = {row["event_id"] for row in store.source_events()}
    assert first["event_id"] in remaining and third["event_id"] in remaining
    assert confirmation["event_id"] in remaining and second["event_id"] in remaining
    assert store.native_retention_status(extra["event_id"])["pruned"] is None  # CONTROL keeps no tombstone
    assert store.native_retention_status(extra["event_id"])["audit"][0]["operation"] == "prune"
    store.close()
    store = DurableIncidentStore(tmp_path / "security.db")
    assert store.native_retention_status(second["event_id"])["hold"]["actor"] == "analyst"
    store.native_hold(second["event_id"], actor="analyst", reason="Investigation complete", enabled=False)
    assert store.prune_control_records(max_rows=1, retention_days=0, now=201)["pruned"] == 1
    assert len(store.source_events()) == 4
    store.close()


def test_pruned_control_records_leave_no_tombstone_and_sequence_never_rewinds(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    first = record(collector, A, 1)
    sequence = store.source_stream("CONTROL", "arp")[0]["sequence"]
    assert store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1,
                                       arp_enabled=False, now=100000)["pruned"] == 1
    assert store.native_retention_status(first["event_id"])["pruned"] is None
    assert not store.conn.execute("SELECT 1 FROM security_native_pruned").fetchone()
    store.conn.execute("VACUUM")
    next_record = record(collector, A, 2)
    assert store.source_stream("CONTROL", "arp")[0]["sequence"] > sequence
    assert store.source_events()[0]["event_id"] == next_record["event_id"]
    store.close()


def test_pruning_and_audit_are_atomic_and_receipt_age_is_used(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    recent = record(collector, A, 1, received=100000)
    expired = record(collector, A, 2, received=1)
    store.conn.execute("""CREATE TRIGGER fail_prune BEFORE INSERT ON security_native_audit
                          BEGIN SELECT RAISE(ABORT, 'simulated audit failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1,
                                    arp_enabled=False, now=100001, batch=1)
    assert len(store.source_events()) == 2
    assert store.native_retention_status(expired["event_id"])["pruned"] is None
    store.conn.execute("DROP TRIGGER fail_prune")
    assert store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1,
                                       arp_enabled=False, now=100001, batch=1)["pruned"] == 1
    assert store.source_events()[0]["event_id"] == recent["event_id"]
    store.close()


def test_native_hold_requires_attribution_and_cannot_restore_pruned_payload(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    event = record(ControlCollector(store, {}), A, 1)
    with pytest.raises(ValueError, match="reason"):
        store.native_hold(event["event_id"], actor="analyst", reason="")
    store.prune_control_records(max_rows=0, max_bytes=1, retention_days=0, arp_enabled=False)
    with pytest.raises(ValueError, match="unavailable"):
        store.native_hold(event["event_id"], actor="analyst", reason="Too late")
    store.close()


def test_active_bindings_candidates_and_fanout_support_remain_pinned(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    first = record(collector, A, 1)
    candidate = record(collector, B, 2)
    analyzer = DurableArpAnalyzer(store, {"ARP_MAC_FANOUT_THRESHOLD": 2})
    assert analyzer.poll() == 2
    assert store.prune_control_records(max_rows=1, retention_days=0)["pruned"] == 0
    assert store.native_retention_status(candidate["event_id"])["pruned"] is None
    second = record(collector, A, 3, ip="10.0.0.2")
    third = record(collector, A, 4, ip="10.0.0.3")
    assert analyzer.poll() == 2
    case = store.snapshot()[0]
    support = store.detections(case["incident_id"])[0]["payload"]["data"]["native_event_ids"]
    assert set(support) == {first["event_id"], second["event_id"], third["event_id"]}
    assert store.prune_control_records(max_rows=1, retention_days=0)["pruned"] == 0
    store.close()


def test_retention_scan_does_not_take_the_writer_lock(tmp_path):
    # A scan with nothing to prune must not queue behind (or block) other writers.
    store = DurableIncidentStore(tmp_path / "security.db")
    record(ControlCollector(store, {}), A, 1)
    store.conn.execute("PRAGMA busy_timeout=100")
    other = sqlite3.connect(tmp_path / "security.db", isolation_level=None)
    other.execute("BEGIN IMMEDIATE")
    try:
        assert store.prune_control_records(max_rows=0, max_bytes=0, retention_days=7, now=2)["pruned"] == 0
    finally:
        other.execute("ROLLBACK")
        other.close()
        store.close()


def test_open_case_pins_are_index_served_at_scale(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    ids = [f"native-{i:03d}" for i in range(300)]
    cases = [(f"case-{i}", "Open" if i < 200 else "Resolved") for i in range(250)]
    # ids 0-9 source id + sensor, 10-14 same id on another sensor (unpinned), 15-24 scalar
    # native_event_id, 25-34 native_event_ids array; 35-44 the same three kinds in closed cases.
    kinds = ["source"] * 10 + ["other-sensor"] * 5 + ["scalar"] * 10 + ["array"] * 10
    kinds += ["source"] * 4 + ["scalar"] * 3 + ["array"] * 3
    pinned = set(ids[:10] + ids[15:35])
    held = {ids[35], ids[39], ids[42]}  # one per kind, each in its own closed case
    detections = []
    for n in range(20_000):
        case, data, source_id, sensor = cases[n % 200][0], {"message": "x" * 200}, f"other-{n}", "s1"
        kind = kinds[n] if n < len(kinds) else None
        case = cases[200 + n - 35][0] if 35 <= n < len(kinds) else case
        if kind in ("source", "other-sensor"):
            source_id, sensor = ids[n], "s2" if kind == "other-sensor" else "s1"
        elif kind == "scalar":
            data["native_event_id"] = ids[n]
        elif kind == "array":
            data["native_event_ids"] = ["unrelated", ids[n]]
        detections.append((f"det-{n}", "CONTROL", source_id, sensor, 0, 0, 1, json.dumps({"data": data}), case))
    with store._transaction():
        store.conn.executemany("INSERT INTO security_incidents VALUES (?, ?, 'X', 't', 'low', ?, 0, '{}')",
                               [(case, case, status) for case, status in cases])
        store.conn.executemany("INSERT INTO security_detections VALUES (?,?,?,?,?,?,?,?,?)", detections)
        for event_id in ids:
            store.conn.execute("INSERT INTO security_source_events VALUES (?, 'CONTROL', 's1', 'dhcp', 0, 0, '{}', '{}')",
                               (event_id,))
            store.conn.execute("INSERT INTO security_source_order(event_id) VALUES (?)", (event_id,))
    for event_id in held:
        store.native_hold(event_id, actor="analyst", reason="keep")
    statements = []
    store.conn.set_trace_callback(lambda sql: statements.append(sql) if "security_detections d" in sql else None)
    while True:
        began = time.monotonic()
        report = store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1, now=10**6)
        assert time.monotonic() - began < 2  # unindexed, each candidate read every open-case payload
        if not report["pruned"]:
            break
    store.prune_metadata(retention_days=0, now=10**9)
    store.conn.set_trace_callback(None)
    assert {row["event_id"] for row in store.source_events(limit=1000)} == pinned | held
    closed = {row[0] for row in store.conn.execute("SELECT incident_id FROM security_incidents WHERE status='Resolved'")}
    assert closed == {"case-200", "case-204", "case-207"}
    assert statements
    for sql in set(statements):
        plan = [row[-1] for row in store.conn.execute("EXPLAIN QUERY PLAN " + sql)]
        # Every detection read is an index seek on the named record, never a walk of open cases.
        assert not [step for step in plan if step.startswith(("SCAN d", "SEARCH d")) and not any(
            index in step for index in ("idx_detection_source_identity", "idx_detections_native_event",
                                        "COVERING INDEX idx_detections_case"))], plan
    store.close()


def test_unfiltered_source_events_reads_newest_window_without_full_sort(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    ids = [record(collector, A if i % 2 else B, i)["event_id"] for i in range(1, 7)]
    newest = store.source_events(limit=3)
    assert [row["event_id"] for row in newest] == ids[:2:-1] and "sequence" not in newest[0]
    assert [row["event_id"] for row in store.source_events(limit=10)] == ids[::-1]


def test_unprunable_gap_rows_do_not_count_toward_the_quota(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    for _ in range(3):
        collector.gap("Control capture buffer overflow; these observed frames were not committed", 1)
    record(collector, A, 1)
    report = store.prune_control_records(max_rows=1, retention_days=0, arp_enabled=False, now=200)
    assert report["rows"] == 1 and not report["over_quota"] and report["pruned"] == 0
    store.close()


def test_sqlite_wal_reset_fix_versions():
    from netwatch_security_store import sqlite_wal_safe

    assert not any(map(sqlite_wal_safe, [(3, 50, 4), (3, 51, 2), (3, 44, 5), (3, 46, 1)]))
    assert all(map(sqlite_wal_safe, [(3, 51, 3), (3, 54, 0), (3, 50, 7), (3, 44, 6)]))


def test_store_refuses_to_open_on_a_wal_reset_sqlite(tmp_path, monkeypatch):
    import netwatch_security_store

    monkeypatch.setattr(netwatch_security_store, "sqlite_wal_safe", lambda: False)
    with pytest.raises(RuntimeError, match="WAL-reset"):
        netwatch_security_store.DurableIncidentStore(str(tmp_path / "security.db"))
    assert not (tmp_path / "security.db").exists()


def test_evidence_trigger_pin_reads_the_catalog_once_per_window(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    ids = [f"native-{i:03d}" for i in range(64)]
    with store._transaction():
        for event_id in ids:
            store.conn.execute("INSERT INTO security_source_events VALUES (?, 'CONTROL', 's1', 'icmp', 0, 0, '{}', '{}')",
                               (event_id,))
            store.conn.execute("INSERT INTO security_source_order(event_id) VALUES (?)", (event_id,))
        # Retained evidence names ids 0-4 as triggers; pruned evidence names 5-9 and pins nothing.
        store.conn.executemany("INSERT INTO evidence_items VALUES (?, 'd', ?, 0, 0, ?, 0, ?)", [
            (f"ev-{n}", f"f{n}", "pruned" if n >= 5 else "complete",
             json.dumps({"triggers": [{"source_event_id": ids[n % 10]}, {"source_event_id": None}]}))
            for n in range(500)])
    statements = []
    store.conn.set_trace_callback(lambda sql: statements.append(sql) if "evidence_items e" in sql else None)
    while store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1, batch=16, now=10**6)["pruned"]:
        pass
    store.conn.set_trace_callback(None)
    assert {row["event_id"] for row in store.source_events(limit=1000)} == set(ids[:5])
    assert statements
    for sql in set(statements):
        plan = {row[0]: (row[1], row[3]) for row in store.conn.execute("EXPLAIN QUERY PLAN " + sql)}
        for parent, step in plan.values():
            if step.startswith(("SCAN e", "SEARCH e")):
                ancestors = []
                while parent in plan:
                    ancestors.append(plan[parent][1])
                    parent = plan[parent][0]
                # Correlated, the catalog's JSON was re-read for every candidate row (215 ms per
                # 16 CONTROL rows on Sensor1, 2026-10-11), which capped CONTROL retention below intake.
                assert not any("CORRELATED" in step for step in ancestors), plan
    store.close()


def test_service_main_exits_2_on_a_wal_reset_sqlite(tmp_path, monkeypatch):
    import netwatch_service

    monkeypatch.setattr(netwatch_service, "sqlite_wal_safe", lambda: False)
    monkeypatch.setattr(netwatch_service, "ServiceSupervisor", lambda *_a, **_k: pytest.fail("supervisor built"))
    assert netwatch_service.main(["--base-dir", str(tmp_path)]) == 2


def test_an_arp_poll_saves_each_scope_once_not_per_row(tmp_path, monkeypatch):
    """Per-row reload and rewrite of the binding table held the writer lock ~2.4 s a poll on Sensor1."""
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    for n in range(6):
        record(collector, A, n + 1, ip=f"10.0.0.{n + 2}")
    analyzer = DurableArpAnalyzer(store, {"ARP_MAC_FANOUT_THRESHOLD": 100})
    writes = []
    real = store._checkpoint
    monkeypatch.setattr(store, "_checkpoint", lambda key, value: (writes.append(key), real(key, value))[1])
    assert analyzer.poll() == 6
    assert sum(key.startswith("ARP_STATE:v1:") for key in writes) == 1
    assert sum(key == analyzer.cursor_key for key in writes) == 1
    state = next(store.cursor(key) for key in writes if key.startswith("ARP_STATE:v1:"))
    assert len(state["bindings"]) == 6
    store.close()
