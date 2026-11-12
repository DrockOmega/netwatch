import json
import queue
import threading
import time

import pytest

from netwatch_db import NATIVE_PRUNE_BATCH, db_persistence_worker
from netwatch_evidence_catalog import EvidenceCatalog
from netwatch_security_store import DurableIncidentStore, retention_status
from netwatch_suricata import EveCollector
from tests.test_sources import append, record

DAY = 86400


def eve(tmp_path, *batches):
    """Each batch is (receipt_time, records); returns the store and the collector."""
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    source = EveCollector(store, {"SURICATA_EVE_PATH": str(tmp_path / "eve.json"),
                                  "LOCAL_PREFIXES": ["10.0.0.0/8"], "DISK_MIN_FREE_BYTES": 0})
    for received, records in batches:
        append(tmp_path / "eve.json", *records)
        source.poll(now=received)
    return store, source


def flows(count, start=0):
    return [record("flow", timestamp=100 + start + i, flow_id=start + i) for i in range(count)]


def prune(store, source="SURICATA", **kwargs):
    limits = {"max_rows": 0, "max_bytes": 0, "retention_days": 0} | kwargs
    return store.prune_native_records(source, **limits)


def ids(store, source="SURICATA"):
    return [row[0] for row in store._read("""SELECT s.event_id FROM security_source_events s
        JOIN security_source_order o ON o.event_id=s.event_id WHERE s.source=? ORDER BY o.sequence""", (source,))]


def test_age_rows_and_bytes_are_applied_per_source_and_keep_the_newest_of_each_type(tmp_path):
    store, source = eve(tmp_path, (1, flows(4)), (10 * DAY, flows(1, 10)))
    before = ids(store)
    # Age: the four old flows expire; the newest flow is pinned regardless.
    assert prune(store, retention_days=7, now=10 * DAY)["pruned"] == 4
    assert ids(store) == before[-1:]
    # Bytes: a target below one record trims to the pinned newest of each type.
    append(tmp_path / "eve.json", *flows(3, 20))
    source.poll(now=10 * DAY + 1)
    report = prune(store, max_bytes=1, now=10 * DAY + 2)
    assert report["pruned"] == 3 and report["over_quota"] and len(store.source_events("SURICATA")) == 1
    store.close()


def test_open_case_detections_holds_and_evidence_pin_records_and_tombstones_are_written(tmp_path):
    store, source = eve(tmp_path, (1, [record("alert", timestamp=101), *flows(3)]), (2, [*flows(1, 9), record("alert", timestamp=102)]))
    alert, held, linked, plain, newest, last_alert = ids(store)
    assert store.open_count() == 1
    store.native_hold(held, actor="analyst", reason="investigating")
    EvidenceCatalog(tmp_path / "evidence", store=store)
    store.conn.execute("INSERT INTO evidence_items VALUES ('ev1','d','f.pcap',1,1,'available',0,?)",
                       (json.dumps({"triggers": [{"source_event_id": linked}]}),))
    report = prune(store, max_rows=1, now=3)
    assert report["pruned"] == 1 and report["over_quota"] and set(ids(store)) == {alert, held, linked, newest, last_alert}
    status = store.native_retention_status(plain)
    assert status["pruned"]["reason"] == "quota" and status["pruned"]["source"] == "SURICATA"
    assert status["audit"][-1]["operation"] == "prune" and status["audit"][-1]["actor"] == "suricata-retention"
    # Closing the case, releasing the hold and pruning the evidence release the pins.
    case = store.snapshot()[0]["incident_id"]
    assert store.update_case(case, actor="analyst", status="Resolved", closure_reason="done")
    store.native_hold(held, actor="analyst", reason="done", enabled=False)
    store.conn.execute("UPDATE evidence_items SET status='pruned'")
    assert prune(store, max_rows=1, now=4)["pruned"] == 3
    assert ids(store) == [newest, last_alert]  # the newest of each type stays
    store.close()


def test_collectors_restore_health_from_pinned_newest_records_after_pruning(tmp_path):
    stats = [record("stats", timestamp=t, stats={"capture": {"kernel_packets": t}}) for t in (100, 200)]
    store, source = eve(tmp_path, (1, [stats[0], *flows(2)]), (2, [stats[1], *flows(1, 5)]))
    assert prune(store, max_bytes=1, now=10 * DAY)["pruned"] == 3  # older stats + two flows
    restored = EveCollector(store, {"SURICATA_EVE_PATH": str(tmp_path / "eve.json"), "DISK_MIN_FREE_BYTES": 0})
    assert restored.counters == {"kernel_packets": 200} and restored.last_stats_time == 200
    store.close()


@pytest.mark.parametrize("limits", [{"max_rows": 1}, {"retention_days": 7}], ids=["quota", "age"])
def test_a_pinned_prefix_longer_than_the_batch_is_walked_past_and_never_pruned(tmp_path, limits):
    store, _ = eve(tmp_path, (1, flows(14)))
    before = ids(store)
    for event_id in before[:10]:  # two and a half windows of four
        store.native_hold(event_id, actor="analyst", reason="investigating")
    report = prune(store, batch=4, now=10 * DAY, **limits)
    assert report["pruned"] == 3 and ids(store) == before[:10] + before[-1:]  # the newest flow stays pinned
    assert prune(store, batch=4, now=10 * DAY, **limits)["pruned"] == 0
    assert ids(store) == before[:10] + before[-1:]
    store.close()


def test_native_and_control_tombstones_age_out_on_the_short_window(tmp_path):
    store, _ = eve(tmp_path, (1, flows(2)))
    assert prune(store, max_rows=1, now=2)["pruned"] == 1
    store.conn.execute("""INSERT INTO security_native_pruned VALUES ('control-1','x',2,'{"source":"CONTROL"}')""")
    store.conn.execute("""INSERT INTO security_native_pruned VALUES ('other-1','x',2,'{"source":"NETWATCH"}')""")
    removed, more = store.prune_metadata(retention_days=30, case_retention_days=0,
                                         native_retention_days=1, now=2 + 2 * DAY)
    assert (removed, more) == (3, False)  # SURICATA and CONTROL tombstones and the SURICATA prune audit
    assert [row[0] for row in store.conn.execute("SELECT event_id FROM security_native_pruned")] == ["other-1"]
    store.close()


def test_a_pruned_native_identity_stays_idempotent(tmp_path):
    store, _ = eve(tmp_path, (1, flows(2)))
    gone = ids(store)[0]
    original = store.source_events(event_id=gone)[0]
    assert prune(store, max_rows=1, now=2)["pruned"] == 1
    assert not store.accept_source_record("SURICATA:replay", {"position": 1},
                                         original["normalized"], original["native"])
    with pytest.raises(ValueError, match="different content"):
        store.accept_source_record("SURICATA:replay", {"position": 2}, original["normalized"],
                                   dict(original["native"], flow_id=999))
    assert store.cursor("SURICATA:replay") == {"position": 1}
    store.close()


def test_legacy_control_tombstones_clear_whatever_their_age(tmp_path, monkeypatch):
    import netwatch_security_store

    monkeypatch.setattr(netwatch_security_store, "LEGACY_TOMBSTONE_BATCH", 2)
    store, _ = eve(tmp_path, (1, flows(1)))
    for n in range(11):
        store.conn.execute("INSERT INTO security_native_pruned VALUES (?,'x',?,'{\"source\":\"CONTROL\"}')",
                           (f"control-{n}", 10 * DAY))  # pruned "today": the 1-day window would keep them
    assert store.prune_metadata(retention_days=30, case_retention_days=0, native_retention_days=1,
                                now=10 * DAY) == (10, True)  # five full batches per call
    assert store.prune_metadata(retention_days=30, case_retention_days=0, native_retention_days=1,
                                now=10 * DAY) == (1, False)
    assert not store.conn.execute("SELECT 1 FROM security_native_pruned").fetchone()
    store.close()


def test_persistence_worker_prunes_native_sources_in_bounded_batches(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.db"
    store = DurableIncidentStore(f"{ledger}.security.db", sensor_id="sensor-a")
    rows = [(f"e{i:05}", "SURICATA", "sensor-a", "flow", 1.0, 1.0 + i / 10000, "{}", "{}") for i in range(2500)]
    with store._transaction():
        store.conn.executemany("INSERT INTO security_source_events VALUES (?,?,?,?,?,?,?,?)", rows)
        store.conn.executemany("INSERT INTO security_source_order(event_id) VALUES (?)", [(r[0],) for r in rows])
    store.close()
    calls, shutdown = [], threading.Event()
    original = DurableIncidentStore.prune_native_records

    def spy(self, source, **kwargs):
        report = original(self, source, **kwargs)
        if shutdown.is_set():  # a next pass can start before the worker sees shutdown (slower on Windows)
            return report
        calls.append((source, kwargs["totals"], report["pruned"]))
        if source == "SURICATA" and report["pruned"] < NATIVE_PRUNE_BATCH:
            shutdown.set()
        return report

    monkeypatch.setattr(DurableIncidentStore, "prune_native_records", spy)
    health = []
    record_health = DurableIncidentStore.record_source_health
    monkeypatch.setattr(DurableIncidentStore, "record_source_health", lambda self, key, body, *a, **k: (
        health.append((key, body["pruned"])) if key == "RETENTION:NATIVE:SURICATA" else None,
        record_health(self, key, body, *a, **k))[1])
    worker = threading.Thread(target=db_persistence_worker, args=(queue.Queue(), queue.Queue(), {
        "DB_NAME": str(ledger), "SPOOL_PATH": str(tmp_path / "spool.db"), "DB_PRUNE_INTERVAL_SEC": 0,
        "NATIVE_RETENTION_DAYS": 1, "LOG_DIR": "", "LOG_TO_CONSOLE": False}, shutdown))
    worker.start()
    worker.join(timeout=20)
    assert not worker.is_alive()
    eve_calls = [call for call in calls if call[0] == "SURICATA"]
    pruned = [call[2] for call in eve_calls]
    assert pruned[:-1] == [NATIVE_PRUNE_BATCH] * (len(pruned) - 1) and pruned[-1] < NATIVE_PRUNE_BATCH
    assert sum(pruned) == 2499  # the newest flow stays pinned
    # Health is written every batch, not only when a pass ends (a never-ending backlog left it stale).
    assert [p for _, p in health[:len(pruned)]] == pruned
    left = 2500 - NATIVE_PRUNE_BATCH
    assert eve_calls[0][1] is None and eve_calls[1][1] == (left, left * 4)  # one payload scan per pass
    store = DurableIncidentStore(f"{ledger}.security.db")
    assert len(store.source_events("SURICATA")) == 1
    assert store.source_health("RETENTION:NATIVE:SURICATA")["status"] == "RUNNING"
    store.close()


def test_a_slow_native_quota_scan_does_not_stall_the_persistence_heartbeat(tmp_path, monkeypatch):
    """VM 2026-10-08: the SURICATA payload scan took 210 s cold inside the loop; the supervisor killed the db."""
    ledger = tmp_path / "ledger.db"
    DurableIncidentStore(f"{ledger}.security.db").close()
    scanning, release, shutdown = threading.Event(), threading.Event(), threading.Event()

    def slow_scan(self, source, **kwargs):
        scanning.set()
        release.wait(10)
        return {"rows": 0, "payload_bytes": 0, "pruned": 0, "over_quota": False}

    monkeypatch.setattr(DurableIncidentStore, "prune_native_records", slow_scan)
    status = queue.Queue()
    worker = threading.Thread(target=db_persistence_worker, args=(queue.Queue(), status, {
        "DB_NAME": str(ledger), "SPOOL_PATH": str(tmp_path / "spool.db"), "DB_PRUNE_INTERVAL_SEC": 0,
        "LOG_DIR": "", "LOG_TO_CONSOLE": False}, shutdown))
    worker.start()
    try:
        assert scanning.wait(10)
        while not status.empty():
            status.get_nowait()
        time.sleep(2.5)
        beats = [m for m in iter(lambda: None if status.empty() else status.get_nowait(), None)
                 if m["action"] == "DB_HEARTBEAT"]
        assert len(beats) >= 2  # one a second while the scan is still running
    finally:
        release.set()
        shutdown.set()
        worker.join(10)
    assert not worker.is_alive()


def slow_begin(store, monkeypatch):
    """Only the outermost enter waits 0.3 s, like a contended BEGIN IMMEDIATE."""
    import contextlib
    original, depth = store._transaction, []

    @contextlib.contextmanager
    def wrapped(*args, **kwargs):
        if not depth:
            time.sleep(0.3)
        depth.append(1)
        try:
            with original(*args, **kwargs):
                yield
        finally:
            depth.pop()

    monkeypatch.setattr(store, "_transaction", wrapped)


def test_batch_deadline_starts_after_the_lock_wait(tmp_path, monkeypatch):
    store, source = eve(tmp_path)
    slow_begin(store, monkeypatch)
    append(tmp_path / "eve.json", *flows(120))
    source.poll(now=1)
    assert len(ids(store)) >= 100  # the 0.3 s BEGIN wait did not cut the first batch to one record
    store.close()


def test_poll_returns_for_the_heartbeat_during_a_long_backlog(tmp_path, monkeypatch):
    store, source = eve(tmp_path)
    slow_begin(store, monkeypatch)
    append(tmp_path / "eve.json", *flows(5000))
    started = time.monotonic()
    source.poll(now=1)
    assert time.monotonic() - started < 3.5
    store.close()


def test_over_quota_prune_starts_at_the_sources_oldest_candidate_not_the_first_order_row(tmp_path):
    store, _ = eve(tmp_path, (1, flows(2000)))
    tail = ids(store)[-20:]
    # Twenty records of another source sit behind 1,980 SURICATA order rows.
    store.conn.executemany("UPDATE security_source_events SET source='OTHER' WHERE event_id=?", [(i,) for i in tail])
    store.native_hold(tail[0], actor="analyst", reason="investigating")
    steps = []

    def counted(**limits):
        count = [0]
        store.conn.set_progress_handler(lambda: count.__setitem__(0, count[0] + 1), 100)
        try:
            report = prune(store, "OTHER", **limits)
        finally:
            store.conn.set_progress_handler(None, 0)
        steps.append(count[0])
        return report

    assert counted(max_rows=15, batch=2)["pruned"] == 2
    assert counted(max_rows=15, batch=2)["pruned"] == 2
    assert steps[1] * 3 < steps[0]  # the second pass skips the SURICATA rows below the floor
    # The held record below the pruned ones stays a candidate: released, it is pruned next.
    store.native_hold(tail[0], actor="analyst", reason="done", enabled=False)
    counted(max_rows=15, batch=1)
    assert tail[0] not in ids(store, "OTHER")
    store.close()


def test_retention_status_tolerates_a_draining_backlog_but_not_falling_behind_or_pins():
    at_cap = {"rows": 10, "payload_bytes": 1_000_000 + 1, "over_quota": True, "protected_or_pending": False}
    assert retention_status(at_cap, 100, 1_000_000) == "RUNNING"
    assert retention_status(dict(at_cap, payload_bytes=1_060_000), 100, 1_000_000) == "DEGRADED"
    assert retention_status(dict(at_cap, rows=106), 100, 1_000_000) == "DEGRADED"
    assert retention_status(dict(at_cap, protected_or_pending=True), 100, 1_000_000) == "DEGRADED"
    assert retention_status(dict(at_cap, payload_bytes=10**12), 100, 0) == "RUNNING"  # 0 disables a bound


def test_legacy_control_tombstone_scan_stops_once_the_table_is_clean(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "s.db"))
    put = "INSERT INTO security_native_pruned VALUES (?,?,?,?)"
    with store._transaction():
        store.conn.execute(put, ("old", "h", time.time(), json.dumps({"source": "CONTROL"})))
    store.prune_metadata(now=time.time())
    with store._transaction():
        store.conn.execute(put, ("new", "h", time.time(), json.dumps({"source": "CONTROL"})))
    store.prune_metadata(now=time.time())
    assert [r[0] for r in store.conn.execute("SELECT event_id FROM security_native_pruned")] == ["new"]
    store.close()
