"""Bounded security-store metadata retention; holds, open cases and references win."""

import queue
import threading

from netwatch_actions import ActionService, RecordingResponseEffector
from netwatch_control import ControlCollector
from netwatch_core import make_message
from netwatch_db import db_persistence_worker
from netwatch_evidence_catalog import EvidenceCatalog
from netwatch_security_store import DurableIncidentStore
from tests.test_actions import guard
from tests.test_arp_replay import A, B, record

DAY = 86400
OLD = 1_700_000_000.0
NOW = OLD + 400 * DAY


def detect(store, target, *, native_event_id=None, now=OLD):
    data = {"message": f"egress to {target}", "severity": "alert"}
    if native_event_id:
        data["native_event_id"] = native_event_id
    return store.add(make_message("DOD_CORE", "ALERT", target, data), now=now)["incident_id"]


def close(store, case_id):
    assert store.update_case(case_id, actor="analyst", status="Resolved", closure_reason="done")


def drain(store, **kwargs):
    total, more = 0, True
    while more:
        removed, more = store.prune_metadata(batch_rows=1, max_batches=1, now=NOW, **kwargs)
        total += removed
    return total


def test_tombstones_and_prune_audit_age_out_but_holds_stay(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    kept = record(collector, A, 1)
    pruned = [record(collector, B, n)["event_id"] for n in (2, 3)]
    store.native_hold(kept["event_id"], actor="analyst", reason="keep")
    report = store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1, arp_enabled=False, now=OLD + 2 * DAY)
    assert report["pruned"] == 2
    top = store.conn.execute("SELECT MAX(sequence) FROM security_source_order").fetchone()[0]

    assert drain(store, retention_days=500, case_retention_days=0) == 0  # order rows left with their events
    assert store.native_retention_status(pruned[0])["audit"][0]["operation"] == "prune"
    assert drain(store, retention_days=30, case_retention_days=0) == 1  # the prune audit (CONTROL keeps no tombstone)
    for event_id in pruned:
        assert store.native_retention_status(event_id) == {"hold": None, "pruned": None, "audit": []}
    status = store.native_retention_status(kept["event_id"])
    assert status["hold"]["actor"] == "analyst" and status["audit"][0]["operation"] == "hold"
    assert store.source_events(event_id=kept["event_id"])
    assert store.conn.execute("SELECT COUNT(*) FROM security_source_order").fetchone()[0] == 1
    fresh = record(collector, A, 4)
    assert store.source_stream("CONTROL", "arp", after=top)[0]["event_id"] == fresh["event_id"]
    store.close()


def test_closed_case_retention_respects_open_cases_actions_evidence_and_holds(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    native = record(ControlCollector(store, {}), A, 1)["event_id"]
    store.native_hold(native, actor="analyst", reason="investigating")
    EvidenceCatalog(tmp_path / "evidence", store=store)
    for evidence_id, status in (("ev-available", "available"), ("ev-pruned", "pruned")):
        store.conn.execute("INSERT INTO evidence_items VALUES (?,?,?,?,?,?,0,'{}')",
                           (evidence_id, str(tmp_path), evidence_id, OLD, 1, status))

    open_case = detect(store, "8.8.8.1")
    gone = detect(store, "8.8.8.2")
    detect(store, "8.8.8.2", now=OLD + 1)
    store.link(gone, "evidence", "ev-pruned", actor="analyst")
    with_action = detect(store, "8.8.8.3")
    with_evidence = detect(store, "8.8.8.4")
    store.link(with_evidence, "evidence", "ev-available", actor="analyst")
    with_unknown_evidence = detect(store, "8.8.8.5")
    store.link(with_unknown_evidence, "evidence", "never-catalogued", actor="analyst")
    with_hold = detect(store, "8.8.8.6", native_event_id=native)
    recent = detect(store, "8.8.8.7", now=NOW - DAY)
    ActionService(store, RecordingResponseEffector(), guard(), clock=lambda: OLD).request(
        kind="block_ip", target="8.8.8.3", reason="r", requested_by="analyst", case_id=with_action,
        expires_at=OLD + 100)
    for case_id in (gone, with_action, with_evidence, with_unknown_evidence, with_hold, recent):
        close(store, case_id)

    removed = drain(store, retention_days=0, case_retention_days=365)
    assert store.get(gone) is None
    assert store.detections(gone) == [] and store.audit(gone) == []
    assert not store.conn.execute("SELECT 1 FROM security_case_links WHERE incident_id=?", (gone,)).fetchone()
    assert removed == 2 + 4 + 1 + 1  # detections, audit (2 detections, link, close), link, case
    for case_id in (open_case, with_action, with_evidence, with_unknown_evidence, with_hold, recent):
        assert store.get(case_id) is not None and store.detections(case_id)

    store.native_hold(native, actor="analyst", reason="done", enabled=False)
    drain(store, retention_days=0, case_retention_days=365)
    assert store.get(with_hold) is None and store.get(with_action) is not None
    assert store.prune_metadata(retention_days=0, case_retention_days=0, now=NOW) == (0, False)
    store.close()


def test_persistence_worker_runs_metadata_retention_and_records_health(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.db"
    store = DurableIncidentStore(f"{ledger}.security.db")
    case_id = detect(store, "8.8.8.9")
    close(store, case_id)
    store.close()
    shutdown, passes = threading.Event(), []
    original = DurableIncidentStore.record_source_health

    # Read the first pass's own health row: retention keeps passing until the worker sees
    # shutdown (one loop turn, slower on Windows), and a later empty pass records 0.
    def health_then_stop(self, source_key, body, now=None):
        original(self, source_key, body, now)
        if source_key == "RETENTION:METADATA":
            passes.append(body["removed_last_pass"])
            shutdown.set()

    monkeypatch.setattr(DurableIncidentStore, "record_source_health", health_then_stop)
    worker = threading.Thread(target=db_persistence_worker, args=(queue.Queue(), queue.Queue(), {
        "DB_NAME": str(ledger), "SPOOL_PATH": str(tmp_path / "spool.db"), "DB_PRUNE_INTERVAL_SEC": 0,
        "LOG_DIR": "", "LOG_TO_CONSOLE": False}, shutdown))
    worker.start()
    worker.join(timeout=60)  # hosted Windows runners stall well past 10s under load
    assert not worker.is_alive()
    store = DurableIncidentStore(f"{ledger}.security.db")
    assert store.get(case_id) is None
    assert passes[0] >= 4 and store.source_health("RETENTION:METADATA")["status"] == "RUNNING"
    store.close()


def test_pruning_a_native_record_removes_its_order_row_in_the_same_transaction(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    gone = record(collector, B, 1)["event_id"]
    store.prune_control_records(max_rows=0, max_bytes=0, retention_days=1, arp_enabled=False, now=OLD + 2 * DAY)
    assert not store.conn.execute("SELECT 1 FROM security_source_order WHERE event_id=?", (gone,)).fetchone()
    store.close()
