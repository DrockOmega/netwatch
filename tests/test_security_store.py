import copy
import os
import queue
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from netwatch_core import make_message
from netwatch_security_store import DurableIncidentStore, publish_detection


def finding(target="8.8.8.8", *, severity="critical", confidence=None):
    data = {"message": f"THREAT INTEL: egress to {target}", "severity": severity}
    if confidence:
        data["confidence"] = confidence
    return make_message("DOD_CORE", "ALERT", target, data)


def test_commit_precedes_queue_and_replay_does_not_increment_case(tmp_path):
    path = tmp_path / "security.db"
    store = DurableIncidentStore(path, max_incidents=1)
    presentation = queue.Queue(maxsize=1)
    payload = finding()
    assert publish_detection(store, presentation, payload)
    first = store.snapshot()[0]
    assert first["confidence"] == "Observed"  # Critical severity is not evidence quality.
    assert publish_detection(store, presentation, payload)
    assert store.snapshot()[0]["count"] == 1
    for target in ("1.1.1.1", "9.9.9.9"):
        publish_detection(store, presentation, finding(target))
    assert store.open_count() == 3  # Display ceiling does not discard cases.
    assert len(store.snapshot()) == 1
    store.close()
    reopened = DurableIncidentStore(path)
    assert reopened.get(first["incident_id"])["count"] == 1
    assert len(reopened.detections(first["incident_id"])) == 1
    assert reopened.conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # _transaction fsyncs the WAL itself
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    reopened.close()


def test_failed_transaction_never_publishes_or_leaves_half_a_case(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    store.conn.execute("""CREATE TRIGGER fail_detection BEFORE INSERT ON security_detections
                          BEGIN SELECT RAISE(ABORT, 'simulated full disk'); END""")
    presentation = queue.Queue()
    with pytest.raises(sqlite3.IntegrityError):
        publish_detection(store, presentation, finding())
    assert presentation.empty()
    assert store.open_count() == 0
    assert store.conn.execute("SELECT COUNT(*) FROM security_case_audit").fetchone()[0] == 0
    store.close()


def test_case_lifecycle_audit_links_and_new_evidence_survive_restart(tmp_path):
    path = tmp_path / "security.db"
    store = DurableIncidentStore(path)
    payload = finding(confidence="Low")
    case = store.add(payload, now=10)
    incident_id = case["incident_id"]
    assert case["confidence"] == "Low"
    with pytest.raises(ValueError, match="reason"):
        store.update_case(incident_id, actor="analyst", status="Resolved")
    assert store.update_case(incident_id, actor="analyst", assignment="household",
                             acknowledge=True, note="Independent endpoint check underway")
    assert store.link(incident_id, "evidence", "pcap-reference", actor="analyst")
    assert not store.link(incident_id, "evidence", "pcap-reference", actor="analyst")
    assert store.update_case(incident_id, actor="analyst", status="Resolved",
                             closure_reason="Approved connection after investigation")
    store.close()
    store = DurableIncidentStore(path)
    restored = store.get(incident_id)
    assert restored["status"] == "Resolved"
    assert restored["assignment"] == "household"
    assert restored["acknowledged_by"] == "analyst"
    assert len(store.audit(incident_id)) == 4
    assert store.add(payload)["status"] == "Resolved"  # Old replay does not reopen it.
    new = store.add(finding(confidence="Medium"), now=20)
    assert new["status"] == "Open"
    assert new["closure_reason"] == ""
    assert new["count"] == 2
    assert new["confidence"] == "Medium"
    assert len(store.detections(incident_id)) == 2
    store.close()


def test_source_identity_conflicts_and_invalid_content_are_rejected(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    payload = finding()
    store.add(payload)
    altered = copy.deepcopy(payload)
    altered["data"]["message"] = "different source record"
    with pytest.raises(ValueError, match="different content"):
        store.add(altered)
    assert store.open_count() == 1
    payload["data"]["sensor_id"] = "different-sensor"
    assert store.add(payload)["count"] == 2
    with pytest.raises(ValueError):
        store.add(finding(), now=float("nan"))
    payload = finding()
    payload["data"]["message"] = "a" * 1_048_577
    with pytest.raises(ValueError, match="MiB"):
        store.add(payload)
    with pytest.raises(ValueError, match="invalid"):
        publish_detection(store, queue.Queue(), {"action": "ALERT"})
    store.close()


def test_structured_offender_does_not_replace_response_target(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    payload = finding()
    payload["data"]["offender_ip"] = "10.0.0.12"
    assert store.add(payload)["target"] == "8.8.8.8"
    payload = make_message("sensor", "ARP_ANOMALY", "UI_SHELL", {
        "message": "ARP binding changed", "offender_ip": "10.0.0.34",
    })
    assert store.add(payload)["target"] == "10.0.0.34"
    store.close()


def test_threaded_and_independent_writers_keep_all_detections(tmp_path):
    path = tmp_path / "security.db"
    first = DurableIncidentStore(path)
    second = DurableIncidentStore(path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda index: (first if index % 2 else second).add(finding()),
                                range(40)))
    assert first.snapshot()[0]["count"] == 40
    assert len({case["incident_id"] for case in results}) == 1
    assert len(first.detections(results[0]["incident_id"])) == 40
    first.close()
    second.close()


def test_process_exit_preserves_committed_detection_and_rolls_back_uncommitted_change(tmp_path):
    path = tmp_path / "security.db"
    script = """
import os, sys
from netwatch_security_store import DurableIncidentStore
from netwatch_core import make_message
store = DurableIncidentStore(sys.argv[1])
case = store.add(make_message('sensor', 'ALERT', b'\\x08\\x08\\x08\\x08',
                            {'message': 'THREAT INTEL: egress'}))
store.conn.execute('BEGIN IMMEDIATE')
store.conn.execute("UPDATE security_incidents SET status='Dismissed'")
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", script, str(path)], check=True,
                   env=dict(os.environ), timeout=10)
    store = DurableIncidentStore(path)
    case = store.snapshot()[0]
    assert case["target"] == "8.8.8.8"
    assert case["status"] == "Open"
    assert store.open_count() == 1
    assert len(store.detections(case["incident_id"])) == 1
    assert store.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    store.close()


def test_failed_open_leaves_no_checkpoint_thread(tmp_path, monkeypatch):
    import threading

    def malformed(self, key):
        raise sqlite3.DatabaseError("database disk image is malformed")
    monkeypatch.setattr(DurableIncidentStore, "cursor", malformed)
    before = sum(t.name == "security-wal-checkpoint" for t in threading.enumerate())
    for _ in range(3):  # the gap-transfer thread retries the open every second
        with pytest.raises(sqlite3.DatabaseError):
            DurableIncidentStore(str(tmp_path / "security.db"))
    assert sum(t.name == "security-wal-checkpoint" for t in threading.enumerate()) == before


def test_sustained_spool_loss_coalesces_gap_detections(tmp_path, monkeypatch):
    from netwatch_spool import TelemetrySpool

    store = DurableIncidentStore(str(tmp_path / "security.db"))
    spool = TelemetrySpool(str(tmp_path / "spool.db"))
    for i in range(5):  # one refused batch per second for the whole episode
        spool._record_admission_refusal(100 + i, 2, 1, 0, spool.max_bytes, reason="disk_floor")
        spool.transfer_gaps(store)
    case = next(c for c in store.snapshot() if c["action"] == "SPOOL_COLLECTION_GAP")
    assert len(store.detections(case["incident_id"])) == 1
    gap = store.spool_gaps()[0]
    assert (gap["loss_batches"], gap["dropped_rows"]) == (5, 10)  # the gap row stays exact
    monkeypatch.setattr(DurableIncidentStore, "SPOOL_GAP_DETECTION_SEC", 0.0)
    spool._record_admission_refusal(200, 2, 1, 0, spool.max_bytes, reason="disk_floor")
    spool.transfer_gaps(store)
    assert len(store.detections(case["incident_id"])) == 2
    spool.close()
    store.close()


def test_spool_gap_detection_memo_drops_only_expired_entries(tmp_path):
    import time

    from netwatch_spool import TelemetrySpool

    store = DurableIncidentStore(str(tmp_path / "security.db"))
    spool = TelemetrySpool(str(tmp_path / "spool.db"))
    stale = time.monotonic() - 2 * store.SPOOL_GAP_DETECTION_SEC
    store._gap_detected = {("old-spool", f"gap-{i}"): stale for i in range(300)}  # one per corrupt batch, long ago
    store._gap_detected[("old-spool", "live")] = time.monotonic()
    spool._record_admission_refusal(100, 2, 1, 0, spool.max_bytes, reason="disk_floor")
    spool.transfer_gaps(store)
    assert len(store._gap_detected) == 2 and ("old-spool", "live") in store._gap_detected
    spool.close()
    store.close()
