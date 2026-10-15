"""Export contention: a slow export must not hold the catalog's SQLite write lock."""

import multiprocessing as mp
import threading
import time
import zipfile

import pytest

from netwatch_evidence import EvidenceRecorder
from netwatch_evidence_catalog import EvidenceCatalog, verify_export
from netwatch_security_store import DurableIncidentStore


def capture(recorder, timestamp, identity):
    recorder.add(timestamp, b"x" * 60)
    assert recorder.request({"trigger_ts": timestamp, "action": "ALERT", "correlation_id": identity}, now=timestamp)
    recorder.poll(now=timestamp, force=True)
    recorder.write_jobs.join()
    return recorder.poll(now=timestamp)[0]


def gate_copy(monkeypatch, entered, release, parties=1):
    """Pause every export inside its payload copy until `release` is set."""
    original = zipfile.ZipFile.write
    barrier = threading.Barrier(parties, action=entered.set)  # Set once every export is inside its copy.

    def paused(self, *args, **kwargs):
        barrier.wait(timeout=10)
        assert release.wait(timeout=10)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "write", paused)


def run(target, *args, **kwargs):
    box = {}

    def body():
        try:
            box["result"] = target(*args, **kwargs)
        except BaseException as exc:
            box["error"] = exc

    thread = threading.Thread(target=body, daemon=True)
    thread.start()
    return thread, box


def within(seconds, target, *args, **kwargs):
    """Run `target` and fail if it waits on the paused export (the busy timeout is 5 s)."""
    thread, box = run(target, *args, **kwargs)
    thread.join(seconds)
    assert not thread.is_alive(), "operation blocked behind an in-flight export or verify"
    if "error" in box:
        raise box["error"]
    return box["result"]


def exporter(root, evidence_id, destination, actor="analyst"):
    catalog = EvidenceCatalog(root)
    try:
        return catalog.export(evidence_id, destination, actor=actor)
    finally:
        catalog.close()


@pytest.fixture
def evidence(tmp_path):
    root = tmp_path / "evidence"
    recorder = EvidenceRecorder(root, pre_sec=0, post_sec=0)
    first = capture(recorder, 100, "first")
    assert first["ok"]
    yield root, recorder, first["evidence_id"]
    recorder.close()


def test_recorder_holds_and_detections_proceed_during_export(tmp_path, monkeypatch, evidence):
    root, recorder, evidence_id = evidence
    entered, release = threading.Event(), threading.Event()
    gate_copy(monkeypatch, entered, release)
    destination = tmp_path / "held.zip"
    thread, box = run(exporter, root, evidence_id, destination)
    assert entered.wait(5)
    # Capture-side writer: retention + registration of a new PCAP.
    assert within(3, capture, recorder, 101, "second")["ok"]
    other = EvidenceCatalog(root)
    within(3, other.hold, evidence_id, actor="analyst", reason="Open investigation")
    within(3, other.hold, evidence_id, actor="analyst", reason="Closed", enabled=False)
    store = DurableIncidentStore(str(root / "catalog.db"))
    from netwatch_core import make_message
    within(3, store.add, make_message("DOD_CORE", "ALERT", "1.1.1.1", {"message": "Finding"}))
    store.close()
    release.set()
    thread.join(10)
    assert box["result"]["ok"] and verify_export(destination)["ok"]
    operations = [row["operation"] for row in other.audit(evidence_id)]
    assert operations[:3] == ["exported", "release", "hold"]
    other.close()


def test_two_exports_copy_concurrently_and_both_audit(tmp_path, monkeypatch, evidence):
    root, _, evidence_id = evidence
    entered, release = threading.Event(), threading.Event()
    gate_copy(monkeypatch, entered, release, parties=2)
    workers = [run(exporter, root, evidence_id, tmp_path / f"{name}.zip", name) for name in ("console", "second")]
    assert entered.wait(4), "second export blocked behind the first"
    release.set()
    for thread, box in workers:
        thread.join(10)
        assert "error" not in box, box.get("error")
        assert box["result"]["ok"]
    catalog = EvidenceCatalog(root)
    assert sorted(row["actor"] for row in catalog.audit(evidence_id) if row["operation"] == "exported") == ["console", "second"]
    catalog.close()


def test_prune_during_export_wins_and_export_leaves_nothing(tmp_path, monkeypatch, evidence):
    root, _, evidence_id = evidence
    entered, release = threading.Event(), threading.Event()
    gate_copy(monkeypatch, entered, release)
    destination = tmp_path / "pruned.zip"
    thread, box = run(exporter, root, evidence_id, destination)
    assert entered.wait(5)
    other = EvidenceCatalog(root)
    assert evidence_id in within(3, other.prune, retention_days=1, now=10 * 86400)["removed"]
    release.set()
    thread.join(10)
    assert isinstance(box.get("error"), ValueError) and "no longer available" in str(box["error"])
    assert not destination.exists()
    assert "exported" not in [row["operation"] for row in other.audit(evidence_id)]
    other.close()


def test_payload_changed_during_copy_fails_and_removes_partial_archive(tmp_path, monkeypatch, evidence):
    root, recorder, evidence_id = evidence
    entered, release = threading.Event(), threading.Event()
    gate_copy(monkeypatch, entered, release)
    destination = tmp_path / "torn.zip"
    thread, box = run(exporter, root, evidence_id, destination)
    assert entered.wait(5)
    payload = root / recorder.catalog.get(evidence_id)["filename"]
    payload.write_bytes(payload.read_bytes()[:-8] + b"tampered")
    release.set()
    thread.join(10)
    assert isinstance(box.get("error"), ValueError)
    assert not destination.exists()
    assert "exported" not in [row["operation"] for row in recorder.catalog.audit(evidence_id)]


def _paused_export(root, evidence_id, destination, entered, release, results):
    original = zipfile.ZipFile.write

    def paused(self, *args, **kwargs):
        entered.set()
        release.wait(10)
        return original(self, *args, **kwargs)

    zipfile.ZipFile.write = paused
    try:
        results.put(exporter(root, evidence_id, destination, "service")["ok"])
    except Exception as exc:
        results.put(repr(exc))


def test_export_in_another_process_does_not_block_this_one(tmp_path, evidence):
    root, _, evidence_id = evidence
    context = mp.get_context("spawn")
    entered, release, results = context.Event(), context.Event(), context.Queue()
    child = context.Process(target=_paused_export,
                            args=(str(root), evidence_id, str(tmp_path / "child.zip"), entered, release, results))
    child.start()
    try:
        assert entered.wait(30)
        started = time.monotonic()
        assert within(3, exporter, root, evidence_id, tmp_path / "parent.zip", "console")["ok"]
        assert time.monotonic() - started < 3
    finally:
        release.set()
        child.join(30)
    assert results.get(timeout=5) is True
    assert verify_export(tmp_path / "child.zip")["ok"]


def test_verify_hashes_outside_the_write_lock(tmp_path, monkeypatch, evidence):
    import netwatch_evidence_catalog as catalog_module
    root, recorder, evidence_id = evidence
    entered, release = threading.Event(), threading.Event()
    original = catalog_module.file_digest

    def paused(path):
        if threading.current_thread().name == "verifier":
            entered.set()
            assert release.wait(10)
        return original(path)

    monkeypatch.setattr(catalog_module, "file_digest", paused)
    other = EvidenceCatalog(root)
    box = {}
    thread = threading.Thread(target=lambda: box.update(result=other.verify(evidence_id)), name="verifier", daemon=True)
    thread.start()
    assert entered.wait(5)
    assert within(3, capture, recorder, 101, "second")["ok"]
    release.set()
    thread.join(10)
    assert box["result"]["ok"]
    other.close()


def test_verify_does_not_resurrect_evidence_pruned_while_hashing(tmp_path, monkeypatch, evidence):
    import netwatch_evidence_catalog as catalog_module
    root, recorder, evidence_id = evidence
    entered, release = threading.Event(), threading.Event()
    original = catalog_module.file_digest

    def paused(path):
        if threading.current_thread().name == "verifier":
            entered.set()
            assert release.wait(10)
        return original(path)

    monkeypatch.setattr(catalog_module, "file_digest", paused)
    other = EvidenceCatalog(root)
    box = {}
    thread = threading.Thread(target=lambda: box.update(result=other.verify(evidence_id)), name="verifier", daemon=True)
    thread.start()
    assert entered.wait(5)
    assert evidence_id in within(3, recorder.catalog.prune, retention_days=1, now=10 * 86400)["removed"]
    release.set()
    thread.join(10)
    assert box["result"]["status"] == "pruned" and other.get(evidence_id)["status"] == "pruned"
    other.close()
