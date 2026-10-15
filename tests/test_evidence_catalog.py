import json
import os
import sqlite3
import zipfile

import pytest

from netwatch_core import make_message
from netwatch_evidence import EvidenceRecorder
from netwatch_evidence_catalog import EvidenceCatalog, verify_export
from netwatch_security_store import DurableIncidentStore


def capture(recorder, timestamp=100, identity="first"):
    recorder.add(timestamp, b"x" * 60)
    assert recorder.request({"trigger_ts": timestamp, "action": "ALERT", "correlation_id": identity,
                             "source": "DOD_CORE", "sensor_id": "sensor-a"}, now=timestamp)
    recorder.poll(now=timestamp, force=True)
    recorder.write_jobs.join()
    return recorder.poll(now=timestamp)[0]


def test_hold_blocks_retention_and_export_detects_tampering(tmp_path):
    root = tmp_path / "evidence"
    recorder = EvidenceRecorder(root, pre_sec=0, post_sec=0, max_files=1)
    first = capture(recorder)
    catalog = recorder.catalog
    item = catalog.get(first["evidence_id"])
    assert catalog.verify(item["evidence_id"])["ok"]
    catalog.hold(item["evidence_id"], actor="analyst", reason="Open investigation")
    assert not capture(recorder, 101, "second")["ok"]
    export = tmp_path / "capture.zip"
    assert catalog.export(item["evidence_id"], export, actor="analyst")["ok"]
    assert verify_export(export)["ok"]
    with pytest.raises(FileExistsError):
        catalog.export(item["evidence_id"], export, actor="analyst")
    recorder.close()
    catalog = EvidenceCatalog(root)
    assert catalog.get(item["evidence_id"])["held"]
    assert not catalog.prune(max_files=1, reserve_files=1, now=1000)["admitted"]
    payload = root / item["filename"]
    payload.write_bytes(b"tampered")
    assert catalog.verify(item["evidence_id"])["status"] == "corrupt"
    with pytest.raises(ValueError, match="integrity"):
        catalog.export(item["evidence_id"], tmp_path / "bad.zip", actor="analyst")
    catalog.close()


def test_completed_orphan_recovery_and_interrupted_prune(tmp_path, monkeypatch):
    recorder = EvidenceRecorder(tmp_path, pre_sec=0, post_sec=0)
    original = recorder.catalog.register
    monkeypatch.setattr(recorder.catalog, "register", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("disk full")))
    assert not capture(recorder)["ok"]
    assert recorder.catalog.list() == []
    monkeypatch.setattr(recorder.catalog, "register", original)
    assert recorder.catalog.recover() == {"recovered": 1, "errors": []}
    item = recorder.catalog.list()[0]
    finish = recorder.catalog._finish_prune
    monkeypatch.setattr(recorder.catalog, "_finish_prune", lambda *a: (_ for _ in ()).throw(OSError("power loss")))
    with pytest.raises(OSError):
        recorder.catalog.prune(max_files=1, reserve_files=1, now=101)
    assert recorder.catalog.get(item["evidence_id"])["status"] == "pruning"
    with pytest.raises(ValueError):
        recorder.catalog.hold(item["evidence_id"], actor="analyst", reason="Too late")
    monkeypatch.setattr(recorder.catalog, "_finish_prune", finish)
    recorder.close()
    catalog = EvidenceCatalog(tmp_path)
    assert catalog.recover()["errors"] == []
    assert catalog.get(item["evidence_id"])["status"] == "pruned"
    assert not (tmp_path / item["filename"]).exists()
    assert [event["operation"] for event in catalog.audit(item["evidence_id"])][:2] == ["pruned", "prune_requested"]
    catalog.close()


def test_coalesced_triggers_link_each_case_and_extend_window(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    cases = [store.add(make_message("DOD_CORE", "ALERT", target, {"message": "Finding"}, correlation_id=identity))
             for target, identity in [("1.1.1.1", "first"), ("8.8.8.8", "second")]]
    recorder = EvidenceRecorder(tmp_path / "captures", catalog_path=tmp_path / "security.db", pre_sec=0,
                                post_sec=0, sensor_id="sensor-a", max_triggers=2)
    recorder.add(100, b"first")
    recorder.add(101, b"second")
    for timestamp, identity in [(100, "first"), (101, "second")]:
        assert recorder.request({"trigger_ts": timestamp, "action": "ALERT", "correlation_id": identity,
                                 "source": "DOD_CORE", "sensor_id": "sensor-a"}, now=timestamp)
    assert not recorder.request({"trigger_ts": 101, "action": "ALERT"}, now=101)
    recorder.poll(now=102, force=True)
    recorder.write_jobs.join()
    result = recorder.poll(now=102)[0]
    assert result["ok"] and result["frames"] == 2
    manifest = recorder.catalog.get(result["evidence_id"])["body"]
    assert len(manifest["triggers"]) == 2 and manifest["sensor_id"] == "sensor-a"
    links = store.conn.execute("SELECT incident_id, reference FROM security_case_links WHERE kind='evidence'").fetchall()
    assert {(row[0], row[1]) for row in links} == {(case["incident_id"], result["evidence_id"]) for case in cases}
    recorder.close()
    store.close()


def test_unknown_files_quota_and_unsafe_paths_are_preserved(tmp_path):
    recorder = EvidenceRecorder(tmp_path, pre_sec=0, post_sec=0, max_bytes=100)
    for timestamp in (float("nan"), float("inf"), -1, "invalid"):
        assert not recorder.request({"trigger_ts": timestamp}, now=100)
    unknown = tmp_path / "unfinished.pcap.partial"
    unknown.write_bytes(b"x" * 100)
    assert not capture(recorder)["ok"]
    assert unknown.exists()
    for filename in ("../escape.pcap", "", ".", "a\\b.pcap"):
        with pytest.raises(ValueError):
            recorder.catalog._path(filename)
    if os.name == "posix":
        (tmp_path / "link.pcap").symlink_to(unknown)
        with pytest.raises(ValueError):
            recorder.catalog._path("link.pcap")
    recorder.close()


def test_manifest_tampering_and_archive_boundaries(tmp_path):
    recorder = EvidenceRecorder(tmp_path / "captures", pre_sec=0, post_sec=0)
    result = capture(recorder)
    item = recorder.catalog.get(result["evidence_id"])
    sidecar = tmp_path / "captures" / (item["filename"] + ".manifest.json")
    body = json.loads(sidecar.read_text())
    body["sensor_id"] = "replaced"
    sidecar.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="inconsistent"):
        recorder.catalog.register(item["body"])
    assert not recorder.catalog.verify(item["evidence_id"])["ok"]
    archive = tmp_path / "oversized.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("manifest.json", " " * 1_048_577)
        output.writestr("capture.pcap", b"fake")
    with pytest.raises(ValueError, match="manifest"):
        verify_export(archive)
    recorder.close()


def test_prune_under_quota_takes_no_writer_lock(tmp_path):
    """Prune opened a transaction and rescanned the directory per catalog row, even with nothing to prune."""
    root = tmp_path / "evidence"
    recorder = EvidenceRecorder(root, pre_sec=0, post_sec=0, max_files=10)
    for i in range(3):
        assert capture(recorder, 100 + i, f"c{i}")["ok"]
    catalog = recorder.catalog
    seen = []
    catalog.store.conn.set_trace_callback(seen.append)
    assert catalog.prune(max_files=10, reserve_files=1, now=200)["removed"] == []
    assert "BEGIN IMMEDIATE" not in seen
    assert len(catalog.prune(max_files=2, reserve_files=1, now=200)["removed"]) == 2  # still prunes at quota
    recorder.close()


def test_missing_and_corrupt_evidence_age_out(tmp_path):
    root = tmp_path / "evidence"
    recorder = EvidenceRecorder(root, pre_sec=0, post_sec=0, max_files=10)
    missing = capture(recorder, 100, "gone")
    corrupt = capture(recorder, 101, "bad")
    catalog = recorder.catalog
    (root / catalog.get(missing["evidence_id"])["filename"]).unlink()
    (root / catalog.get(corrupt["evidence_id"])["filename"]).write_bytes(b"tampered")
    assert catalog.verify(missing["evidence_id"])["status"] == "missing"
    assert catalog.verify(corrupt["evidence_id"])["status"] == "corrupt"
    removed = catalog.prune(retention_days=1, now=101 + 2 * 86400)["removed"]
    assert set(removed) == {missing["evidence_id"], corrupt["evidence_id"]}
    assert {catalog.get(i)["status"] for i in removed} == {"pruned"}
    recorder.close()
