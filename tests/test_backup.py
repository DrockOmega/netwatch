import json
import os
import sqlite3
import threading

import pytest

from netwatch_backup import MANIFEST, backup, main, restore, verify
from netwatch_core import make_message
from netwatch_security_store import DurableIncidentStore
from netwatch_spool import TelemetrySpool
from tests.test_spool import _sample_rows


@pytest.fixture
def runtime(tmp_path):
    """A live runtime directory: open WAL stores with committed rows still only in the WAL."""
    base = tmp_path / "runtime"
    base.mkdir()
    (base / "netwatch.config.json").write_text(json.dumps({"SENSOR_ID": "backup-test"}))
    (base / "evidence").mkdir()
    (base / "evidence" / "1_ALERT_x.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    (base / "evidence" / "1_ALERT_x.pcap.manifest.json").write_text("{}")
    store = DurableIncidentStore(base / "telemetry_security.db")
    store.add(make_message("TEST", "ALERT", "SYSTEM", {"message": "backed up", "severity": "alert"}))
    spool = TelemetrySpool(str(base / "telemetry_spool.db"))
    spool.enqueue_batch("b-1", _sample_rows(3), [])
    ledger = sqlite3.connect(base / "telemetry_ledger.db", isolation_level=None, check_same_thread=False)
    ledger.execute("PRAGMA journal_mode=WAL")
    ledger.execute("PRAGMA wal_autocheckpoint=0")  # keep committed rows in the WAL, as a busy writer does
    ledger.execute("CREATE TABLE network_events (id INTEGER PRIMARY KEY, payload TEXT)")
    ledger.executemany("INSERT INTO network_events(payload) VALUES (?)", [("row",)] * 100)
    yield base, ledger
    ledger.close()
    spool.close()
    store.close()


def _rows(path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]


def test_online_backup_while_writing_then_verified_restore(tmp_path, runtime):
    base, ledger = runtime
    stop = threading.Event()

    def writer():
        while not stop.is_set():
            ledger.execute("INSERT INTO network_events(payload) VALUES ('live')")

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        manifest = backup(base, tmp_path / "backup")
    finally:
        stop.set()
        thread.join()
    written = ledger.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]
    kinds = {entry["path"]: entry["kind"] for entry in manifest["files"]}
    assert kinds == {"telemetry_security.db": "sqlite", "telemetry_ledger.db": "sqlite",
                     "telemetry_spool.db": "sqlite", "netwatch.config.json": "config",
                     "evidence/1_ALERT_x.pcap": "evidence", "evidence/1_ALERT_x.pcap.manifest.json": "evidence"}
    assert 100 <= _rows(tmp_path / "backup" / "telemetry_ledger.db") <= written  # WAL rows included

    target = tmp_path / "restored"
    restore(tmp_path / "backup", target)
    assert _rows(target / "telemetry_ledger.db") == _rows(tmp_path / "backup" / "telemetry_ledger.db")
    restored = DurableIncidentStore(target / "telemetry_security.db")
    try:
        assert restored.open_count() == 1
    finally:
        restored.close()
    assert TelemetrySpool(str(target / "telemetry_spool.db")).count_pending()["batches"] == 1
    assert (target / "evidence" / "1_ALERT_x.pcap").read_bytes() == (base / "evidence" / "1_ALERT_x.pcap").read_bytes()
    assert (target / "netwatch.config.json").read_text() == (base / "netwatch.config.json").read_text()


def test_verify_rejects_changed_files_and_corrupt_stores(tmp_path, runtime):
    base, _ = runtime
    copy = tmp_path / "backup"
    backup(base, copy)
    pcap = copy / "evidence" / "1_ALERT_x.pcap"
    pcap.write_bytes(pcap.read_bytes()[:-1] + b"\x01")
    with pytest.raises(ValueError, match="1_ALERT_x.pcap: SHA-256 mismatch"):
        verify(copy)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        restore(copy, tmp_path / "never")
    assert not (tmp_path / "never").exists()  # nothing written when verification fails

    # A store whose bytes match its (rewritten) hash but whose pages are damaged fails integrity.
    copy2 = tmp_path / "backup2"
    backup(base, copy2)
    ledger = copy2 / "telemetry_ledger.db"
    data = bytearray(ledger.read_bytes())
    data[4096 + 8:4096 + 64] = b"\xff" * 56  # damage the first table b-tree page header/cells
    ledger.write_bytes(bytes(data))
    manifest = json.loads((copy2 / MANIFEST).read_text())
    from netwatch_evidence_catalog import file_digest
    for entry in manifest["files"]:
        if entry["path"] == "telemetry_ledger.db":
            entry["sha256"] = file_digest(ledger)
    (copy2 / MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="telemetry_ledger.db: integrity check failed"):
        verify(copy2)


def test_restore_refuses_non_empty_target_and_unsafe_manifest_paths(tmp_path, runtime):
    base, _ = runtime
    copy = tmp_path / "backup"
    backup(base, copy)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("existing")
    with pytest.raises(ValueError, match="empty directory"):
        restore(copy, occupied)
    assert [p.name for p in occupied.iterdir()] == ["keep.txt"]
    assert main(["restore", str(copy), str(occupied)]) == 1

    manifest = json.loads((copy / MANIFEST).read_text())
    manifest["files"][0]["path"] = "../escape.db"
    (copy / MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="unsafe path"):
        restore(copy, tmp_path / "target")


def test_backup_refuses_occupied_or_nested_output(tmp_path, runtime):
    base, _ = runtime
    with pytest.raises(ValueError, match="outside the runtime directory"):
        backup(base, base / "backups")
    assert not (base / "backups").exists()
    (tmp_path / "used").mkdir()
    (tmp_path / "used" / "x").write_text("x")
    with pytest.raises(ValueError, match="empty directory"):
        backup(base, tmp_path / "used")
    assert main(["backup", "--base-dir", str(base), str(tmp_path / "cli")]) == 0
    assert main(["verify", str(tmp_path / "cli")]) == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes; Windows relies on the base directory ACL")
def test_backup_is_owner_only_on_posix(tmp_path, runtime):
    import os
    base, _ = runtime
    old = os.umask(0o022)
    try:
        manifest = backup(base, tmp_path / "backup")
    finally:
        os.umask(old)
    assert (tmp_path / "backup").stat().st_mode & 0o777 == 0o700
    for entry in manifest["files"]:
        if entry["kind"] == "sqlite":
            assert (tmp_path / "backup" / entry["path"]).stat().st_mode & 0o777 == 0o600
