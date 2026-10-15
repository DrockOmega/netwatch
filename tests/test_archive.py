import datetime as dt
import gzip
import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from netwatch_archive import (
    CASE_SNAPSHOTS_KEPT,
    export_ledger_day,
    finished_eve_files,
    run,
    snapshot_cases,
    verify_snapshot,
)

DAY = dt.date(2026, 10, 8)
T0 = dt.datetime(2026, 10, 8, tzinfo=dt.UTC).timestamp()


def _ledger(path, stamps):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE network_events (uuid TEXT PRIMARY KEY, timestamp REAL, src_ip TEXT, packet_metadata BLOB)")
    conn.executemany("INSERT INTO network_events VALUES (?, ?, ?, ?)",
                     [(f"u{i}", ts, "10.0.0.5", b"\x01") for i, ts in enumerate(stamps)])
    conn.commit()
    conn.close()


def test_export_takes_exactly_one_utc_day(tmp_path):
    db = tmp_path / "ledger.db"
    _ledger(db, [T0 - 1, T0, T0 + 3599.5, T0 + 86399.9, T0 + 86400])
    out = tmp_path / "day.jsonl.gz"
    assert export_ledger_day(db, DAY, out) == 3
    rows = [json.loads(line) for line in gzip.open(out, "rt")]
    assert [r["timestamp"] for r in rows] == [T0, T0 + 3599.5, T0 + 86399.9]
    assert rows[0]["packet_metadata"] == "01"


def test_finished_eve_files_skip_the_live_file_and_fresh_writes(tmp_path):
    eve = tmp_path / "eve.json"
    for name, age in (("eve.json", 90_000), ("eve.json.2026-10-10", 3_000), ("eve.json.2026-10-11", 0),
                      ("eve.json.2026-10-09.gz", 90_000)):
        (tmp_path / name).write_text("{}\n")
        os.utime(tmp_path / name, (1_000_000 - age, 1_000_000 - age))
    assert [p.name for p in finished_eve_files(eve, 1_000_000)] == ["eve.json", "eve.json.2026-10-10"]
    os.utime(tmp_path / "eve.json.2026-10-10", (1_000_000 - 60, 1_000_000 - 60))
    assert [p.name for p in finished_eve_files(eve, 1_000_000)] == ["eve.json"]


def test_run_records_only_successful_uploads_and_is_idempotent(tmp_path):
    db = tmp_path / "telemetry_ledger.db"
    _ledger(db, [T0 + 10, T0 + 86400 + 10, T0 + 2 * 86400 + 10])
    eve_dir = tmp_path / "suricata"
    eve_dir.mkdir()
    for name, age in (("eve.json.2026-10-08", 90_000), ("eve.json.2026-10-09", 0)):
        (eve_dir / name).write_bytes(b'{"event_type":"flow"}\n')
        os.utime(eve_dir / name, (T0 + 2 * 86400 - age, T0 + 2 * 86400 - age))
    config = {"DB_NAME": str(db), "SURICATA_EVE_PATH": str(eve_dir / "eve.json")}
    remote, sent, fail = tmp_path / "remote", [], {"ledger-2026-10-09.jsonl.gz"}

    def upload(local, remote_path):
        if os.path.basename(remote_path) in fail:
            raise subprocess.CalledProcessError(1, "rclone", stderr=b"quota exceeded")
        os.makedirs(os.path.dirname(remote_path), exist_ok=True)
        shutil.copy(local, remote_path)
        sent.append(Path(os.path.relpath(remote_path, remote)).as_posix())

    now = T0 + 2 * 86400 + 20  # 2026-10-10: the 8th and 9th are complete days
    assert run(config, str(remote), upload, now=now) == 1
    assert sorted(sent) == ["ledger/ledger-2026-10-08.jsonl.gz", "suricata/eve.json.2026-10-08.gz"]
    assert not list((tmp_path / "archive" / "staging").iterdir())
    fail.clear()
    sent.clear()
    assert run(config, str(remote), upload, now=now) == 0
    assert sent == ["ledger/ledger-2026-10-09.jsonl.gz"]
    sent.clear()
    assert run(config, str(remote), upload, now=now) == 0 and sent == []
    assert gzip.open(remote / "suricata" / "eve.json.2026-10-08.gz").read() == b'{"event_type":"flow"}\n'


def test_rclone_command_lines_and_remote_retention(tmp_path, monkeypatch):
    import netwatch_archive

    calls = []
    # Also answers build_config's gateway lookup (route print) on Windows.
    monkeypatch.setattr(netwatch_archive.subprocess, "run",
                        lambda cmd, **kw: calls.append((cmd, kw)) or subprocess.CompletedProcess(cmd, 0, "", ""))
    netwatch_archive.rclone_uploader("rc", tmp_path / "r.conf")(tmp_path / "a.gz", "remote:dir/a.gz")
    netwatch_archive.rclone_uploader("rc", None)(tmp_path / "a.gz", "remote:dir/a.gz")
    assert calls[0][0] == ["rc", "copyto", str(tmp_path / "a.gz"), "remote:dir/a.gz", "--config", str(tmp_path / "r.conf")]
    assert calls[1][0] == ["rc", "copyto", str(tmp_path / "a.gz"), "remote:dir/a.gz"]
    assert calls[0][1]["check"] is True

    # main(): the retention call is the only remote delete
    (tmp_path / "base").mkdir()
    _ledger(tmp_path / "base" / "telemetry_ledger.db", [])
    calls.clear()
    assert netwatch_archive.main(["--base-dir", str(tmp_path / "base"), "--remote", "gd:Arch/", "--rclone", "rc",
                                  "--rclone-config", str(tmp_path / "r.conf"), "--keep-days", "30"]) == 0
    deletes = [c for c, _ in calls if c[1] == "delete"]
    assert deletes == [["rc", "delete", "gd:Arch", "--min-age", "30d", "--config", str(tmp_path / "r.conf")]]


def test_failed_remote_retention_counts_as_a_failure(tmp_path, monkeypatch):
    import netwatch_archive

    def boom(*_a, **_k):
        raise subprocess.CalledProcessError(1, "rc")

    monkeypatch.setattr(netwatch_archive.subprocess, "run", boom)
    (tmp_path / "base").mkdir()
    _ledger(tmp_path / "base" / "telemetry_ledger.db", [])
    assert netwatch_archive.main(["--base-dir", str(tmp_path / "base"), "--remote", "gd:Arch"]) == 1


def _security_store(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE security_incidents (incident_id TEXT PRIMARY KEY, status TEXT);
        CREATE INDEX idx_status ON security_incidents(status);
        CREATE TABLE security_case_audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT);
        CREATE TABLE security_source_events (event_id TEXT PRIMARY KEY, native TEXT);
        INSERT INTO security_incidents VALUES ('NW-1', 'Open'), ('NW-2', 'Dismissed');
        INSERT INTO security_case_audit(incident_id) VALUES ('NW-1'), ('NW-1'), ('NW-2');
        DELETE FROM security_case_audit WHERE sequence = 3;
        INSERT INTO security_source_events VALUES ('e1', 'x');
    """)
    conn.commit()
    return conn  # left open: the WAL holds the rows, like the live store


def test_cases_snapshot_is_consistent_skips_native_payloads_and_restores(tmp_path):
    live = _security_store(tmp_path / "sec.db")
    out = tmp_path / "snap.db"
    counts = snapshot_cases(tmp_path / "sec.db", out)
    assert counts == {"security_incidents": 2, "security_case_audit": 2}
    verify_snapshot(out, counts)
    snap = sqlite3.connect(f"file:{out.as_posix()}?mode=ro", uri=True)
    tables = {r[0] for r in snap.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'index')")}
    assert "security_source_events" not in tables and "idx_status" in tables
    assert snap.execute("SELECT seq FROM sqlite_sequence WHERE name='security_case_audit'").fetchone() == (3,)
    snap.close()
    with pytest.raises(sqlite3.DatabaseError):
        verify_snapshot(out, dict(counts, security_incidents=3))
    live.close()


def test_run_uploads_a_cases_snapshot_and_keeps_a_bounded_local_set(tmp_path):
    _security_store(tmp_path / "sec.db").close()
    db = tmp_path / "telemetry_ledger.db"
    _ledger(db, [])
    config = {"DB_NAME": str(db), "INCIDENT_DB": str(tmp_path / "sec.db"),
              "SURICATA_EVE_PATH": str(tmp_path / "eve.json")}
    sent = []

    def upload(local, remote_path):
        sent.append(remote_path)
        shutil.copy(local, tmp_path / Path(remote_path).name)

    for day in range(CASE_SNAPSHOTS_KEPT + 2):
        assert run(config, "gd:A", upload, now=T0 + day * 86400) == 0
    assert sent[0] == "gd:A/cases/cases-20261008T000000Z.db.gz"
    kept = sorted(p.name for p in (tmp_path / "archive" / "cases").iterdir())
    assert len(kept) == CASE_SNAPSHOTS_KEPT and kept[-1] == Path(sent[-1]).name
    restored = tmp_path / "restored.db"
    restored.write_bytes(gzip.open(tmp_path / kept[-1]).read())
    verify_snapshot(restored, {"security_incidents": 2, "security_case_audit": 2})
    assert not list((tmp_path / "archive" / "staging").iterdir())
