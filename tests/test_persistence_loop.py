"""The persistence loop must not block on spool maintenance, gap transfer or a stepped wall clock."""

import queue
import threading
import time
import types

import netwatch_db
from netwatch_db import db_persistence_worker
from netwatch_security_store import DurableIncidentStore
from netwatch_spool import TelemetrySpool
from tests.test_spool import _sample_rows


def _config(tmp_path):
    return {"DB_NAME": str(tmp_path / "ledger.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
            "SPOOL_PATH": str(tmp_path / "spool.db"), "DB_PRUNE_INTERVAL_SEC": 0,
            "LOG_DIR": "", "LOG_TO_CONSOLE": False}


def _heartbeats_for(tmp_path, seconds, shutdown, release=None):
    status = queue.Queue()
    worker = threading.Thread(target=db_persistence_worker,
                              args=(queue.Queue(), status, _config(tmp_path), shutdown))
    worker.start()
    try:
        time.sleep(seconds)
        beats = [m for m in iter(lambda: None if status.empty() else status.get_nowait(), None)
                 if m["action"] == "DB_HEARTBEAT"]
    finally:
        if release:
            release.set()  # the shutdown transfer would otherwise wait out the slow write too
        shutdown.set()
        worker.join(10)
    assert not worker.is_alive()
    return beats


def test_batch_path_runs_no_vacuum_or_checkpoint(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool.db"))
    sql = []
    spool.get_connection().set_trace_callback(sql.append)
    assert spool.enqueue_batch("b-1", _sample_rows(3), [])[0]
    spool.acknowledge_batch("b-1")
    assert not [s for s in sql if "VACUUM" in s.upper() or "WAL_CHECKPOINT" in s.upper()]
    spool.close()


def test_slow_gap_transfer_does_not_stall_the_heartbeat(tmp_path, monkeypatch):
    release = threading.Event()
    real = DurableIncidentStore.record_source_health

    def slow(self, *args, **kwargs):
        release.wait(6)
        return real(self, *args, **kwargs)

    TelemetrySpool(str(tmp_path / "spool.db"))._record_admission_refusal(100, 5, 3, 0, 1 << 20)
    monkeypatch.setattr(DurableIncidentStore, "record_source_health", slow)
    assert len(_heartbeats_for(tmp_path, 2.5, threading.Event(), release)) >= 2


def test_spool_gap_rows_are_not_resent_as_status(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool.db"))
    conn = spool.get_connection()
    for i in range(150):
        conn.execute("INSERT INTO spool_gaps (gap_id, timestamp, reason, dropped_rows, dropped_observations, "
                     "spool_bytes, limit_bytes) VALUES (?, 1.0, 'rejected_batch:x', 1, 0, 0, 1)", (f"rejected:{i}",))
    spool.close()
    status = queue.Queue(maxsize=100)
    shutdown = threading.Event()
    shutdown.set()
    db_persistence_worker(queue.Queue(), status, _config(tmp_path), shutdown)
    actions = [status.get_nowait()["action"] for _ in range(status.qsize())]
    assert "DB_HEARTBEAT" in actions and "SPOOL_GAP" not in actions


def test_heartbeat_survives_a_backwards_wall_clock_step(tmp_path, monkeypatch):
    start = time.time()
    clock = types.SimpleNamespace(
        time=lambda: time.time() - (3600 if time.time() - start > 1 else 0),
        monotonic=time.monotonic, sleep=time.sleep)
    monkeypatch.setattr(netwatch_db, "time", clock)
    assert len(_heartbeats_for(tmp_path, 3.5, threading.Event())) >= 3


def test_a_malformed_ledger_row_is_dropped_without_killing_the_worker(tmp_path):
    import sqlite3

    from netwatch_core import make_db_batch_message

    db_queue, shutdown = queue.Queue(), threading.Event()
    db_queue.put(make_db_batch_message([("short",), *_sample_rows(1, start_ts=time.time())], []))
    worker = threading.Thread(target=db_persistence_worker, args=(db_queue, queue.Queue(), _config(tmp_path), shutdown))
    worker.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and worker.is_alive():
        try:
            with sqlite3.connect(tmp_path / "ledger.db") as conn:
                if conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]:
                    break
        except sqlite3.Error:
            pass
        time.sleep(0.05)
    assert worker.is_alive()
    shutdown.set()
    worker.join(10)
    with sqlite3.connect(tmp_path / "ledger.db") as conn:
        assert conn.execute("SELECT uuid FROM network_events").fetchall() == [("evt-0",)]


def test_a_malformed_web_observation_is_logged_when_dropped(tmp_path):
    import logging
    import sqlite3

    from netwatch_core import make_db_batch_message

    errors = []  # the component logger does not propagate to caplog
    handler = logging.Handler(logging.ERROR)
    handler.emit = lambda record: errors.append(record.getMessage())
    logging.getLogger("netwatch.db").addHandler(handler)
    db_queue, shutdown = queue.Queue(), threading.Event()
    db_queue.put(make_db_batch_message(_sample_rows(1, start_ts=time.time()), [("short", 1, 2)]))
    worker = threading.Thread(target=db_persistence_worker, args=(db_queue, queue.Queue(), _config(tmp_path), shutdown))
    worker.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not errors:
        time.sleep(0.05)
    shutdown.set()
    worker.join(10)
    logging.getLogger("netwatch.db").removeHandler(handler)
    assert any("malformed web observation" in message for message in errors)
    with sqlite3.connect(tmp_path / "ledger.db") as conn:
        assert conn.execute("SELECT uuid FROM network_events").fetchall() == [("evt-0",)]


def test_ledger_connection_is_closed_when_the_shutdown_checkpoint_fails(tmp_path, monkeypatch):
    import logging
    import sqlite3

    from netwatch_core import make_db_batch_message

    closed, warnings = [], []

    class Conn(sqlite3.Connection):
        def execute(self, sql, *args):
            if "wal_checkpoint(TRUNCATE" in sql:
                raise sqlite3.OperationalError("database is locked")
            return super().execute(sql, *args)

        def close(self):
            closed.append(1)
            super().close()

    real = sqlite3.connect
    ledger = str(tmp_path / "ledger.db")
    monkeypatch.setattr(sqlite3, "connect",
                        lambda path, *a, **k: real(path, *a, **dict(k, factory=Conn)) if path == ledger else real(path, *a, **k))
    handler = logging.Handler(logging.WARNING)
    handler.emit = lambda record: warnings.append(record.getMessage())  # component logger does not propagate
    logging.getLogger("netwatch.db").addHandler(handler)
    db_queue, shutdown = queue.Queue(), threading.Event()
    db_queue.put(make_db_batch_message(_sample_rows(1, start_ts=time.time()), []))
    worker = threading.Thread(target=db_persistence_worker, args=(db_queue, queue.Queue(), _config(tmp_path), shutdown))
    worker.start()
    time.sleep(1)
    shutdown.set()
    worker.join(10)
    logging.getLogger("netwatch.db").removeHandler(handler)
    assert not worker.is_alive()
    assert closed, "ledger connection left open after a failed shutdown checkpoint"
    assert any("shutdown checkpoint failed" in m for m in warnings)


def test_ledger_checkpoint_truncates_a_wal_past_its_bound(tmp_path):
    import os
    import sqlite3

    import netwatch_db

    path = str(tmp_path / "ledger.db")
    writer = sqlite3.connect(path, isolation_level=None)
    netwatch_db.configure_connection(writer, 65536)
    writer.execute("PRAGMA wal_autocheckpoint=0;")
    writer.execute("CREATE TABLE t (v BLOB)")
    writer.execute("BEGIN")
    writer.executemany("INSERT INTO t VALUES (?)", ((os.urandom(512),) for _ in range(2000)))
    writer.execute("COMMIT")  # ~1 MB of WAL, far past 4 x 64 KiB; PASSIVE alone never shrinks the file
    checkpointer = sqlite3.connect(path, isolation_level=None, timeout=0)
    assert netwatch_db.checkpoint_ledger(checkpointer, path + "-wal", 65536)
    assert os.path.getsize(path + "-wal") == 0
    assert not netwatch_db.checkpoint_ledger(checkpointer, path + "-wal", 65536)  # within bound: PASSIVE only
    assert writer.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 2000
    checkpointer.close()
    writer.close()
