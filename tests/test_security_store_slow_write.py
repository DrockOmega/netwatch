import logging
import os
import sqlite3
import time

import netwatch_security_store
from netwatch_security_store import DurableIncidentStore


def _capture(monkeypatch):
    # Other tests leave component loggers configured; pin the one the store reports through.
    logger = logging.getLogger("netwatch.testcomponent")
    monkeypatch.setattr(netwatch_security_store, "_component_logger", lambda: logger)


def test_slow_write_names_its_caller(tmp_path, monkeypatch, caplog):
    _capture(monkeypatch)
    store = DurableIncidentStore(str(tmp_path / "s.db"))
    clock = iter([100.0, 103.5])
    monkeypatch.setattr(netwatch_security_store.time, "monotonic", lambda: next(clock))
    try:
        with caplog.at_level(logging.WARNING, logger="netwatch.testcomponent"):
            with store._transaction():
                pass
    finally:
        store.close()
    assert "held the writer lock 3.5s" in caplog.text
    assert "test_slow_write_names_its_caller" in caplog.text


def test_writer_still_holding_is_reported_mid_hold(tmp_path, monkeypatch, caplog):
    _capture(monkeypatch)
    monkeypatch.setattr(netwatch_security_store, "SLOW_WRITE_SEC", 0.05)
    store = DurableIncidentStore(str(tmp_path / "s.db"))
    try:
        with caplog.at_level(logging.WARNING, logger="netwatch.testcomponent"):
            with store._transaction():
                deadline = netwatch_security_store.time.monotonic() + 2
                while "still holding" not in caplog.text and netwatch_security_store.time.monotonic() < deadline:
                    netwatch_security_store.time.sleep(0.01)
                assert "test_writer_still_holding_is_reported_mid_hold" in caplog.text
    finally:
        store.close()


def test_wal_is_checkpointed_in_the_background_not_after_commits(tmp_path, monkeypatch):
    calls = []
    real = DurableIncidentStore._checkpoint_wal
    monkeypatch.setattr(DurableIncidentStore, "WAL_CHECKPOINT_SEC", 0.02)
    monkeypatch.setattr(DurableIncidentStore, "_checkpoint_wal",
                        lambda self, stop: (calls.append(1), real(self, stop)))
    store = DurableIncidentStore(str(tmp_path / "s.db"))
    assert store.conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0] == 0
    deadline = netwatch_security_store.time.monotonic() + 2
    while not calls and netwatch_security_store.time.monotonic() < deadline:
        netwatch_security_store.time.sleep(0.01)  # the thread records its start asynchronously
    assert calls == [1]
    store.close()
    assert store._checkpointer.is_set()  # other tests' unclosed stores keep their own threads


def test_order_backfill_probe_runs_until_done_then_never_again(tmp_path):
    """The probe scanned the whole native ledger on every store open (11 s each on the sensor VM)."""
    path = tmp_path / "security.db"
    store = DurableIncidentStore(path)
    rows = [(f"e{i}", "SURICATA", "s", "flow", 1.0, float(i), "{}", "{}") for i in range(3)]
    with store._transaction():
        store.conn.executemany("INSERT INTO security_source_events VALUES (?,?,?,?,?,?,?,?)", rows)
        store.conn.execute("DELETE FROM security_source_cursors WHERE source_key=?",
                           (netwatch_security_store.ORDER_BACKFILL_KEY,))
    store.close()
    store = DurableIncidentStore(path)  # legacy rows without a sequence: backfilled and marked
    assert store.conn.execute("SELECT COUNT(*) FROM security_source_order").fetchone()[0] == 3
    store.conn.execute("DELETE FROM security_source_order WHERE event_id='e0'")
    store.close()
    store = DurableIncidentStore(path)  # marked: no scan on this open
    assert store.conn.execute("SELECT COUNT(*) FROM security_source_order").fetchone()[0] == 2
    store.close()


def test_wal_file_is_truncated_to_the_limit_after_a_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(netwatch_security_store, "WAL_MAX_BYTES", 65536)
    monkeypatch.setattr(DurableIncidentStore, "WAL_CHECKPOINT_SEC", 0.02)
    path = tmp_path / "s.db"
    store = DurableIncidentStore(str(path))
    try:
        store.conn.execute("CREATE TABLE blob (b BLOB)")
        store.conn.execute("PRAGMA wal_autocheckpoint=0")
        for _ in range(40):
            store.conn.execute("INSERT INTO blob VALUES (zeroblob(65536))")
        assert os.path.getsize(f"{path}-wal") > 65536 * 4
        deadline = time.monotonic() + 5
        while os.path.getsize(f"{path}-wal") > 65536 and time.monotonic() < deadline:
            time.sleep(0.05)
            store.conn.execute("INSERT INTO blob VALUES (zeroblob(100))")  # the next write resets and truncates the WAL
        assert os.path.getsize(f"{path}-wal") <= 65536
    finally:
        store.close()


def _hold_write_lock(path, seconds):
    import time

    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    time.sleep(seconds)
    conn.execute("COMMIT")
    conn.close()


def test_a_writer_waiting_for_the_lock_never_freezes_other_threads(tmp_path):
    """The slow-write timer read conn.in_transaction while its writer sat in BEGIN's busy wait,
    which held the GIL until the busy timeout expired: every thread of the process froze
    (~32 s with a 30 s timeout, the sniffer stalls on Sensor1 2026-10-11/12)."""
    import multiprocessing as mp
    import threading
    import time

    from netwatch_security_store import DurableIncidentStore

    path = str(tmp_path / "security.db")
    store = DurableIncidentStore(path)
    with store._lock:
        store.conn.execute("PRAGMA busy_timeout=4000")
    holder = mp.get_context("spawn").Process(target=_hold_write_lock, args=(path, 5))
    holder.start()
    time.sleep(1.5)  # the other process holds the write lock

    def write():
        try:
            with store._transaction():
                pass
        except Exception:
            pass  # busy timeout: expected

    writer = threading.Thread(target=write, daemon=True)
    writer.start()
    worst, end = 0.0, time.monotonic() + 3
    while time.monotonic() < end:
        started = time.monotonic()
        time.sleep(0.01)
        worst = max(worst, time.monotonic() - started)
    writer.join(10)
    holder.join(10)
    store.close()
    assert worst < 0.5, f"another thread froze for {worst:.1f}s while a writer waited for the lock"


def test_checkpoint_error_is_logged_once_per_distinct_text(tmp_path, monkeypatch):
    import threading

    stop, state, messages = threading.Event(), {"n": 0}, []
    texts = ["database is locked"] * 3 + ["disk I/O error"]

    class Conn:
        def execute(self, sql):
            if "wal_checkpoint" in sql:
                text = texts[state["n"]]
                state["n"] += 1
                if state["n"] == len(texts):
                    stop.set()
                raise sqlite3.OperationalError(text)

        def close(self):
            pass

    logger = logging.getLogger("netwatch.testcomponent")
    handler = logging.Handler(logging.WARNING)
    handler.emit = lambda record: messages.append(record.getMessage())  # propagate=False in production
    logger.addHandler(handler)
    _capture(monkeypatch)
    monkeypatch.setattr(netwatch_security_store.sqlite3, "connect", lambda *a, **k: Conn())
    monkeypatch.setattr(DurableIncidentStore, "WAL_CHECKPOINT_SEC", 0.001)
    store = DurableIncidentStore.__new__(DurableIncidentStore)
    store.path = str(tmp_path / "s.db")
    try:
        store._checkpoint_wal(stop)
    finally:
        logger.removeHandler(handler)
    assert [m for m in messages if "checkpoint" in m] and len(messages) == 2
    assert "database is locked" in messages[0] and "disk I/O error" in messages[1]
