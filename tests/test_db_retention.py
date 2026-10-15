import json
import queue
import sqlite3
import threading

import pytest

import netwatch_db
from netwatch_core import make_message
from netwatch_db import (
    compact_event_rows,
    configure_connection,
    db_persistence_worker,
    ensure_network_event_columns,
    normalize_web_observation_rows,
    packet_row_metadata,
    prune_network_events,
    prune_web_observations,
)


def event_row(uuid, timestamp, *, flags="A", size=100, domain="encrypted-payload", count=1, metadata=None):
    return [
        uuid, timestamp, "src-mac", "dst-mac", "10.0.0.1", "8.8.8.8",
        "TCP", 443, flags, 64, size, domain, "US", count,
        *(metadata or (None, "null", "unknown", "unknown", 1, "{}")),
    ]


def test_event_rows_compact_to_directional_flow_seconds_with_packet_weight():
    compacted = compact_event_rows([
        event_row("one", 10.1, flags="S", size=60),
        event_row("two", 10.9, flags="A", size=140, count=3),
        event_row("three", 11.0, flags="A", size=80),
    ])

    assert len(compacted) == 2
    assert compacted[0][0] == "one"
    assert compacted[0][1] == 10.0
    assert compacted[0][8] == "SA"
    assert compacted[0][10] == 200
    assert compacted[0][13] == 4
    assert compacted[1][13] == 1


def test_event_compaction_keeps_distinct_domains_separate():
    compacted = compact_event_rows([
        event_row("one", 10.1, domain="api.example.com"),
        event_row("two", 10.2, domain="encrypted-payload"),
    ])
    assert len(compacted) == 2


def test_capture_identity_survives_compaction_and_database_reload(tmp_path):
    from netwatch_history import HistoryStore
    from netwatch_ui_state import load_recent_traffic_events

    rows = []
    variants = [(12345, [42], "sensor-a", "eth0"),
                (12346, [42], "sensor-a", "eth0"),
                (12345, [43], "sensor-a", "eth0"),
                (12345, [42], "sensor-b", "eth0"),
                (12345, [42], "sensor-a", "eth1")]
    for index, (port, tags, sensor, interface) in enumerate(variants):
        rows.append(event_row(str(index), 10.1, metadata=packet_row_metadata({
            "source_port": port, "vlan_ids": tags, "sensor_id": sensor,
            "interface": interface, "ip_protocol": 6, "fragmented": False,
        })))
    duplicate = rows[0].copy()
    duplicate[0] = "duplicate"
    compacted = compact_event_rows([*rows, duplicate])
    assert len(compacted) == 5
    assert compacted[0][13] == 2
    assert compact_event_rows(compacted) == compacted

    path = tmp_path / "capture.db"
    with sqlite3.connect(path) as conn:
        conn.execute("""CREATE TABLE network_events (
            uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, mac_dst TEXT,
            src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
            tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER, sni_domain TEXT,
            country TEXT)""")
        conn.execute("INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     event_row("legacy", 9.0)[:13])
        ensure_network_event_columns(conn)
        ensure_network_event_columns(conn)
        conn.executemany(netwatch_db.EVENT_INSERT_SQL, netwatch_db.ledger_event_rows(compacted))
    history = HistoryStore(str(path))
    try:
        stored = {row["uuid"]: row for row in history.query()}
    finally:
        history.close()
    assert stored["legacy"]["event_version"] == 1
    assert stored["legacy"]["source_port"] is None
    assert stored["legacy"]["sensor_id"] == "unknown"
    assert json.loads(stored["0"]["vlan_ids"]) == [42]
    events = {row["event_id"]: row for row in load_recent_traffic_events(str(path))}
    assert events["0"]["source_port"] == 12345
    assert events["0"]["sensor_id"] == "sensor-a"
    assert events["0"]["vlan_ids"] == [42]
    assert events["0"]["packet_metadata"] == {"fragmented": False, "ip_protocol": 6}
    assert events["legacy"]["vlan_ids"] is None


def test_web_observation_rows_are_validated_and_typed():
    rows = normalize_web_observation_rows([[
        "flow-1", "10.5", "10.0.0.2", "8.8.8.8", "src", "dst",
        "TCP", "443", "example.com", "HUMAN LIKELY", "7", "new destination",
        "WIN", "US", "517",
    ], ["short"]])

    assert rows == [(
        "flow-1", 10.5, "10.0.0.2", "8.8.8.8", "src", "dst",
        "TCP", 443, "example.com", "HUMAN LIKELY", 7, "new destination",
        "WIN", "US", 517,
    )]


def test_web_observation_retention_is_bounded(tmp_path):
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    try:
        conn.execute("CREATE TABLE web_observations (flow_id TEXT, timestamp REAL)")
        conn.executemany(
            "INSERT INTO web_observations VALUES (?, ?)",
            [(f"flow-{index}", float(index)) for index in range(10)],
        )
        removed, more = prune_web_observations(
            conn, now=10, retention_days=0, max_rows=4, batch_rows=10,
        )
        remaining = conn.execute(
            "SELECT flow_id FROM web_observations ORDER BY timestamp"
        ).fetchall()
    finally:
        conn.close()

    assert removed == 6
    assert more is False
    assert remaining == [("flow-6",), ("flow-7",), ("flow-8",), ("flow-9",)]


def test_writer_connection_caps_reusable_wal_space(tmp_path):
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    try:
        assert configure_connection(conn, 1_048_576) == 1_048_576
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert conn.execute("PRAGMA journal_size_limit").fetchone()[0] == 1_048_576
    finally:
        conn.close()


def test_writer_connection_rejects_failed_wal_activation():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    try:
        with pytest.raises(sqlite3.OperationalError, match="WAL activation failed"):
            configure_connection(conn, 1_048_576)
    finally:
        conn.close()


def drain(conn, **kwargs):
    """Call until no work remains, as the worker does across turns; returns each call's removal."""
    removed = []
    while True:
        count, more = prune_network_events(conn, **kwargs)
        removed.append(count)
        if not more:
            return removed


def test_retention_prunes_one_bounded_batch_per_call(tmp_path):
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    try:
        conn.execute("CREATE TABLE network_events (timestamp REAL)")
        conn.executemany(
            "INSERT INTO network_events (timestamp) VALUES (?)",
            [(float(index),) for index in range(23)],
        )

        removed = drain(conn, now=100, retention_days=0, max_rows=5, batch_rows=4)

        rows = conn.execute(
            "SELECT timestamp FROM network_events ORDER BY timestamp"
        ).fetchall()
    finally:
        conn.close()

    assert removed == [4, 4, 4, 4, 2]
    assert rows == [(18.0,), (19.0,), (20.0,), (21.0,), (22.0,)]


def test_retention_age_and_row_ceiling_do_not_double_count(tmp_path):
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    try:
        conn.execute("CREATE TABLE network_events (timestamp REAL)")
        conn.executemany(
            "INSERT INTO network_events (timestamp) VALUES (?)",
            [(float(index),) for index in range(20)],
        )

        removed = drain(conn, now=20, retention_days=10 / 86400, max_rows=5, batch_rows=3)
        remaining = conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]
    finally:
        conn.close()

    assert sum(removed) == 15
    assert remaining == 5


def test_retention_batch_budget_reports_remaining_work(tmp_path):
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    try:
        conn.execute("CREATE TABLE network_events (timestamp REAL)")
        conn.executemany(
            "INSERT INTO network_events (timestamp) VALUES (?)",
            [(float(index),) for index in range(23)],
        )
        removed, more = prune_network_events(
            conn,
            now=100,
            retention_days=0,
            max_rows=5,
            batch_rows=4,
        )
        remaining = conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]
    finally:
        conn.close()

    assert removed == 4
    assert more is True
    assert remaining == 19


def test_worker_persists_queued_batch_between_pending_prune_passes(tmp_path, monkeypatch):
    db_path = tmp_path / "ledger.db"
    db_queue = queue.Queue()
    status_queue = queue.Queue()
    shutdown = threading.Event()
    observed = []
    calls = 0

    def bounded_prune(conn, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 1, True
        observed.append(conn.execute(
            "SELECT COUNT(*) FROM network_events WHERE uuid = 'sentinel'"
        ).fetchone()[0])
        shutdown.set()
        return 0, False

    monkeypatch.setattr(netwatch_db, "prune_network_events", bounded_prune)
    db_queue.put(make_message("DOD_CORE", "DB_BATCH", "DB_WORKER", {"rows": [[
        "sentinel", 1.0, "src-mac", "dst-mac", "10.0.0.1", "8.8.8.8",
        "UDP", 53, "", 64, 72, "example.com", "US", 1, None, "null", "unknown", "unknown", 1, "{}",
    ]] }))
    config = {
        "DB_NAME": str(db_path),
        "SPOOL_PATH": str(tmp_path / "spool.db"),
        "DB_RETENTION_DAYS": 0,
        "DB_MAX_ROWS": 1,
        "DB_PRUNE_INTERVAL_SEC": 0,
        "DB_PRUNE_BATCH_ROWS": 1,
        "LOG_DIR": "",
        "LOG_TO_CONSOLE": False,
    }
    worker = threading.Thread(
        target=db_persistence_worker,
        args=(db_queue, status_queue, config, shutdown),
    )
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert observed == [1]


def test_worker_persists_durable_web_observation(tmp_path, monkeypatch):
    db_path = tmp_path / "ledger.db"
    db_queue = queue.Queue()
    status_queue = queue.Queue()
    shutdown = threading.Event()
    observed = []

    def inspect_after_write(conn, **_kwargs):
        rows = conn.execute(
            "SELECT flow_id, label FROM web_observations ORDER BY timestamp"
        ).fetchall()
        if rows:
            observed.extend(rows)
            shutdown.set()
        return 0, False

    monkeypatch.setattr(netwatch_db, "prune_network_events", inspect_after_write)
    db_queue.put(make_message("DOD_CORE", "DB_BATCH", "DB_WORKER", {
        "rows": [],
        "observations": [[
            "flow-1", 10.0, "10.0.0.2", "8.8.8.8", "src", "dst",
            "TCP", 443, "example.com", "HUMAN LIKELY", 7,
            "new destination", "WIN", "US", 517,
        ]],
    }))
    config = {
        "DB_NAME": str(db_path),
        "SPOOL_PATH": str(tmp_path / "spool.db"),
        "DB_RETENTION_DAYS": 0,
        "DB_MAX_ROWS": 0,
        "WEB_OBSERVATION_MAX_ROWS": 100,
        "DB_PRUNE_INTERVAL_SEC": 0,
        "DB_PRUNE_BATCH_ROWS": 10,
        "LOG_DIR": "",
        "LOG_TO_CONSOLE": False,
    }
    worker = threading.Thread(
        target=db_persistence_worker,
        args=(db_queue, status_queue, config, shutdown),
    )
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert observed == [("flow-1", "HUMAN LIKELY")]


def test_row_ceiling_keeps_the_newest_rowids_without_counting(tmp_path):
    """A COUNT(*) took 10 s at 17M rows on Sensor1, the whole persistence heartbeat timeout."""
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    try:
        conn.execute("CREATE TABLE network_events (timestamp REAL)")
        conn.executemany("INSERT INTO network_events (timestamp) VALUES (?)", [(float(i),) for i in range(20)])
        conn.execute("DELETE FROM network_events WHERE timestamp IN (3, 4, 5)")  # rowids 4-6 gone: newest 20, rows 17
        seen = []
        conn.set_trace_callback(seen.append)
        assert prune_network_events(conn, now=20, retention_days=0, max_rows=100, batch_rows=5) == (0, False)
        # Keeps rowids 6..20: 14 rows, one under the ceiling, because of the holes.
        assert prune_network_events(conn, now=20, retention_days=0, max_rows=15, batch_rows=5) == (3, False)
        assert prune_network_events(conn, now=20, retention_days=0, max_rows=15, batch_rows=5) == (0, False)
        assert prune_network_events(conn, now=20, retention_days=0, max_rows=12, batch_rows=2) == (2, True)
        assert not any("COUNT(*)" in sql for sql in seen)
        assert [r[0] for r in conn.execute("SELECT rowid FROM network_events ORDER BY rowid LIMIT 1")] == [9]
    finally:
        conn.close()


def test_ledger_wal_is_checkpointed_beside_the_loop(tmp_path, monkeypatch):
    """The writer never checkpoints inside COMMIT; a side thread moves frames into the ledger file."""
    import shutil
    import time

    db_path = tmp_path / "ledger.db"
    db_queue = queue.Queue()
    shutdown = threading.Event()
    seen = {}

    def inspect(conn, **_kwargs):
        if conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]:
            seen["autocheckpoint"] = conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and "rows" not in seen:
                shutil.copyfile(db_path, tmp_path / "main-only.db")  # the main file alone, no WAL
                copy = sqlite3.connect(tmp_path / "main-only.db")
                if copy.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='network_events'").fetchone()[0]:
                    if copy.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]:
                        seen["rows"] = True
                copy.close()
                time.sleep(0.02)
            shutdown.set()
        return 0, False

    monkeypatch.setattr(netwatch_db, "prune_network_events", inspect)
    monkeypatch.setattr(netwatch_db, "LEDGER_CHECKPOINT_SEC", 0.05)
    db_queue.put(make_message("DOD_CORE", "DB_BATCH", "DB_WORKER", {"rows": [event_row("e1", 10.0)]}))
    config = {"DB_NAME": str(db_path), "DB_RETENTION_DAYS": 0, "DB_MAX_ROWS": 0, "DB_PRUNE_INTERVAL_SEC": 0,
              "SPOOL_PATH": str(tmp_path / "spool.db"), "LOG_DIR": "", "LOG_TO_CONSOLE": False}
    worker = threading.Thread(target=db_persistence_worker, args=(db_queue, queue.Queue(), config, shutdown))
    worker.start()
    worker.join(timeout=10)

    assert not worker.is_alive()
    assert seen == {"autocheckpoint": 0, "rows": True}
