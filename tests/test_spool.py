"""Tests for durable telemetry spool under failures, corruptions, and restarts."""

import sqlite3

import pytest

from netwatch_core import make_db_batch_message
from netwatch_db import (
    EVENT_INSERT_SQL,
    db_persistence_worker,
    ledger_event_rows,
)
from netwatch_spool import TelemetrySpool


def _sample_rows(count, start_id=0, start_ts=1000.0):
    rows = []
    for i in range(count):
        uid = f"evt-{start_id + i}"
        ts = start_ts + i
        # 20-field row matching compact_event_rows / schema
        rows.append((
            uid, ts, "00:11:22:33:44:55", "66:77:88:99:aa:bb",
            "192.168.1.10", "1.1.1.1", "TCP", 443,
            "S", 64, 1500, "example.com", "US", 1,
            54321, "null", "sensor-1", "eth0", 2, "{}",
        ))
    return rows


def test_spool_basic_enqueue_and_ack(tmp_path):
    spool_file = tmp_path / "spool.db"
    spool = TelemetrySpool(str(spool_file))

    rows = _sample_rows(5)
    accepted, reason, gap = spool.enqueue_batch("b-1", rows, [])
    assert accepted is True
    assert reason == "spooled"
    assert gap is None

    counts = spool.count_pending()
    assert counts["batches"] == 1
    assert counts["rows"] == 5

    batch_id, fetched_rows, fetched_obs, corrupt_gap = spool.fetch_pending_batch()
    assert batch_id == "b-1"
    assert len(fetched_rows) == 5
    assert corrupt_gap is None

    spool.acknowledge_batch(batch_id)
    counts = spool.count_pending()
    assert counts["batches"] == 0
    assert counts["rows"] == 0

    spool.close()


def test_spool_full_refuses_admission_and_records_gap(tmp_path):
    spool_file = tmp_path / "spool.db"
    # Set a tiny spool limit: 1 MB is min, so we fill it or test ceiling logic
    spool = TelemetrySpool(str(spool_file), max_bytes=1024 * 1024)

    rows1 = _sample_rows(2)
    accepted1, _, _ = spool.enqueue_batch("b-1", rows1, [])
    assert accepted1 is True

    rows2 = _sample_rows(10)
    rows2[0] = (*rows2[0][:-1], 'x' * spool.max_bytes)
    accepted2, reason2, gap2 = spool.enqueue_batch("b-2", rows2, [])
    assert accepted2 is False
    assert reason2 == "spool_full"
    assert gap2 is not None
    assert gap2["dropped_rows"] == 10

    # Drain gaps
    gaps = spool.drain_unacknowledged_gaps()
    assert len(gaps) == 1
    assert gaps[0]["reason"] == "spool_full"
    assert gaps[0]["dropped_rows"] == 10

    spool.close()


def test_spool_detects_corrupt_tail_records_gap_and_replays_rest(tmp_path):
    spool_file = tmp_path / "spool.db"
    spool = TelemetrySpool(str(spool_file))

    rows1 = _sample_rows(3, start_id=1)
    rows2 = _sample_rows(3, start_id=4)
    spool.enqueue_batch("b-corrupt", rows1, [])
    spool.enqueue_batch("b-valid", rows2, [])

    # Tamper with the first batch in sqlite to simulate corruption
    conn = sqlite3.connect(str(spool_file))
    conn.execute(
        "UPDATE spool_batches SET payload_json = 'corrupted-json-data' WHERE batch_id = 'b-corrupt'"
    )
    conn.commit()
    conn.close()

    # Fetching pending batch should detect corruption, skip it, record gap, and return next valid batch
    batch_id, fetched_rows, fetched_obs, corrupt_gap = spool.fetch_pending_batch()
    assert corrupt_gap is not None
    assert corrupt_gap["batch_id"] == "b-corrupt"
    assert corrupt_gap["dropped_rows"] == 3
    assert batch_id == "b-valid"
    assert len(fetched_rows) == 3

    spool.acknowledge_batch(batch_id)
    assert spool.count_pending()["batches"] == 0

    gaps = spool.drain_unacknowledged_gaps()
    assert any("corrupt_batch" in g["reason"] for g in gaps)

    spool.close()


def test_ledger_failure_spools_and_recovers_idempotently(tmp_path):
    """Simulate ledger failure, verify rows remain spooled, then recover ledger and land rows."""
    db_file = tmp_path / "ledger.db"
    spool_file = tmp_path / "spool.db"
    spool = TelemetrySpool(str(spool_file))
    rows = _sample_rows(10)
    spool.enqueue_batch("b-1", rows, [])
    spool.close()

    # Create ledger connection
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE network_events (
            uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, mac_dst TEXT,
            src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
            tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER, sni_domain TEXT,
            country TEXT DEFAULT '--', packet_count INTEGER NOT NULL DEFAULT 1,
            source_port INTEGER, vlan_ids TEXT, sensor_id TEXT, capture_interface TEXT,
            event_version INTEGER, packet_metadata TEXT, community_id TEXT
        )
    """)
    conn.close()

    # Re-open spool and replay
    spool2 = TelemetrySpool(str(spool_file))
    batch_id, fetched_rows, _, _ = spool2.fetch_pending_batch()
    assert batch_id == "b-1"

    # Insert into ledger
    conn = sqlite3.connect(str(db_file))
    conn.executemany(EVENT_INSERT_SQL, ledger_event_rows(fetched_rows))
    conn.commit()

    # Acknowledge in spool
    spool2.acknowledge_batch(batch_id)
    assert spool2.count_pending()["batches"] == 0

    # Verify rows in ledger
    cur = conn.execute("SELECT COUNT(*) FROM network_events")
    assert cur.fetchone()[0] == 10
    conn.close()
    spool2.close()


def test_writer_crash_replays_idempotently_without_duplicates(tmp_path):
    """Simulate writer crash after ledger write but before spool ack."""
    db_file = tmp_path / "ledger.db"
    spool_file = tmp_path / "spool.db"

    spool = TelemetrySpool(str(spool_file))
    rows = _sample_rows(5)
    spool.enqueue_batch("b-1", rows, [])

    # Setup ledger
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE network_events (
            uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, mac_dst TEXT,
            src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
            tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER, sni_domain TEXT,
            country TEXT DEFAULT '--', packet_count INTEGER NOT NULL DEFAULT 1,
            source_port INTEGER, vlan_ids TEXT, sensor_id TEXT, capture_interface TEXT,
            event_version INTEGER, packet_metadata TEXT, community_id TEXT
        )
    """)

    # First write attempt: writes to ledger, but process "dies" before acknowledging spool
    b_id, r, _, _ = spool.fetch_pending_batch()
    conn.executemany(EVENT_INSERT_SQL, ledger_event_rows(r))
    conn.commit()

    # Spool is NOT acknowledged here (simulating crash)
    spool.close()

    # On restart, fetch pending batch again and write to ledger (INSERT OR IGNORE)
    spool_restart = TelemetrySpool(str(spool_file))
    b_id2, r2, _, _ = spool_restart.fetch_pending_batch()
    assert b_id2 == "b-1"
    conn.executemany(EVENT_INSERT_SQL, ledger_event_rows(r2))
    conn.commit()
    spool_restart.acknowledge_batch(b_id2)

    # Exactly 5 rows land; no duplicate primary keys or extra rows
    cur = conn.execute("SELECT COUNT(*) FROM network_events")
    assert cur.fetchone()[0] == 5

    conn.close()
    spool_restart.close()


def test_shutdown_with_failing_ledger_preserves_spool(tmp_path):
    """If ledger is inaccessible during shutdown, batches stay safely spooled."""
    import queue
    import threading

    db_file = tmp_path / "unwritable" / "ledger.db"  # directory does not exist / uncreatable
    spool_file = tmp_path / "spool.db"

    config = {
        "DB_NAME": str(db_file),
        "SPOOL_PATH": str(spool_file),
        "SPOOL_RETRY_INTERVAL_SEC": 0.05,
        "LOG_DIR": str(tmp_path),
    }

    db_q = queue.Queue()
    status_q = queue.Queue()
    shutdown_ev = threading.Event()

    # Put a batch into queue
    rows = _sample_rows(4)
    db_q.put(make_db_batch_message(rows, []))

    # Signal shutdown immediately
    shutdown_ev.set()

    # Run persistence worker
    db_persistence_worker(db_q, status_q, config, shutdown_event=shutdown_ev)

    # Verify spool preserved the batch
    spool = TelemetrySpool(str(spool_file))
    counts = spool.count_pending()
    assert counts["batches"] >= 1
    assert counts["rows"] == 4
    spool.close()


def test_capacity_recovers_after_drain(tmp_path):
    spool = TelemetrySpool(str(tmp_path / 'spool.db'), max_bytes=2 * 1024 * 1024)
    rows = _sample_rows(1)
    rows[0] = (*rows[0][:-1], 'x' * 300_000)
    for i in range(20):
        accepted, _, _ = spool.enqueue_batch(str(i), rows, [])
        if not accepted:
            break
    while spool.count_pending()['batches']:
        spool.acknowledge_batch(spool.fetch_pending_batch()[0])
    assert spool.enqueue_batch('again', rows, [])[0]
    assert spool.get_disk_usage() <= spool.max_bytes
    spool.close()


def test_gap_emit_does_not_erase_durable_record(tmp_path):
    path = str(tmp_path / 'spool.db')
    spool = TelemetrySpool(path)
    spool.max_bytes = 1
    spool.enqueue_batch('lost', _sample_rows(2), [])
    assert spool.drain_unacknowledged_gaps()
    spool.close()
    spool = TelemetrySpool(path)
    assert spool.drain_unacknowledged_gaps()[0]['dropped_rows'] == 2
    spool.close()


def test_spool_uses_full_sync(tmp_path):
    spool = TelemetrySpool(str(tmp_path / 'spool.db'))
    assert spool.get_connection().execute('PRAGMA synchronous').fetchone()[0] == 2
    spool.close()


def _run_backlog(tmp_path, count, poison=False, active=False):
    import queue
    import threading

    path = str(tmp_path / 'spool.db')
    spool = TelemetrySpool(path)
    if poison:
        spool.enqueue_batch('bad', [({'bad': 1}, *[None] * 12, 1, *[None] * 6)], [])  # unbindable: rejected
    for i in range(count):
        spool.enqueue_batch(str(i), _sample_rows(1, start_id=i), [])
    spool.close()
    stop = threading.Event()

    class Inbox(queue.Queue):
        calls = 0

        def get(self, *args, **kwargs):
            self.calls += 1
            if active and self.calls == 2:
                check = TelemetrySpool(path)
                pending = check.count_pending()['batches']
                check.close()
                stop.set()
                # Replay is time-boxed per iteration; slow fsync (Windows) may leave a tail.
                assert pending <= count - 2
            raise queue.Empty

    inbox = Inbox()
    if not active:
        stop.set()
    ledger = str(tmp_path / 'ledger.db')
    db_persistence_worker(inbox, queue.Queue(maxsize=1), {
        'DB_NAME': ledger, 'SPOOL_PATH': path, 'LOG_DIR': str(tmp_path),
    }, shutdown_event=stop)
    with sqlite3.connect(ledger) as conn:
        assert conn.execute('SELECT COUNT(*) FROM network_events').fetchone()[0] == count
    return path


def test_poison_batch_is_quarantined_and_replay_continues(tmp_path):
    path = _run_backlog(tmp_path, 2, poison=True)
    spool = TelemetrySpool(path)
    assert spool.get_connection().execute(
        "SELECT state FROM spool_batches WHERE batch_id='bad'"
    ).fetchone()[0] == 'rejected'
    assert any(g['reason'].startswith('rejected_batch:') and g['dropped_rows'] == 1
               for g in spool.drain_unacknowledged_gaps())
    spool.close()


def test_shutdown_drains_more_than_five_batches(tmp_path):
    _run_backlog(tmp_path, 12)


def test_active_replay_drains_multiple_batches_per_iteration(tmp_path):
    _run_backlog(tmp_path, 12, active=True)


def test_disk_bound_and_gap_counts_through_repeated_outages(tmp_path):
    spool = TelemetrySpool(str(tmp_path / 'spool.db'), max_bytes=2 * 1024 * 1024)
    rows = _sample_rows(1)
    rows[0] = (*rows[0][:-1], 'x' * 300_000)
    lost = 0
    for cycle in range(3):
        for i in range(30):
            accepted, _, _ = spool.enqueue_batch(f'{cycle}-{i}', rows, [])
            lost += not accepted
            assert spool.get_disk_usage() <= spool.max_bytes
        while spool.count_pending()['batches']:
            spool.acknowledge_batch(spool.fetch_pending_batch()[0])
        assert spool.enqueue_batch(f'recovered-{cycle}', _sample_rows(1), [])[0]
        spool.acknowledge_batch(f'recovered-{cycle}')
    assert sum(g['dropped_rows'] for g in spool.drain_unacknowledged_gaps()) == lost
    spool.close()


def test_gap_transfer_commit_before_mark_restarts_without_duplicates(tmp_path, monkeypatch):
    import pytest

    from netwatch_security_store import DurableIncidentStore

    path = str(tmp_path / 'spool.db')
    store_path = str(tmp_path / 'security.db')
    spool = TelemetrySpool(path)
    store = DurableIncidentStore(store_path)
    spool._record_admission_refusal(100, 7, 2, 0, spool.max_bytes)
    def crash(gap):
        raise RuntimeError('simulated crash after commit')
    monkeypatch.setattr(spool, 'mark_gap_transferred', crash)
    with pytest.raises(RuntimeError):
        spool.transfer_gaps(store)
    assert len(store.spool_gaps()) == 1
    spool.close()
    store.close()
    spool = TelemetrySpool(path)
    store = DurableIncidentStore(store_path)
    spool.transfer_gaps(store)
    spool.transfer_gaps(store)
    assert len(store.spool_gaps()) == 1
    assert store.spool_gaps()[0]['dropped_rows'] == 7
    assert spool.get_connection().execute('SELECT transferred_batches FROM spool_gaps').fetchone()[0] == 1
    spool._record_admission_refusal(200, 3, 4, 0, spool.max_bytes)
    spool.transfer_gaps(store)
    assert len(store.spool_gaps()) == 1
    assert store.spool_gaps()[0]['dropped_rows'] == 10
    health = store.source_health('SPOOL:' + spool.identity)
    assert (health['refused_batches'], health['dropped_rows'], health['dropped_observations']) == (2, 10, 6)
    spool.close()
    store.close()


def test_failed_security_commit_does_not_mark_spool(tmp_path, monkeypatch):
    import pytest

    from netwatch_security_store import DurableIncidentStore

    spool = TelemetrySpool(str(tmp_path / 'spool.db'))
    store = DurableIncidentStore(str(tmp_path / 'security.db'))
    spool._record_admission_refusal(100, 1, 0, 0, spool.max_bytes)
    def fail(*args):
        raise sqlite3.OperationalError('simulated unavailable store')
    monkeypatch.setattr(store, '_add', fail)
    with pytest.raises(sqlite3.OperationalError):
        spool.transfer_gaps(store)
    assert spool.get_connection().execute('SELECT transferred_batches FROM spool_gaps').fetchone()[0] == 0
    assert store.spool_gaps() == []
    spool.close()
    store.close()


def test_desktop_worker_transfers_losses_without_supervisor(tmp_path):
    import queue
    import threading

    from netwatch_security_store import DurableIncidentStore

    path = str(tmp_path / 'spool.db')
    spool = TelemetrySpool(path)
    spool._record_admission_refusal(100, 5, 3, 0, spool.max_bytes)
    spool.enqueue_batch('corrupt', _sample_rows(2), [])
    spool.get_connection().execute("UPDATE spool_batches SET payload_json='broken'")
    spool.fetch_pending_batch()
    spool.enqueue_batch('rejected', _sample_rows(4), [])
    spool.reject_batch('rejected', 'bad data')
    spool.enqueue_batch('pending', _sample_rows(1), [])
    spool.close()
    config = {'DB_NAME': str(tmp_path / 'missing' / 'ledger.db'),
              'INCIDENT_DB': str(tmp_path / 'security.db'), 'SPOOL_PATH': path,
              'LOG_DIR': str(tmp_path), 'LOG_TO_CONSOLE': False}
    stop = threading.Event()
    stop.set()
    for _ in range(2):
        db_persistence_worker(queue.Queue(), queue.Queue(maxsize=1), config, stop)
    store = DurableIncidentStore(config['INCIDENT_DB'])
    gaps = store.spool_gaps()
    assert len(gaps) == 3
    assert sum(g['dropped_rows'] for g in gaps) == 11
    health = store.source_health('SPOOL:' + spool.identity)
    assert (health['refused_batches'], health['corrupt_batches'], health['rejected_batches']) == (1, 1, 1)
    assert health['pending_batches'] == 1 and health['pending_bytes'] > 0
    assert health['limit_bytes'] == spool.max_bytes
    store.close()


def test_legacy_gap_upgrade_preserves_exact_loss_and_unknown_refusals(tmp_path):
    from netwatch_security_store import DurableIncidentStore

    path = str(tmp_path / 'spool.db')
    with sqlite3.connect(path) as conn:
        conn.execute('''CREATE TABLE spool_gaps (
            gap_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, reason TEXT NOT NULL,
            dropped_rows INTEGER NOT NULL, dropped_observations INTEGER NOT NULL,
            spool_bytes INTEGER NOT NULL, limit_bytes INTEGER NOT NULL)''')
        conn.execute("INSERT INTO spool_gaps VALUES ('spool_full', 100, 'spool_full', 123, 45, 0, 1000000)")
    spool = TelemetrySpool(path)
    store = DurableIncidentStore(str(tmp_path / 'security.db'))
    spool.transfer_gaps(store)
    spool._record_admission_refusal(200, 7, 3, 0, spool.max_bytes)
    spool.transfer_gaps(store)
    spool.close()
    spool = TelemetrySpool(path)
    spool.transfer_gaps(store)
    assert len(store.spool_gaps()) == 1
    gap = store.spool_gaps()[0]
    assert (gap['dropped_rows'], gap['dropped_observations']) == (130, 48)
    assert gap['loss_batches'] is None and gap['batch_count_exact'] == 0
    assert store.source_health('SPOOL:' + spool.identity)['refused_batches'] is None
    spool.close()
    store.close()


def test_new_loss_between_commit_and_mark_is_not_acknowledged(tmp_path, monkeypatch):
    from netwatch_security_store import DurableIncidentStore

    spool = TelemetrySpool(str(tmp_path / 'spool.db'))
    store = DurableIncidentStore(str(tmp_path / 'security.db'))
    spool._record_admission_refusal(100, 3, 1, 0, spool.max_bytes)
    original = spool.mark_gap_transferred
    def new_loss(gap):
        spool._record_admission_refusal(200, 4, 2, 0, spool.max_bytes)
        original(gap)
    monkeypatch.setattr(spool, 'mark_gap_transferred', new_loss)
    spool.transfer_gaps(store)
    assert spool.get_connection().execute('SELECT transferred_batches FROM spool_gaps').fetchone()[0] == 0
    monkeypatch.setattr(spool, 'mark_gap_transferred', original)
    spool.transfer_gaps(store)
    assert len(store.spool_gaps()) == 1
    assert store.spool_gaps()[0]['dropped_rows'] == 7
    spool.close()
    store.close()


def _scripted_worker(tmp_path, batches, stop_when=None):
    """Run the persistence worker in-process; stop once the inbox is empty and ``stop_when()``."""
    import queue
    import threading

    stop = threading.Event()
    if stop_when is None:
        stop.set()

    class Inbox(queue.Queue):
        def get(self, *args, **kwargs):
            if self.empty() and stop_when():
                stop.set()
            return super().get(*args, **kwargs)

    inbox = Inbox()
    for rows in batches:
        inbox.put(make_db_batch_message(rows, []))
    config = {'DB_NAME': str(tmp_path / 'ledger.db'), 'SPOOL_PATH': str(tmp_path / 'spool.db'),
              'LOG_DIR': str(tmp_path), 'LOG_TO_CONSOLE': False, 'SPOOL_RETRY_INTERVAL_SEC': 0.01,
              'INCIDENT_DB': str(tmp_path / 'security.db')}
    db_persistence_worker(inbox, queue.Queue(maxsize=1), config, shutdown_event=stop)
    return config


def _fail_first(monkeypatch, name, count):
    """Inject storage errors into one spool operation (disk I/O error, then recovery)."""
    original = getattr(TelemetrySpool, name)
    left = [count]

    def flaky(self, *args, **kwargs):
        if left[0]:
            left[0] -= 1
            raise sqlite3.OperationalError('disk I/O error')
        return original(self, *args, **kwargs)
    monkeypatch.setattr(TelemetrySpool, name, flaky)
    return left


def _ledger_totals(config):
    with sqlite3.connect(config['DB_NAME']) as conn:
        return conn.execute('SELECT COUNT(*), SUM(packet_count) FROM network_events').fetchone()


def _assert_spool_settled(config):
    spool = TelemetrySpool(config['SPOOL_PATH'])
    assert spool.count_pending()['batches'] == 0 and spool.drain_unacknowledged_gaps() == []
    spool.close()


def test_spool_admission_failure_holds_the_dequeued_batch_until_admitted(tmp_path, monkeypatch):
    left = _fail_first(monkeypatch, 'enqueue_batch', 3)
    config = _scripted_worker(tmp_path, [_sample_rows(4), _sample_rows(3, start_id=10)],
                              stop_when=lambda: not left[0])
    assert _ledger_totals(config) == (7, 7)
    _assert_spool_settled(config)


def test_spool_ack_failure_after_ledger_commit_replays_without_duplicates(tmp_path, monkeypatch):
    left = _fail_first(monkeypatch, 'acknowledge_batch', 2)
    config = _scripted_worker(tmp_path, [_sample_rows(5)], stop_when=lambda: not left[0])
    assert _ledger_totals(config) == (5, 5)
    _assert_spool_settled(config)


def test_spool_status_failure_does_not_kill_the_worker(tmp_path, monkeypatch):
    left = _fail_first(monkeypatch, 'count_pending', 2)
    config = _scripted_worker(tmp_path, [_sample_rows(2)], stop_when=lambda: not left[0])
    assert _ledger_totals(config) == (2, 2)
    _assert_spool_settled(config)


def test_unadmittable_batch_at_shutdown_fails_the_drain_loudly(tmp_path, monkeypatch):
    import pytest

    _fail_first(monkeypatch, 'enqueue_batch', 10**6)
    # A clean return would let the runtime report an ordered drain that lost a batch.
    with pytest.raises(sqlite3.OperationalError):
        _scripted_worker(tmp_path, [_sample_rows(2)])


def test_close_closes_connection_and_logs_when_compaction_fails(tmp_path, monkeypatch):
    import logging

    spool = TelemetrySpool(str(tmp_path / "spool.db"))
    c = spool.get_connection()

    def boom():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(spool, "_compact", boom)
    records = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    lg = logging.getLogger("netwatch.db")
    h = _H(level=logging.WARNING)
    lg.addHandler(h)
    try:
        spool.close()
    finally:
        lg.removeHandler(h)

    with pytest.raises(sqlite3.ProgrammingError):
        c.execute("SELECT 1")
    assert any("spool compaction at close failed" in m for m in records)
    assert spool._conn is None


def test_close_never_raises_when_conn_close_fails(tmp_path):
    spool = TelemetrySpool(str(tmp_path / "spool.db"))

    class _Conn:
        def close(self):
            raise sqlite3.OperationalError("close failed")

    spool._conn = _Conn()
    spool._compact = lambda: None
    spool.close()
    assert spool._conn is None
