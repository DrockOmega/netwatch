"""SQLite ledger persistence and bounded maintenance."""

import json
import operator
import os
import queue
import sqlite3
import struct
import threading
import time
import traceback

from netwatch_core import DISK_MIN_FREE_BYTES, community_id_v1, is_message_payload, make_message, try_put_drop_oldest
from netwatch_log import setup_logging

EVENT_INSERT_SQL = (
    "INSERT OR IGNORE INTO network_events "
    "(uuid, timestamp, mac_src, mac_dst, src_ip, dst_ip, protocol, port, "
    " tcp_flags, ttl, size_bytes, sni_domain, country, packet_count, source_port, "
    " vlan_ids, sensor_id, capture_interface, event_version, packet_metadata, community_id) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

WEB_OBSERVATION_INSERT_SQL = (
    "INSERT OR IGNORE INTO web_observations "
    "(flow_id, timestamp, src_ip, dst_ip, mac_src, mac_dst, protocol, port, "
    " domain, label, score, reason, os_guess, country, size_bytes) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

LEDGER_CHECKPOINT_SEC = 5.0
LEDGER_WAL_ESCALATE = 4  # x DB_WAL_MAX_BYTES: past it a PASSIVE checkpoint alone no longer bounds the WAL
# live VM: 1000-row batches held the writer lock up to 9 s; 128 fell behind the sensor's ~43k SURICATA
# records/hour (2026-10-13: 21k/h pruned, store at 2.3 GB against a 1 GiB target).
NATIVE_PRUNE_BATCH = 512

_TCP_FLAG_ORDER = "FSRPAUECN"
EVENT_METADATA_COLUMNS = (
    "source_port", "vlan_ids", "sensor_id", "capture_interface",
    "event_version", "packet_metadata", "community_id",
)


_ROW_METADATA_KEYS = ("ip_protocol", "fragmented", "non_initial_fragment", "icmp_type", "icmp_code", "tls_enrichment")
_ROW_METADATA_VALUES = operator.itemgetter(*_ROW_METADATA_KEYS)


def packet_row_key(event):
    """The six identity fields of a version-2 row as cheap hashable values.

    The core builds one per packet and ``encode_packet_rows`` turns them into ledger text after
    compaction, so the JSON is written once per one-second flow row, not once per packet.
    """
    vlan_ids = event.get("vlan_ids")
    try:
        metadata = _ROW_METADATA_VALUES(event)  # parser events carry every key
    except KeyError:
        metadata = json.dumps({key: event[key] for key in _ROW_METADATA_KEYS if key in event},
                              sort_keys=True, separators=(",", ":"))
    return (
        event.get("source_port"),
        tuple(vlan_ids) if type(vlan_ids) is list else json.dumps(vlan_ids, separators=(",", ":")),
        str(event.get("sensor_id") or "unknown"),
        str(event.get("interface") or "unknown"), 2,
        metadata,
    )


def encode_packet_rows(rows):
    """Ledger text for rows whose fields 15 and 19 still hold ``packet_row_key`` values."""
    encoded = []
    for row in rows:
        vlan, metadata = row[15], row[19]
        if type(vlan) is tuple:
            vlan = json.dumps(list(vlan), separators=(",", ":"))
        if type(metadata) is tuple:
            metadata = json.dumps(dict(zip(_ROW_METADATA_KEYS, metadata, strict=True)), sort_keys=True, separators=(",", ":"))
        encoded.append((*row[:15], vlan, *row[16:19], metadata))
    return encoded


def packet_row_metadata(event):
    """Append versioned capture identity; absent legacy fields remain unknown."""
    return encode_packet_rows([(None,) * 14 + packet_row_key(event)])[0][14:]


def row_community_id(row):
    """Community ID of a version-2 ledger row whose endpoints and ports/type-code are known."""
    if len(row) != 20 or row[18] != 2:
        return None
    try:
        metadata = json.loads(row[19])
        proto = metadata.get("ip_protocol")
        if metadata.get("non_initial_fragment") is not False:
            return None
        if proto in (6, 17):
            ports = (row[14], row[7])
        elif proto in (1, 58):
            ports = (metadata.get("icmp_type"), metadata.get("icmp_code"))
        else:
            return None
        if None in ports:
            return None
        return community_id_v1(proto, row[4], ports[0], row[5], ports[1])
    except (TypeError, ValueError, AttributeError, OverflowError, struct.error):
        return None


def ledger_event_rows(rows):
    """Append the derived Community ID at insert time, so older spooled rows replay too."""
    return [(*row, row_community_id(row)) for row in rows]


def compact_event_rows(rows):
    """Collapse packet rows into one-second directional flow summaries.

    Detection still sees every packet before this boundary.  The ledger keeps the
    packet and byte totals needed by history without paying one SQLite row and one
    IPC serialization per frame.
    """
    compacted = {}
    for raw in rows or ():
        row = list(raw)
        if len(row) != 20:
            raise ValueError(f"network event row has {len(row)} fields; expected 20")
        packet_count = max(1, int(row[13]))
        second = int(float(row[1]))
        key = (second, *row[2:8], row[11], row[12], *row[14:])
        current = compacted.get(key)
        if current is None:
            row[1] = float(second)
            row[13] = packet_count
            compacted[key] = row
            continue
        flags = f"{current[8]}{row[8]}"
        merged_flags = "".join(flag for flag in _TCP_FLAG_ORDER if flag in flags)
        current[8] = merged_flags or current[8] or row[8]
        current[10] = int(current[10]) + int(row[10])
        current[13] = int(current[13]) + packet_count
    return [tuple(row) for row in compacted.values()]


def normalize_web_observation_rows(rows):
    """Validate durable session rows before they cross the SQLite boundary."""
    normalized = []
    for raw in rows or ():
        if not isinstance(raw, list | tuple) or len(raw) != 15:
            continue
        row = list(raw)
        try:
            row[0] = str(row[0]).strip()
            row[1] = float(row[1])
            row[7] = int(row[7])
            row[10] = int(row[10])
            row[14] = int(row[14])
        except (TypeError, ValueError, OverflowError):
            continue
        if not row[0]:
            continue
        for index in (2, 3, 4, 5, 6, 8, 9, 11, 12, 13):
            row[index] = str(row[index] or "")
        normalized.append(tuple(row))
    return normalized


def ensure_network_event_columns(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(network_events)")}
    additions = {
        "packet_count": "INTEGER NOT NULL DEFAULT 1",
        "source_port": "INTEGER",
        "vlan_ids": "TEXT NOT NULL DEFAULT 'null'",
        "sensor_id": "TEXT NOT NULL DEFAULT 'unknown'",
        "capture_interface": "TEXT NOT NULL DEFAULT 'unknown'",
        "event_version": "INTEGER NOT NULL DEFAULT 1",
        "packet_metadata": "TEXT NOT NULL DEFAULT '{}'",
        "community_id": "TEXT",
    }
    conn.execute("SAVEPOINT event_schema")
    try:
        for name, declaration in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE network_events ADD COLUMN {name} {declaration}")
        conn.execute("RELEASE event_schema")
    except Exception:
        conn.execute("ROLLBACK TO event_schema")
        conn.execute("RELEASE event_schema")
        raise


def checkpoint_ledger(conn, wal_path, wal_max_bytes):
    """PASSIVE never blocks the writer, but under a sustained write rate it never ends with the whole
    WAL copied before the next commit, so the WAL never rewinds and grows until the disk is full
    (stress run 2026-10-12: 2.1 GB in 70 s at ~8.5k rows/s). Past the bound, TRUNCATE: the writer waits
    up to its busy timeout, and a batch that still loses the lock stays in the spool. True if truncated."""
    conn.execute("PRAGMA wal_checkpoint(PASSIVE);").fetchone()
    try:
        size = os.path.getsize(wal_path)
    except OSError:
        return False
    if not wal_max_bytes or size <= LEDGER_WAL_ESCALATE * wal_max_bytes:
        return False
    conn.execute("PRAGMA busy_timeout=2000;")
    try:
        return not conn.execute("PRAGMA wal_checkpoint(TRUNCATE);").fetchone()[0]
    finally:
        conn.execute("PRAGMA busy_timeout=0;")


def configure_connection(conn, wal_max_bytes):
    """Apply the live-writer durability and bounded-WAL policy."""
    try:
        wal_max_bytes = max(0, int(wal_max_bytes))
    except (TypeError, ValueError, OverflowError):
        wal_max_bytes = 67_108_864
    mode_row = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
    mode = str(mode_row[0]).lower() if mode_row else ""
    if mode != "wal":
        raise sqlite3.OperationalError(f"WAL activation failed; journal mode is {mode or 'unknown'}")
    conn.execute("PRAGMA synchronous=FULL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute(f"PRAGMA journal_size_limit={wal_max_bytes};")
    return wal_max_bytes


def prune_network_events(conn, *, now, retention_days, max_rows, batch_rows):
    """Delete one bounded batch: expired rows first, otherwise rows over the ceiling.

    The live writer uses autocommit, so the batch releases the write lock and the
    worker alternates maintenance with queued telemetry instead of starving ingestion.
    Returns ``(removed, more_pending)``.
    """
    batch_rows = max(1, int(batch_rows))
    if retention_days > 0:
        cutoff = float(now) - float(retention_days) * 86400.0
        count = conn.execute(
            "DELETE FROM network_events WHERE rowid IN ("
            " SELECT rowid FROM network_events WHERE timestamp < ?"
            " ORDER BY timestamp ASC, rowid ASC LIMIT ?"
            ")",
            (cutoff, batch_rows),
        ).rowcount or 0
        if count > 0:
            # A full age batch may leave more; the ceiling is checked on the next call.
            return count, count == batch_rows or max_rows > 0

    if max_rows > 0:
        # The ceiling keeps the newest max_rows rowids: two index seeks, where a COUNT(*) took
        # 10 s at 17M rows on the sensor (2026-10-12), as long as the persistence heartbeat timeout.
        # shortcut: rowid holes left by age deletes make it keep slightly fewer than max_rows;
        # exact only if out-of-order timestamps ever leave large holes.
        newest = conn.execute("SELECT MAX(rowid) FROM network_events").fetchone()[0]
        if newest is not None and newest > max_rows:
            count = conn.execute(
                "DELETE FROM network_events WHERE rowid IN ("
                " SELECT rowid FROM network_events WHERE rowid <= ? ORDER BY rowid LIMIT ?"
                ")",
                (newest - int(max_rows), batch_rows),
            ).rowcount or 0
            return count, count == batch_rows

    return 0, False


def prune_web_observations(conn, *, now, retention_days, max_rows, batch_rows):
    """Apply the observation ledger's age and row ceilings in bounded commits."""
    removed = 0
    batch_rows = max(1, int(batch_rows))
    if retention_days > 0:
        cutoff = float(now) - float(retention_days) * 86400.0
        removed += conn.execute(
            "DELETE FROM web_observations WHERE rowid IN ("
            " SELECT rowid FROM web_observations WHERE timestamp < ?"
            " ORDER BY timestamp ASC, rowid ASC LIMIT ?)",
            (cutoff, batch_rows),
        ).rowcount or 0
    total = conn.execute("SELECT COUNT(*) FROM web_observations").fetchone()[0]
    excess = max(0, int(total) - max(0, int(max_rows))) if max_rows > 0 else 0
    if excess:
        removed += conn.execute(
            "DELETE FROM web_observations WHERE rowid IN ("
            " SELECT rowid FROM web_observations"
            " ORDER BY timestamp ASC, rowid ASC LIMIT ?)",
            (min(batch_rows, excess),),
        ).rowcount or 0
    remaining = conn.execute("SELECT COUNT(*) FROM web_observations").fetchone()[0]
    more_pending = bool(
        (retention_days > 0 and conn.execute(
            "SELECT 1 FROM web_observations WHERE timestamp < ? LIMIT 1", (cutoff,),
        ).fetchone())
        or (max_rows > 0 and remaining > max_rows)
    )
    return removed, more_pending


def db_persistence_worker(db_queue, status_queue, config, shutdown_event=None):
    """Persist telemetry via durable on-disk spool while interleaving retention work."""
    from netwatch_spool import TelemetrySpool

    log = setup_logging("db", config)
    spool_path = config.get("SPOOL_PATH", "telemetry_spool.db")
    spool_max_bytes = config.get("SPOOL_MAX_BYTES", 67_108_864)
    spool_wal_max_bytes = config.get("SPOOL_WAL_MAX_BYTES", 16_777_216)
    spool = TelemetrySpool(spool_path, max_bytes=spool_max_bytes, wal_max_bytes=spool_wal_max_bytes,
                           min_free_bytes=config.get("DISK_MIN_FREE_BYTES", DISK_MIN_FREE_BYTES))

    gap_store = None
    conn = None

    def get_ledger_conn():
        nonlocal conn
        if conn is None:
            c = sqlite3.connect(config["DB_NAME"], isolation_level=None)
            try:
                configure_connection(c, config.get("DB_WAL_MAX_BYTES", 67_108_864))
                c.execute("PRAGMA wal_autocheckpoint=0;")  # ledger_checkpoints() runs them beside the loop
                c.execute("""
                    CREATE TABLE IF NOT EXISTS network_events (
                        uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, mac_dst TEXT,
                        src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
                        tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER, sni_domain TEXT,
                        country TEXT DEFAULT '--', packet_count INTEGER NOT NULL DEFAULT 1
                    )
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS web_observations (
                        flow_id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                        src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
                        mac_src TEXT, mac_dst TEXT, protocol TEXT, port INTEGER,
                        domain TEXT, label TEXT NOT NULL, score INTEGER, reason TEXT,
                        os_guess TEXT, country TEXT, size_bytes INTEGER
                    )
                """)
                ensure_network_event_columns(c)
                for ddl in (
                    "CREATE INDEX IF NOT EXISTS idx_events_ts ON network_events(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_events_src ON network_events(src_ip, timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_events_dst ON network_events(dst_ip, timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_events_community ON network_events(community_id)",
                    "CREATE INDEX IF NOT EXISTS idx_web_observations_ts ON web_observations(timestamp)",
                ):
                    c.execute(ddl)
                conn = c
            except Exception:
                try:
                    c.close()
                except Exception:
                    pass
                raise
        return conn

    # Try initial connection setup
    try:
        get_ledger_conn()
    except Exception as exc:
        log.error("initial ledger connection failed; will spool and retry: %s: %s", type(exc).__name__, exc)

    retention_days = float(config.get("DB_RETENTION_DAYS", 7) or 0)
    max_rows = int(config.get("DB_MAX_ROWS", 0) or 0)
    web_max_rows = int(config.get("WEB_OBSERVATION_MAX_ROWS", 100_000) or 0)
    prune_interval = float(config.get("DB_PRUNE_INTERVAL_SEC", 600))
    prune_pending = False
    last_prune = time.monotonic()
    last_status = 0.0

    retry_delay = float(config.get("SPOOL_RETRY_INTERVAL_SEC", 1.0))
    next_ledger_retry = 0.0

    from netwatch_privilege import get_privilege_state

    privilege_state = get_privilege_state()

    def emit_status(action, message=None, error=None, extra=None):
        data = {"message": message or action, "timestamp": time.time(), "privilege": privilege_state}
        if extra:
            data.update(extra)
        msg = make_message(
            "DB_WORKER",
            action,
            "UI_SHELL",
            data,
            error=error,
        )
        try_put_drop_oldest(status_queue, msg)

    metadata_removed = 0

    def prune_metadata(store, now):
        """One bounded security-store batch per turn; failures leave rows for the next pass."""
        nonlocal metadata_removed
        try:
            # A fixed small batch keeps the shared security writer lock short.
            removed, more = store.prune_metadata(
                retention_days=float(config.get("METADATA_RETENTION_DAYS", 30) or 0),
                case_retention_days=float(config.get("CASE_RETENTION_DAYS", 365) or 0),
                batch_rows=1000, max_batches=1,
                native_retention_days=float(config.get("NATIVE_METADATA_RETENTION_DAYS", 1) or 0), now=now)
            metadata_removed += removed
            if not more:
                store.record_source_health("RETENTION:METADATA", {
                    "status": "RUNNING", "removed_last_pass": metadata_removed}, now)
                if metadata_removed:
                    log.info("metadata retention: removed %d row(s)", metadata_removed)
                metadata_removed = 0
            return more
        except sqlite3.Error as exc:
            log.error("metadata retention failed: %s: %s", type(exc).__name__, exc)
            return False

    native_totals = {}

    def prune_native(store, now):
        """One bounded SURICATA payload batch per turn (same pins as CONTROL)."""
        from netwatch_security_store import retention_status

        more = False
        for source in ("SURICATA",):
            try:
                report = store.prune_native_records(
                    source, max_rows=config.get("NATIVE_MAX_ROWS", 1_000_000),
                    max_bytes=config.get("NATIVE_MAX_BYTES", 1_073_741_824),
                    retention_days=config.get("NATIVE_RETENTION_DAYS", 7),
                    batch=NATIVE_PRUNE_BATCH, totals=native_totals.get(source), now=now)
            except (sqlite3.Error, ValueError) as exc:
                log.error("%s retention failed: %s: %s", source, type(exc).__name__, exc)
                native_totals.pop(source, None)
                continue
            # Recorded every batch: written only at the end of a pass, a backlog that never ends left
            # the row 21 h stale on the sensor. Pinned growth or a falling-behind backlog degrades it.
            store.record_source_health(f"RETENTION:NATIVE:{source}", {
                "status": retention_status(report, config.get("NATIVE_MAX_ROWS", 1_000_000),
                                           config.get("NATIVE_MAX_BYTES", 1_073_741_824)), **report}, now)
            if report["pruned"] >= NATIVE_PRUNE_BATCH:  # Only a full batch can leave work behind.
                native_totals[source] = (report["rows"], report["payload_bytes"])
                more = True
                continue
            native_totals.pop(source, None)
        return more

    def prune_assets(store, now):
        """One bounded batch of idle assets per turn."""
        from netwatch_assets import prune_assets as prune

        try:
            removed, more = prune(store, retention_days=float(config.get("ASSET_RETENTION_DAYS", 90) or 0),
                                  now=now)
            if removed:
                log.info("asset retention: removed %d idle asset(s)", removed)
            return more
        except sqlite3.Error as exc:
            log.error("asset retention failed: %s: %s", type(exc).__name__, exc)
            return False

    retention_stop = threading.Event()

    def security_retention():
        """Security-store retention beside the loop, on its own connection: the native quota scan
        reads every payload (12 s warm, 210 s cold on the sensor VM) and must not stall the heartbeat."""
        store = None
        while not retention_stop.wait(max(0.05, prune_interval)):
            try:
                if store is None:
                    from netwatch_security_store import security_db_path, security_store_from_config

                    path = security_db_path(config)
                    if path != ":memory:" and not os.path.isdir(os.path.dirname(os.path.abspath(path))):
                        continue
                    store = security_store_from_config(config)
                while not retention_stop.is_set():
                    started = time.monotonic()
                    if not (prune_metadata(store, time.time()) | prune_native(store, time.time())
                            | prune_assets(store, time.time())):
                        break
                    # Rest 3x the batch's own time so other writers take the shared lock between
                    # batches: a fixed 0.1 s gap left it held nearly always on the sensor (2026-10-11).
                    retention_stop.wait(max(0.1, 3 * (time.monotonic() - started)))
            except Exception as exc:  # never end retention for good; the next pass retries
                log.error("security retention deferred: %s: %s", type(exc).__name__, exc)
        if store is not None:
            store.close()

    retention_thread = threading.Thread(target=security_retention, name="security-retention", daemon=True)
    retention_thread.start()

    def ledger_checkpoints():
        """Ledger WAL checkpoints on their own connection: as an autocheckpoint inside the loop's
        COMMIT, the checkpoint's fdatasync of the ledger blocked the heartbeat 30 s on a cold VM."""
        checkpointer, last_warned = None, 0.0
        try:  # same normalisation as configure_connection; a bad value must not end the thread
            wal_max_bytes = max(0, int(config.get("DB_WAL_MAX_BYTES", 67_108_864)))
        except (TypeError, ValueError):
            wal_max_bytes = 67_108_864
        while not retention_stop.wait(LEDGER_CHECKPOINT_SEC):
            try:
                if checkpointer is None:
                    if conn is None:  # never create the ledger before the writer has opened it
                        continue
                    checkpointer = sqlite3.connect(config["DB_NAME"], isolation_level=None, timeout=0)
                # PASSIVE never blocks the writer; a busy turn leaves the frames for the next one.
                if checkpoint_ledger(checkpointer, config["DB_NAME"] + "-wal", wal_max_bytes) \
                        and time.monotonic() - last_warned >= 60:
                    last_warned = time.monotonic()
                    log.warning("ledger WAL past %d bytes under sustained writes; truncated", LEDGER_WAL_ESCALATE * wal_max_bytes)
            except sqlite3.Error as exc:
                log.debug("ledger checkpoint deferred: %s: %s", type(exc).__name__, exc)
        if checkpointer is not None:
            checkpointer.close()

    checkpoint_thread = threading.Thread(target=ledger_checkpoints, name="ledger-wal-checkpoint", daemon=True)
    checkpoint_thread.start()

    def prune(now):
        nonlocal conn
        if conn is None:
            return False
        try:
            removed, more = prune_network_events(
                conn,
                now=now,
                retention_days=retention_days,
                max_rows=max_rows,
                batch_rows=config.get("DB_PRUNE_BATCH_ROWS", 25_000),
            )
            if removed:  # a progress heartbeat between the two deletes
                emit_status("DB_HEARTBEAT", f"DB_WORKER_MAINTENANCE:{removed}")
            web_removed, web_more = prune_web_observations(
                conn,
                now=now,
                retention_days=retention_days,
                max_rows=web_max_rows,
                batch_rows=config.get("DB_PRUNE_BATCH_ROWS", 25_000),
            )
            removed += web_removed
            more = more or web_more
            if removed:
                log.info(
                    "retention: pruned %d event row(s)%s",
                    removed,
                    "; more pending" if more else "",
                )
            return more
        except sqlite3.Error as exc:
            log.error("retention prune failed: %s: %s", type(exc).__name__, exc)
            return False

    def emit_spool_gaps(spool):
        nonlocal gap_store
        try:
            if gap_store is None:
                from netwatch_security_store import security_db_path, security_store_from_config

                path = security_db_path(config)
                if path != ":memory:" and not os.path.isdir(os.path.dirname(os.path.abspath(path))):
                    raise OSError("security store directory unavailable")
                gap_store = security_store_from_config(config)
                # FULL on this connection only: the spool marks a gap transferred right after this commit,
                # so the commit must survive a power cut. Gap transfers are rare; the lock cost is not.
                gap_store.conn.execute("PRAGMA synchronous=FULL")
            spool.transfer_gaps(gap_store)
        except (sqlite3.Error, OSError) as exc:
            log.warning("gap transfer unavailable; preserving spool receipts: %s at %s", exc, " <- ".join(
                f"{os.path.basename(f.filename)}:{f.lineno} {f.name}"
                for f in reversed(traceback.extract_tb(exc.__traceback__)[-3:])))

    def spool_gap_transfer():
        """Gap transfer beside the loop: its security-store commit must not stall the heartbeat.
        Own spool, since a spool connection only works on the thread that opened it."""
        gap_spool = None
        while not retention_stop.wait(1.0):
            try:
                if gap_spool is None:
                    gap_spool = TelemetrySpool(spool_path, max_bytes=spool_max_bytes, wal_max_bytes=spool_wal_max_bytes,
                                               min_free_bytes=config.get("DISK_MIN_FREE_BYTES", DISK_MIN_FREE_BYTES))
                emit_spool_gaps(gap_spool)
            except Exception as exc:  # gaps stay pending in the spool; the shutdown call retries
                log.error("gap transfer deferred: %s: %s", type(exc).__name__, exc)
        if gap_spool is not None:
            gap_spool.close()

    gap_thread = threading.Thread(target=spool_gap_transfer, name="spool-gap-transfer", daemon=True)
    gap_thread.start()

    def replay_until(deadline):
        nonlocal conn, retry_delay, next_ledger_retry
        while time.monotonic() < deadline:
            batch_id, rows, observations, _ = spool.fetch_pending_batch()
            if batch_id is None:
                return
            try:
                c = get_ledger_conn()
                c.execute("BEGIN IMMEDIATE")
                if rows:
                    c.executemany(EVENT_INSERT_SQL, ledger_event_rows(rows))
                if observations:
                    c.executemany(WEB_OBSERVATION_INSERT_SQL, observations)
                c.execute("COMMIT")
            except Exception as exc:
                if conn is not None and conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass  # A broken connection is closed and reopened below.
                if isinstance(exc, sqlite3.IntegrityError | sqlite3.InterfaceError
                              | sqlite3.ProgrammingError | sqlite3.DataError
                              | ValueError | TypeError | IndexError):
                    spool.reject_batch(batch_id, exc)
                    continue
                emit_status("DB_WRITE_FAILURE", error=exc)
                log.warning("ledger unavailable; preserving spool: %s", exc)
                if conn is not None:
                    conn.close()
                    conn = None
                next_ledger_retry = time.monotonic() + retry_delay
                retry_delay = min(30.0, retry_delay * 2)
                return
            # Spool failures must not be classified as ledger data failures.
            spool.acknowledge_batch(batch_id)
            retry_delay = float(config.get("SPOOL_RETRY_INTERVAL_SEC", 1.0))

    emit_status("DB_HEARTBEAT", "DB_WORKER_STARTED")
    log.info(
        "persistence worker started (retention %.0fd, max_rows %s, spool %s)",
        retention_days,
        max_rows or "unbounded",
        spool_path,
    )

    batch_seq = 0

    def take(payload):
        """Turn a DB_BATCH message into a spool batch with a fixed id, or None."""
        nonlocal batch_seq
        if not (is_message_payload(payload) and payload["action"] == "DB_BATCH"):
            return None
        rows = payload["data"].get("rows", [])
        raw_observations = payload["data"].get("observations", [])
        observations = normalize_web_observation_rows(raw_observations)
        if isinstance(raw_observations, list | tuple) and len(observations) != len(raw_observations):
            log.error("dropped %d malformed web observation(s)", len(raw_observations) - len(observations))
        # The core compacts before sending; a malformed row is dropped here rather than killing the worker.
        batch = [row for row in rows if isinstance(row, list | tuple) and len(row) == 20] if isinstance(rows, list) else []
        if isinstance(rows, list) and len(batch) != len(rows):
            log.error("dropped %d malformed ledger row(s)", len(rows) - len(batch))
        if not (batch or observations):
            return None
        batch_seq += 1
        return f"{payload.get('correlation_id', 'batch')}-{batch_seq}", batch, observations

    def admit(b_id, batch, observations):
        """Spool receipt or an exact durable full-spool/disk-floor gap; storage errors raise to the caller."""
        accepted, reason, gap_info = spool.enqueue_batch(b_id, batch, observations)
        if not accepted:
            log.warning("spool admission refused (%s): dropped %d rows, %d obs",
                        reason, gap_info["dropped_rows"], gap_info["dropped_observations"])

    # A dequeued batch stays here until the spool receipts it; the same id makes a
    # retry after an ambiguous commit replace, not duplicate, the spooled copy.
    held = None
    base_retry = spool_delay = float(config.get("SPOOL_RETRY_INTERVAL_SEC", 1.0))
    while True:
        now = time.monotonic()  # wall-clock steps must not silence the heartbeat
        try:
            if now - last_status >= 1.0:
                counts = spool.count_pending()
                emit_status("DB_HEARTBEAT", extra={"spool_pending": counts["batches"]})
                last_status = now

            if prune_pending or now - last_prune >= prune_interval:
                if not prune_pending:
                    last_prune = now
                prune_pending = prune(time.time())

            if held is None:
                try:
                    held = take(db_queue.get(timeout=0.05))
                except queue.Empty:
                    if shutdown_event is not None and shutdown_event.is_set():
                        break
            elif shutdown_event is not None and shutdown_event.is_set():
                break
            if held is not None:
                admit(*held)
                held = None

            # Bound replay time so arriving traffic and maintenance get a turn.
            if now >= next_ledger_retry:
                replay_until(time.monotonic() + 0.1)
            spool_delay = base_retry
        except (sqlite3.Error, OSError) as exc:
            # Spool storage failure: keep the held batch and stop dequeuing, so the
            # core's exact backpressure accounting covers anything it cannot queue.
            log.warning("spool unavailable; holding batch and retrying: %s: %s", type(exc).__name__, exc)
            emit_status("DB_WRITE_FAILURE", "SPOOL_UNAVAILABLE", error=exc)
            # Still alive: a supervisor restart here would turn an exact hold into unknown loss.
            emit_status("DB_HEARTBEAT", "SPOOL_UNAVAILABLE", error=exc, extra={"status": "DEGRADED"})
            time.sleep(spool_delay)
            spool_delay = min(5.0, spool_delay * 2)

    # Shutdown: receipt the held batch and the rest of db_queue. A storage error
    # here exits non-zero, so the runtime reports an unverified drain and a gap.
    if held is not None:
        admit(*held)
    while True:
        try:
            held = take(db_queue.get_nowait())
        except queue.Empty:
            break
        if held is not None:
            admit(*held)

    # Fits the service's RUNTIME_STOP_GRACE_SEC after core drains, with time left for close/checkpoint.
    replay_until(time.monotonic() + 8.0)

    retention_stop.set()
    retention_thread.join(2)  # a batch commits in well under this; an interrupted scan is only a read
    checkpoint_thread.join(2)  # PASSIVE is safe to abandon; the TRUNCATE below finishes the job
    gap_thread.join(2)
    emit_spool_gaps(spool)
    pending_after_shutdown = spool.count_pending()
    if pending_after_shutdown["batches"] > 0:
        log.warning(
            "shutdown with %d batches (%d rows) remaining in spool; preserved for restart",
            pending_after_shutdown["batches"],
            pending_after_shutdown["rows"],
        )
        emit_status(
            "SPOOL_PRESERVED",
            "SPOOL_PRESERVED_ON_SHUTDOWN",
            extra=pending_after_shutdown,
        )

    if conn is not None:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except sqlite3.Error as exc:
            log.warning("shutdown checkpoint failed: %s", exc)
        finally:
            try:
                conn.close()
            except sqlite3.Error as exc:  # close must never raise into shutdown
                log.warning("ledger connection close failed: %s", exc)

    if gap_store is not None:
        gap_store.close()
    spool.close()
    log.info("persistence worker shut down")

