"""Durable on-disk spool for telemetry and packet history rows.

Sits between the analytics producers and the ledger writer. When SQLite or the
underlying storage fails, rows accumulate safely on disk with per-record/batch
checksums. Batches are acknowledged and removed only after the ledger commit
succeeds. When restarted, unacknowledged batches replay idempotently.

If the spool hits its hard byte ceiling, new rows are rejected and an explicit,
durable loss gap is recorded.
"""

import json
import logging
import os
import sqlite3
import time
import uuid
import zlib

from netwatch_core import disk_admission

SPOOL_SCHEMA = """
CREATE TABLE IF NOT EXISTS spool_batches (
    batch_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL,
    created_at REAL NOT NULL,
    payload_json TEXT NOT NULL,
    payload_crc INTEGER NOT NULL,
    row_count INTEGER NOT NULL,
    observation_count INTEGER NOT NULL,
    byte_size INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'spooled'
);
CREATE INDEX IF NOT EXISTS idx_spool_batches_seq ON spool_batches(sequence, created_at);
CREATE INDEX IF NOT EXISTS idx_spool_batches_state ON spool_batches(state, sequence);

CREATE TABLE IF NOT EXISTS spool_identity (identity TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS spool_gaps (
    gap_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    reason TEXT NOT NULL,
    dropped_rows INTEGER NOT NULL,
    dropped_observations INTEGER NOT NULL,
    spool_bytes INTEGER NOT NULL,
    limit_bytes INTEGER NOT NULL
);
"""


class TelemetrySpool:
    """Manages transactional spooling and acknowledgement of telemetry batches."""

    def __init__(self, spool_path, max_bytes=67_108_864, wal_max_bytes=16_777_216, min_free_bytes=0):
        self.spool_path = os.path.abspath(spool_path)
        self.min_free_bytes = max(0, int(min_free_bytes))
        self.max_bytes = max(1024 * 1024, int(max_bytes))
        self.wal_max_bytes = max(1024 * 1024, int(wal_max_bytes))
        self._ensure_dir()
        self._conn = None
        self._seq = 0
        self._init_db()

    def _ensure_dir(self):
        parent = os.path.dirname(self.spool_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def _open_conn(self):
        conn = sqlite3.connect(self.spool_path, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=FULL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        # Budget both database and one full transaction WAL, plus SHM/headers.
        page_limit = max(1, (self.max_bytes - 131072) // (2 * page_size))
        conn.execute(f"PRAGMA max_page_count={page_limit}")
        # Auto-checkpoint keeps the WAL inside the budget without a per-batch TRUNCATE fsync.
        conn.execute(f"PRAGMA wal_autocheckpoint={max(1, page_limit // 4)}")
        conn.execute(f"PRAGMA journal_size_limit={min(self.wal_max_bytes, self.max_bytes // 4)};")
        return conn

    def _init_db(self):
        conn = self._open_conn()
        try:
            conn.executescript(SPOOL_SCHEMA)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(spool_gaps)")}
            for name, default in (("loss_batches", 1), ("transferred_batches", 0), ("batch_count_exact", 1)):
                if name not in columns:
                    conn.execute(f"ALTER TABLE spool_gaps ADD COLUMN {name} INTEGER NOT NULL DEFAULT {default}")
            if "loss_batches" not in columns:
                # Old full gaps retained rows/observations, but not refusal counts.
                conn.execute("UPDATE spool_gaps SET batch_count_exact=0 WHERE reason='spool_full'")
            conn.execute("INSERT INTO spool_identity SELECT ? WHERE NOT EXISTS (SELECT 1 FROM spool_identity)",
                         (uuid.uuid4().hex,))
            self.identity = conn.execute("SELECT identity FROM spool_identity").fetchone()[0]
            row = conn.execute("SELECT MAX(sequence) FROM spool_batches").fetchone()
            self._seq = int(row[0]) if (row and row[0] is not None) else 0
        finally:
            conn.close()

    def get_connection(self):
        if self._conn is None:
            self._conn = self._open_conn()
        return self._conn

    def close(self):
        if self._conn is not None:
            log = logging.getLogger("netwatch.db")  # module logger never reaches LOG_DIR (propagate=False)
            try:
                self._compact()  # VACUUM-if-empty runs only here, never on the batch path
            except (sqlite3.Error, OSError) as exc:  # close must never raise into shutdown
                log.warning("spool compaction at close failed: %s", exc)
            finally:
                try:
                    self._conn.close()
                except (sqlite3.Error, OSError) as exc:
                    log.warning("spool connection close failed: %s", exc)
                self._conn = None

    def get_disk_usage(self):
        """Total bytes occupied by spool file, WAL and SHM."""
        total = 0
        for ext in ("", "-wal", "-shm"):
            p = f"{self.spool_path}{ext}"
            if os.path.exists(p):
                try:
                    total += os.path.getsize(p)
                except OSError:
                    pass
        return total

    def count_pending(self):
        """Count unacknowledged batches and rows."""
        conn = self.get_connection()
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(row_count), 0), COALESCE(SUM(observation_count), 0) "
            "FROM spool_batches WHERE state = 'spooled'"
        ).fetchone()
        return {
            "batches": int(row[0]),
            "rows": int(row[1]),
            "observations": int(row[2]),
        }

    def enqueue_batch(self, batch_id, rows, observations, created_at=None):
        """Persist a telemetry batch into the spool.

        Returns (accepted, reason, dropped_info).
        """
        now = time.time() if created_at is None else float(created_at)
        row_list = rows or []
        obs_list = observations or []
        row_count = sum(r[13] for r in row_list)
        obs_count = len(obs_list)

        payload_obj = {
            "batch_id": batch_id,
            "rows": row_list,
            "observations": obs_list,
        }
        payload_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
        byte_size = len(payload_bytes)
        crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF

        conn = self.get_connection()
        current_size = conn.execute(
            "SELECT COALESCE(SUM(byte_size), 0) FROM spool_batches WHERE state='spooled'"
        ).fetchone()[0]
        if not disk_admission(self.spool_path, self.min_free_bytes)[0]:
            # Only the cumulative gap row is updated while the volume is low.
            gap_info = self._record_admission_refusal(
                now, row_count, obs_count, current_size, self.min_free_bytes, reason="disk_floor")
            return False, "disk_floor", gap_info
        # Reserve SQLite page/index overhead and space for a transaction WAL.
        disk_full = 2 * (current_size + byte_size + 65536) + 131072 > self.max_bytes
        if current_size + byte_size > self.max_bytes or disk_full:
            # Spool full: refuse admission and write explicit loss gap
            gap_info = self._record_admission_refusal(
                now, row_count, obs_count, current_size, self.max_bytes
            )
            return False, "spool_full", gap_info

        conn = self.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            self._seq += 1
            conn.execute(
                "INSERT OR REPLACE INTO spool_batches "
                "(batch_id, sequence, created_at, payload_json, payload_crc, row_count, observation_count, byte_size, state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'spooled')",
                (
                    batch_id,
                    self._seq,
                    now,
                    payload_bytes.decode("utf-8"),
                    crc,
                    row_count,
                    obs_count,
                    byte_size,
                ),
            )
            conn.execute("COMMIT")
            return True, "spooled", None
        except Exception as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            if isinstance(exc, sqlite3.OperationalError) and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                gap = self._record_admission_refusal(now, row_count, obs_count, current_size, self.max_bytes)
                return False, "spool_full", gap
            raise

    def _record_admission_refusal(self, now, rows, obs, current_size, max_bytes, reason="spool_full"):
        gap_id = reason
        conn = self.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO spool_gaps "
                "(gap_id, timestamp, reason, dropped_rows, dropped_observations, spool_bytes, limit_bytes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(gap_id) DO UPDATE SET "
                "dropped_rows=dropped_rows+excluded.dropped_rows, "
                "dropped_observations=dropped_observations+excluded.dropped_observations, "
                "loss_batches=loss_batches+1, spool_bytes=excluded.spool_bytes, limit_bytes=excluded.limit_bytes",
                (gap_id, now, reason, rows, obs, current_size, max_bytes),
            )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return {
            "gap_id": gap_id,
            "timestamp": now,
            "dropped_rows": rows,
            "dropped_observations": obs,
            "spool_bytes": current_size,
            "limit_bytes": max_bytes,
        }

    def fetch_pending_batch(self):
        """Fetch the oldest spooled batch.

        Returns (batch_id, rows, observations, error_or_corrupt_gap) or (None, None, None, None).
        If payload corruption is detected, marks the batch corrupt, logs a gap, and returns next valid.
        """
        conn = self.get_connection()
        corrupt_gap = None
        while True:
            row = conn.execute(
                "SELECT batch_id, sequence, payload_json, payload_crc, row_count, observation_count, created_at "
                "FROM spool_batches WHERE state = 'spooled' ORDER BY sequence ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None, None, None, corrupt_gap

            batch_id, seq, payload_json, expected_crc, row_count, obs_count, created_at = row
            try:
                raw_bytes = payload_json.encode("utf-8")
                actual_crc = zlib.crc32(raw_bytes) & 0xFFFFFFFF
                if actual_crc != expected_crc:
                    raise ValueError(f"CRC mismatch: expected {expected_crc}, got {actual_crc}")
                data = json.loads(payload_json)
                rows = data.get("rows", [])
                observations = data.get("observations", [])
                return batch_id, rows, observations, corrupt_gap
            except Exception as exc:
                # Mark corrupt and record durable loss gap
                gap_id = f"spool_corrupt_{batch_id}_{int(time.time() * 1000)}"
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute(
                        "UPDATE spool_batches SET state = 'corrupt', payload_json='', byte_size=0 WHERE batch_id = ?",
                        (batch_id,),
                    )
                    conn.execute(
                        "INSERT INTO spool_gaps "
                        "(gap_id, timestamp, reason, dropped_rows, dropped_observations, spool_bytes, limit_bytes) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            gap_id,
                            time.time(),
                            f"corrupt_batch:{exc}",
                            row_count,
                            obs_count,
                            self.get_disk_usage(),
                            self.max_bytes,
                        ),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise
                corrupt_gap = {
                    "gap_id": gap_id,
                    "batch_id": batch_id,
                    "error": str(exc),
                    "dropped_rows": row_count,
                    "dropped_observations": obs_count,
                }
                # Continue iteratively; every skipped batch retains its own durable gap.

    def acknowledge_batch(self, batch_id):
        """Remove or mark committed a successfully written batch."""
        conn = self.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM spool_batches WHERE batch_id = ?", (batch_id,))
            conn.execute("COMMIT")
            return True
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    def drain_unacknowledged_gaps(self):
        """Read loss gaps; best-effort reporting is never an acknowledgement."""
        conn = self.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT gap_id, timestamp, reason, dropped_rows, dropped_observations, spool_bytes, limit_bytes "
                "FROM spool_gaps ORDER BY timestamp ASC"
            ).fetchall()
            conn.execute("COMMIT")
            return [
                {
                    "gap_id": r[0],
                    "timestamp": r[1],
                    "reason": r[2],
                    "dropped_rows": r[3],
                    "dropped_observations": r[4],
                    "spool_bytes": r[5],
                    "limit_bytes": r[6],
                }
                for r in rows
            ]
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    def _compact(self):
        conn = self.get_connection()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if not self.count_pending()["batches"]:
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def reject_batch(self, batch_id, error):
        """Quarantine data failures and record their loss atomically."""
        conn = self.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO spool_gaps (gap_id, timestamp, reason, dropped_rows, dropped_observations, spool_bytes, limit_bytes) "
                "SELECT ?, ?, ?, row_count, observation_count, ?, ? "
                "FROM spool_batches WHERE batch_id=? AND state='spooled'",
                (f"rejected:{batch_id}", time.time(), f"rejected_batch:{error}",
                 self.get_disk_usage(), self.max_bytes, batch_id),
            )
            conn.execute("UPDATE spool_batches SET state='rejected', payload_json='', byte_size=0 "
                         "WHERE batch_id=?", (batch_id,))
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise

    def mark_gap_transferred(self, gap):
        """Acknowledge only the committed cumulative revision, never erase loss."""
        self.get_connection().execute(
            "UPDATE spool_gaps SET transferred_batches=? WHERE gap_id=? AND loss_batches=?",
            (gap["loss_batches"], gap["gap_id"], gap["loss_batches"]))

    def transfer_gaps(self, store):
        """Commit idempotent cumulative receipts before spool acknowledgement."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        try:
            gaps = [dict(row) for row in conn.execute(
                "SELECT * FROM spool_gaps WHERE loss_batches>transferred_batches")]
            for gap in gaps:
                store.record_spool_gap(self.identity, gap)
                self.mark_gap_transferred(gap)
            totals = conn.execute("""SELECT
                COALESCE(SUM(CASE WHEN reason='spool_full' THEN loss_batches ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN reason LIKE 'corrupt_batch:%' THEN loss_batches ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN reason LIKE 'rejected_batch:%' THEN loss_batches ELSE 0 END), 0),
                COALESCE(SUM(dropped_rows), 0), COALESCE(SUM(dropped_observations), 0),
                COALESCE(MIN(batch_count_exact), 1),
                COALESCE(SUM(CASE WHEN reason='disk_floor' THEN loss_batches ELSE 0 END), 0)
                FROM spool_gaps""").fetchone()
            pending_bytes = conn.execute(
                "SELECT COALESCE(SUM(byte_size),0) FROM spool_batches WHERE state='spooled'").fetchone()[0]
            disk_ok, disk_free = disk_admission(self.spool_path, self.min_free_bytes)
            store.record_source_health("SPOOL:" + self.identity, {
                "status": "DEGRADED" if any(totals[:5]) or totals[6] or not disk_ok else "RUNNING",
                "disk_admission": "open" if disk_ok else "refusing", "disk_free_bytes": disk_free,
                "disk_floor_bytes": self.min_free_bytes, "disk_floor_refused_batches": totals[6],
                "pending_batches": self.count_pending()["batches"], "pending_bytes": pending_bytes,
                "disk_bytes": self.get_disk_usage(), "limit_bytes": self.max_bytes,
                "refused_batches": totals[0] if totals[5] else None, "corrupt_batches": totals[1], "rejected_batches": totals[2],
                "dropped_rows": totals[3], "dropped_observations": totals[4],
            })
        finally:
            conn.row_factory = None
