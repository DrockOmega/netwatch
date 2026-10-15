"""Transactional detections and cases, independent of Qt and presentation queues.

This is the collector's local SQLite store and the source of truth.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

from netwatch_core import make_message, try_put_drop_oldest
from netwatch_history import _FILTERS as HISTORY_FILTERS
from netwatch_history import HistoryStore
from netwatch_incidents import (
    _CLOSED_INCIDENT_STATUSES,
    SEVERITY_RANK,
    Incident,
    IncidentStore,
    _target_text,
    detection_fields,
    load_rule_pack,
    map_attack,
)

# Saved-hunt filter name -> fixed SQL fragment over security_source_events. Values are always bound.
HUNT_SOURCE_FILTERS = {
    "source": "source = ?", "sensor_id": "sensor_id = ?", "event_type": "event_type = ?",
    "community_id": "json_extract(normalized, '$.community_id') = ?",
    "src_ip": "json_extract(normalized, '$.src_ip') = ?",
    "dst_ip": "json_extract(normalized, '$.dst_ip') = ?",
    "destination_port": "json_extract(normalized, '$.destination_port') = ?",
    "application": "json_extract(normalized, '$.application') = ?",
    "since": "event_time >= ?", "until": "event_time <= ?",
}
HUNT_LIMIT = 500
HUNT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")

CASE_STATUSES = frozenset({"Open", "Acknowledged", "Pending", "Contained",
                           "Resolved", "Recovered", "Dismissed"})

def _readback(body):
    # Readback is unverified until an independent check exists; a stored claim cannot promote it.
    return body | {"readback": "unverified"}


def security_db_path(config):
    """INCIDENT_DB, which DEFAULTS always sets; hand-built configs fall back beside DB_NAME, else memory."""
    return config.get("INCIDENT_DB") or (f"{config['DB_NAME']}.security.db" if config.get("DB_NAME") else ":memory:")


def security_store_from_config(config):
    path = security_db_path(config)
    rules = config.get("CORRELATION_RULES")
    # A configured but missing pack disables cross-source joins; /v1/rules then reports no pack.
    pack = load_rule_pack(rules) if rules and os.path.isfile(rules) else None
    return DurableIncidentStore(path, sensor_id=config.get("SENSOR_ID", "unknown"), rule_pack=pack,
                                local_networks=(*config.get("LOCAL_PREFIXES", ()),
                                                *config.get("LOCAL_PREFIXES6", ())))


def publish_detection(store, presentation_queue, payload):
    """The presentation queue is never the acknowledgment boundary."""
    if store.add(payload) is None:
        raise ValueError("invalid detection envelope")
    return try_put_drop_oldest(presentation_queue, payload)


def _json_default(value):
    if isinstance(value, bytes | bytearray):
        return {"$binary": bytes(value).hex()}
    raise TypeError(f"unsupported security event value: {type(value).__name__}")


def sqlite_wal_safe(version=sqlite3.sqlite_version_info):
    """SQLite before 3.51.3 (backports 3.50.7, 3.44.6) can corrupt a WAL database when a checkpoint races a write."""
    return version >= (3, 51, 3) or (3, 50, 7) <= version < (3, 51) or (3, 44, 6) <= version < (3, 45)


def _encode(value):
    return json.dumps(value, default=_json_default, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def _event_time(value, fallback):
    try:
        timestamp = float(value)
    except OverflowError:
        return fallback  # An integer beyond float range is no timestamp.
    except (TypeError, ValueError):
        try:
            timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError, OverflowError, OSError):
            return fallback
    if not math.isfinite(timestamp):
        return fallback
    try:
        datetime.fromtimestamp(timestamp, UTC)
    except (ValueError, OverflowError, OSError):
        return fallback
    return timestamp


def _incident(body):
    # Cases written before sources/rules existed fall back to the dataclass defaults.
    return Incident(**{name: body[name] for name in Incident.__dataclass_fields__ if name in body})


def _case_body(text):
    """A stored case body; cases written before ATT&CK tagging get map tags from their kind."""
    body = json.loads(text)
    if "attack" not in body:
        body["attack"] = map_attack(body.get("action"), body.get("detail", ""))
    return body


SLOW_WRITE_SEC = 1.0
ORDER_BACKFILL_KEY = "MIGRATION:source_order:v1"
LEGACY_TOMBSTONE_BATCH = 5000
# A source being drained sits just over its target between batches; only past this much is it
# falling behind (health DEGRADED). Without slack CONTROL flapped DEGRADED at the cap on the sensor.
RETENTION_SLACK = 1.05


def retention_status(report, max_rows, max_bytes):
    """RUNNING, or DEGRADED when pins hold a source over target or it is past ``RETENTION_SLACK``."""
    behind = ((max_rows > 0 and report.get("rows", 0) > max_rows * RETENTION_SLACK)
              or (max_bytes > 0 and report.get("payload_bytes", 0) > max_bytes * RETENTION_SLACK))
    return "DEGRADED" if behind or report.get("protected_or_pending") else "RUNNING"


def _component_logger():
    import logging
    loggers = [lg for name, lg in logging.root.manager.loggerDict.items()
               if name.startswith("netwatch.") and isinstance(lg, logging.Logger) and lg.handlers]
    return loggers[0] if loggers else logging.getLogger("netwatch")


def note_notify_failure(owner):
    """Count a failed notify callback; log only the first so a dead queue cannot flood the log."""
    owner.notify_failures += 1
    if owner.notify_failures == 1:
        _component_logger().warning("notify callback failed (further failures counted in health)", exc_info=True)


def _where(frames):
    frames = [f for f in frames if "contextlib" not in f.filename and "threading" not in f.filename][-4:]
    return " <- ".join(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in reversed(frames))


def _warn_slow_write(held):
    """Name the caller of any security-store write that held the shared writer lock too long.

    Every worker shares this file's single SQLite writer lock; one slow writer starves the rest
    past their busy timeout. Logs through whichever component logger this process configured.
    """
    if held < SLOW_WRITE_SEC:
        return
    import traceback
    _component_logger().warning("security store write held the writer lock %.1fs: %s",
                                held, _where(traceback.extract_stack()[:-3]))


def _warn_still_holding(thread_id, store):
    """Report a writer mid-hold: a worker killed as stale never reaches the post-hoc log.

    Reads the store's own flag, never the connection: conn.in_transaction from this timer
    thread waited on SQLite's connection mutex while the writer sat in BEGIN's busy wait,
    holding the GIL and freezing every thread of the process for the whole busy timeout
    (~32 s with the evidence catalog's 30 s, the sniffer stalls on the sensor 2026-10-11/12)."""
    import traceback
    frame = sys._current_frames().get(thread_id)
    if frame is not None and store._holding:  # still waiting in BEGIN is not a hold
        _component_logger().warning("security store write still holding the writer lock after %.0fs: %s",
                                    SLOW_WRITE_SEC, _where(traceback.extract_stack(frame)))


WAL_MAX_BYTES = 67_108_864  # same 64 MiB cap as DB_WAL_MAX_BYTES for the ledger and spool


class DurableIncidentStore:
    """Commit source detections and correlated cases before acknowledgment.

    All mutations use SQLite transactions (synchronous=NORMAL): crash-safe on return, durable
    against a power cut once the background checkpointer syncs the WAL (every few seconds). The
    display limit never deletes persisted evidence or cases. One connection per
    process/thread is required, as with the existing packet writer.
    """

    def __init__(self, path, max_incidents=500, *, sensor_id="unknown", rule_pack=None, local_networks=()):
        if not sqlite_wal_safe():
            # Several processes write this WAL store; on these versions that corrupted
            # the sensor's twice (2026-10-10/11). Refusing beats a third rebuild.
            raise RuntimeError(f"SQLite {sqlite3.sqlite_version} has the WAL-reset corruption bug; "
                               "refusing to open the security store (install 3.51.3 or later)")
        self.max_incidents = max(1, int(max_incidents))
        self.rule_pack = rule_pack
        self.rules = list(rule_pack["rules"]) if rule_pack else []
        self.local_networks = tuple(local_networks)
        self.sensor_id = str(sensor_id or "unknown")
        self.path = str(path)
        # source -> order sequence below which no over-quota prune candidate of that source remains.
        self._prune_floor = {}
        self._legacy_tombstones_done = False  # pre-2026-10-12 CONTROL tombstones: a full scan, needed until none remain
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        # ponytail: serialize local detection writers; independent connections
        # per thread if measured alert throughput makes this lock a bottleneck.
        self._lock = threading.RLock()
        self._holding = False  # inside BEGIN..COMMIT; read by the slow-write timer instead of the connection
        self._gap_detected = {}  # (spool_id, gap_id) -> monotonic time of the last gap detection
        self.conn = sqlite3.connect(path, isolation_level=None, timeout=5, check_same_thread=False)
        if path != ":memory:" and os.name == "posix":
            os.chmod(path, 0o600)  # WAL/SHM inherit the database's access permissions.
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        mode = self.conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if path != ":memory:" and mode != "wal":
            self.conn.close()
            raise sqlite3.OperationalError("security ledger requires WAL")
        self.conn.execute(f"PRAGMA journal_size_limit={WAL_MAX_BYTES}")  # PASSIVE checkpoints never shrink the file
        # No per-commit WAL fsync: FULL held the shared writer lock through every fsync, and syncing
        # the -wal file through our own handle is outside SQLite's locking (on POSIX, closing it drops
        # the process's locks). The checkpointer's sync makes commits power-cut durable.
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._checkpointer = None
        if path != ":memory:":
            # An inline auto-checkpoint copies the WAL into the main file and fsyncs it
            # after a commit, stalling whichever worker loop tripped it (0.6s+ on a
            # loaded VM). A background thread on its own connection does it instead.
            self.conn.execute("PRAGMA wal_autocheckpoint=0")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS security_incidents (
                incident_id TEXT PRIMARY KEY, correlation_key TEXT NOT NULL UNIQUE,
                action TEXT NOT NULL, target TEXT NOT NULL, severity TEXT NOT NULL,
                status TEXT NOT NULL, last_seen REAL NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_detections (
                event_id TEXT PRIMARY KEY, source TEXT NOT NULL,
                source_event_id TEXT NOT NULL, sensor_id TEXT NOT NULL,
                event_time REAL NOT NULL, received_at REAL NOT NULL,
                schema_version INTEGER NOT NULL, payload TEXT NOT NULL,
                incident_id TEXT NOT NULL REFERENCES security_incidents(incident_id)
            );
            CREATE INDEX IF NOT EXISTS idx_detections_case
                ON security_detections(incident_id, received_at);
            -- Retention pins seek the detections naming a native record (the first is also the
            -- evidence catalog's); unindexed, one prune read every open-case payload per candidate.
            CREATE INDEX IF NOT EXISTS idx_detection_source_identity
                ON security_detections(source_event_id, source, sensor_id);
            CREATE INDEX IF NOT EXISTS idx_detections_native_event
                ON security_detections(CAST(json_extract(payload, '$.data.native_event_id') AS TEXT));
            CREATE INDEX IF NOT EXISTS idx_detections_native_events ON security_detections(incident_id)
                WHERE json_type(payload, '$.data.native_event_ids') IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_cases_seen
                ON security_incidents(last_seen);
            CREATE TABLE IF NOT EXISTS security_case_audit (
                sequence INTEGER PRIMARY KEY, incident_id TEXT NOT NULL
                    REFERENCES security_incidents(incident_id),
                timestamp REAL NOT NULL, actor TEXT NOT NULL,
                operation TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_case_audit
                ON security_case_audit(incident_id, sequence);
            CREATE TABLE IF NOT EXISTS security_case_links (
                incident_id TEXT NOT NULL REFERENCES security_incidents(incident_id),
                kind TEXT NOT NULL, reference TEXT NOT NULL,
                PRIMARY KEY (incident_id, kind, reference)
            );
            CREATE TABLE IF NOT EXISTS security_source_events (
                event_id TEXT PRIMARY KEY, source TEXT NOT NULL, sensor_id TEXT NOT NULL,
                event_type TEXT NOT NULL, event_time REAL NOT NULL,
                received_at REAL NOT NULL, normalized TEXT NOT NULL, native TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_source_events_type
                ON security_source_events(source, sensor_id, event_type, received_at);
            -- Collectors restore health from source_events(source, sensor_id=..., limit=1) at startup.
            CREATE INDEX IF NOT EXISTS idx_source_events_latest
                ON security_source_events(source, sensor_id, received_at);
            CREATE INDEX IF NOT EXISTS idx_source_events_community
                ON security_source_events(json_extract(normalized, '$.community_id'));
            CREATE TABLE IF NOT EXISTS security_correlation_keys (
                event_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL
                    REFERENCES security_incidents(incident_id),
                source TEXT NOT NULL, received_at REAL NOT NULL,
                community_id TEXT, asset TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_correlation_community
                ON security_correlation_keys(community_id, received_at);
            CREATE INDEX IF NOT EXISTS idx_correlation_asset
                ON security_correlation_keys(asset, received_at);
            CREATE INDEX IF NOT EXISTS idx_correlation_case
                ON security_correlation_keys(incident_id);
            CREATE TABLE IF NOT EXISTS security_hunts (
                name TEXT PRIMARY KEY, created_at REAL NOT NULL, actor TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_hunt_runs (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL REFERENCES security_hunts(name),
                timestamp REAL NOT NULL, actor TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_source_cursors (
                source_key TEXT PRIMARY KEY, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_spool_gaps (
                spool_id TEXT NOT NULL, gap_id TEXT NOT NULL, loss_batches INTEGER NOT NULL,
                timestamp REAL NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (spool_id, gap_id)
            );
            CREATE TABLE IF NOT EXISTS security_source_health (
                source_key TEXT PRIMARY KEY, updated_at REAL NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_source_order (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS security_native_holds (
                event_id TEXT PRIMARY KEY, actor TEXT NOT NULL, reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_native_pruned (
                event_id TEXT PRIMARY KEY, native_sha256 TEXT NOT NULL,
                pruned_at REAL NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_native_pruned_at
                ON security_native_pruned(pruned_at);
            CREATE TABLE IF NOT EXISTS security_native_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL, actor TEXT NOT NULL,
                operation TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_items (
                evidence_id TEXT PRIMARY KEY, directory TEXT NOT NULL,
                filename TEXT NOT NULL, created_at REAL NOT NULL,
                size_bytes INTEGER NOT NULL, status TEXT NOT NULL,
                held INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL,
                UNIQUE(directory, filename)
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_root
                ON evidence_items(directory, status, created_at);
            CREATE TABLE IF NOT EXISTS evidence_audit (
                sequence INTEGER PRIMARY KEY, evidence_id TEXT NOT NULL,
                timestamp REAL NOT NULL, actor TEXT NOT NULL,
                operation TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_response_actions (
                action_id TEXT PRIMARY KEY,
                case_id TEXT REFERENCES security_incidents(incident_id),
                kind TEXT NOT NULL, target TEXT NOT NULL, scope TEXT NOT NULL,
                requested_by TEXT NOT NULL, reason TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN (
                    'requested', 'approved', 'denied', 'applied', 'failed', 'released', 'expired')),
                requested_at REAL NOT NULL, decided_at REAL, applied_at REAL, closed_at REAL,
                expires_at REAL NOT NULL,
                readback TEXT NOT NULL CHECK (readback = 'unverified'),
                body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_response_actions_due
                ON security_response_actions(state, expires_at);
            CREATE INDEX IF NOT EXISTS idx_response_actions_case
                ON security_response_actions(case_id, requested_at);
            CREATE TABLE IF NOT EXISTS security_action_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL REFERENCES security_response_actions(action_id),
                timestamp REAL NOT NULL, actor TEXT NOT NULL,
                operation TEXT NOT NULL, state TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_action_audit
                ON security_action_audit(action_id, sequence);
            CREATE TABLE IF NOT EXISTS security_assets (
                asset_id TEXT PRIMARY KEY, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assets_seen ON security_assets(last_seen);
            CREATE TABLE IF NOT EXISTS security_asset_identities (
                interval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL REFERENCES security_assets(asset_id),
                kind TEXT NOT NULL, value TEXT NOT NULL, first_seen REAL NOT NULL,
                last_seen REAL NOT NULL, observations INTEGER NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_asset_identity_value
                ON security_asset_identities(kind, value, first_seen);
            CREATE INDEX IF NOT EXISTS idx_asset_identity_asset
                ON security_asset_identities(asset_id, kind, first_seen);
            CREATE TABLE IF NOT EXISTS security_asset_services (
                asset_id TEXT NOT NULL REFERENCES security_assets(asset_id),
                protocol TEXT NOT NULL, port INTEGER NOT NULL, first_seen REAL NOT NULL,
                last_seen REAL NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (asset_id, protocol, port)
            );
            CREATE TABLE IF NOT EXISTS security_asset_software (
                asset_id TEXT NOT NULL REFERENCES security_assets(asset_id),
                name TEXT NOT NULL, version TEXT NOT NULL, first_seen REAL NOT NULL,
                last_seen REAL NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (asset_id, name, version)
            );
            CREATE TABLE IF NOT EXISTS security_exposure_findings (
                finding_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL REFERENCES security_assets(asset_id),
                score INTEGER NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                observations INTEGER NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_exposure_rank
                ON security_exposure_findings(score, last_seen);
            CREATE INDEX IF NOT EXISTS idx_exposure_asset
                ON security_exposure_findings(asset_id);
            CREATE TRIGGER IF NOT EXISTS security_action_transition
            BEFORE UPDATE OF state ON security_response_actions
            WHEN OLD.state != NEW.state AND NOT (
                (OLD.state = 'requested' AND NEW.state IN ('approved', 'denied'))
                OR (OLD.state = 'approved' AND NEW.state IN ('applied', 'failed'))
                OR (OLD.state = 'applied' AND NEW.state IN ('released', 'expired'))
            )
            BEGIN
                SELECT RAISE(ABORT, 'illegal transition');
            END;
            CREATE TRIGGER IF NOT EXISTS security_action_no_delete
            BEFORE DELETE ON security_response_actions
            BEGIN
                SELECT RAISE(ABORT, 'response actions are durable');
            END;
            CREATE TRIGGER IF NOT EXISTS security_action_audit_no_update
            BEFORE UPDATE ON security_action_audit
            BEGIN
                SELECT RAISE(ABORT, 'action audit is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS security_action_audit_no_delete
            BEFORE DELETE ON security_action_audit
            BEGIN
                SELECT RAISE(ABORT, 'action audit is append-only');
            END;
        """)
        # Older native rows have no recorded commit sequence. Backfill a stable
        # receipt-time ordering once; new rows receive their sequence atomically.
        # Probe with a plain read so every process start does not hold the
        # writer lock across a scan of the whole native ledger, and only until the
        # marker says it was done (the probe alone took 11 s per open on the sensor VM).
        if self.cursor(ORDER_BACKFILL_KEY) is None:
            if self._read("""SELECT 1 FROM security_source_events s WHERE NOT EXISTS
                    (SELECT 1 FROM security_source_order o WHERE o.event_id=s.event_id) LIMIT 1"""):
                with self._transaction():
                    self.conn.execute("""INSERT INTO security_source_order(event_id)
                        SELECT s.event_id FROM security_source_events s
                        LEFT JOIN security_source_order o ON o.event_id=s.event_id
                        WHERE o.event_id IS NULL ORDER BY s.received_at, s.event_id""")
            try:
                self.checkpoint(ORDER_BACKFILL_KEY, {"done": True})
            except sqlite3.OperationalError:
                pass  # busy store: the next open probes again
        if path != ":memory:":
            # Started last: a constructor that raises above must not leave a thread (and the
            # store it references) running, since the gap-transfer thread retries every second.
            self._checkpointer = threading.Event()
            threading.Thread(target=self._checkpoint_wal, args=(self._checkpointer,),
                             name="security-wal-checkpoint", daemon=True).start()

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self.conn.in_transaction:
                yield  # Joins the caller's batch; the outermost transaction commits or rolls back.
                return
            # Started before BEGIN: a thread start under the lock cost the GIL-bound capture process seconds.
            watchdog = threading.Timer(SLOW_WRITE_SEC, _warn_still_holding, (threading.get_ident(), self))
            watchdog.daemon = True
            watchdog.start()
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                began = time.monotonic()
                self._holding = True
                try:
                    yield
                    self.conn.execute("COMMIT")
                except BaseException:
                    if self.conn.in_transaction:
                        self.conn.execute("ROLLBACK")
                    raise
                finally:
                    self._holding = False
                    _warn_slow_write(time.monotonic() - began)
            finally:
                watchdog.cancel()

    def _read(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def _write_case(self, key, body):
        self.conn.execute("""
            INSERT INTO security_incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                severity=excluded.severity, status=excluded.status,
                last_seen=excluded.last_seen, body=excluded.body
        """, (body["incident_id"], key, body["action"], body["target"],
              body["severity"], body["status"], body["last_seen"], _encode(body)))

    def _audit(self, incident_id, operation, body, actor, now):
        self.conn.execute("""
            INSERT INTO security_case_audit
            (incident_id, timestamp, actor, operation, body) VALUES (?, ?, ?, ?, ?)
        """, (incident_id, now, actor, operation, _encode(body)))

    def add(self, payload, severity=None, now=None):
        with self._transaction():
            return self._add(payload, severity=severity, now=now)

    def _add(self, payload, severity=None, now=None):
        key = IncidentStore.correlation_key(payload)
        if key is None:
            return None
        encoded = _encode(payload)
        if len(encoded.encode("utf-8")) > 1_048_576:
            raise ValueError("security detection exceeds one MiB")
        received = float(time.time() if now is None else now)
        if not math.isfinite(received):
            raise ValueError("receipt time must be finite")
        source_id = payload["data"].get("source_event_id") or payload["correlation_id"]
        if not isinstance(source_id, str) or not source_id.strip() or len(source_id) > 4096:
            raise ValueError("source event identity must be nonempty bounded text")
        if not payload["source"].strip() or len(payload["source"]) > 512:
            raise ValueError("source name must be nonempty bounded text")
        sensor_id = str(payload["data"].get("sensor_id") or self.sensor_id)
        identity = _encode([payload["source"], sensor_id, source_id, payload["action"]])
        event_id = hashlib.sha256(identity.encode()).hexdigest()
        correlation_key = _encode(key)
        duplicate = self.conn.execute(
            "SELECT payload, incident_id FROM security_detections WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if duplicate:
            if duplicate["payload"] != encoded:
                raise ValueError("source event identity reused with different content")
            return self.get(duplicate["incident_id"])
        existing = self.conn.execute(
            "SELECT body FROM security_incidents WHERE correlation_key=?", (correlation_key,),
        ).fetchone()
        previous = json.loads(existing["body"]) if existing else {}
        # Reuse the pure correlator on the stored candidates; persisted state is authoritative.
        correlator = IncidentStore(rules=self.rules, local_networks=self.local_networks)
        fields = detection_fields(payload, self.local_networks)
        bodies = {}
        if previous:
            correlator._incidents[key] = _incident(previous)
        elif self.rules and (fields["community_id"] or fields["asset"]):
            window = max(rule["window_sec"] for rule in self.rules)
            candidates = self.conn.execute("""
                SELECT k.received_at, c.correlation_key, c.body, d.payload FROM security_correlation_keys k
                JOIN security_incidents c ON c.incident_id=k.incident_id
                JOIN security_detections d ON d.event_id=k.event_id
                WHERE (k.community_id=? OR k.asset=?) AND k.source!=? AND k.received_at>=?
                AND c.status NOT IN ('Resolved','Recovered','Dismissed')
                ORDER BY k.received_at DESC LIMIT 100""", (fields["community_id"], fields["asset"],
                payload["source"], received - window)).fetchall()
            for row in reversed(candidates):
                candidate_key = tuple(json.loads(row["correlation_key"]))
                bodies[candidate_key] = json.loads(row["body"])
                correlator._incidents.setdefault(candidate_key, _incident(bodies[candidate_key]))
                correlator._recent.append((candidate_key, detection_fields(json.loads(row["payload"]),
                                           self.local_networks), row["received_at"]))
        case = correlator.add(payload, severity=severity, now=received)
        correlation = correlator.last_correlation
        if correlation:
            # The detection joins the stored case under that case's own key.
            key = next(k for k, v in correlator._incidents.items() if v.incident_id == case["incident_id"])
            correlation_key, previous = _encode(key), bodies[key]
        if not previous:
            case["incident_id"] = f"NW-{uuid.uuid4().hex}"
        for name, default in (("assignment", ""), ("acknowledged_by", ""),
                              ("closure_reason", "")):
            case[name] = previous.get(name, default)
        if previous.get("status") in _CLOSED_INCIDENT_STATUSES and case["status"] == "Open":
            case["closure_reason"] = ""
        self._write_case(correlation_key, case)
        self.conn.execute("""
            INSERT INTO security_detections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (event_id, payload["source"], source_id, sensor_id,
              _event_time(payload["data"].get("timestamp"), received), received,
              1, encoded, case["incident_id"]))
        self._audit(case["incident_id"], "detection", {"event_id": event_id},
                    payload["source"], received)
        if fields["community_id"] or fields["asset"]:
            self.conn.execute("INSERT INTO security_correlation_keys VALUES (?, ?, ?, ?, ?, ?)",
                              (event_id, case["incident_id"], payload["source"], received,
                               fields["community_id"], fields["asset"]))
        if correlation:
            self._audit(case["incident_id"], "correlation", {"event_id": event_id, **correlation},
                        payload["source"], received)
        return case

    def get(self, incident_id):
        rows = self._read(
            "SELECT body FROM security_incidents WHERE incident_id=?", (str(incident_id),),
        )
        row = rows[0] if rows else None
        return _case_body(row["body"]) if row else None

    def snapshot(self):
        # Cases survive display truncation; SQL bounds the read, not retention.
        rank = "CASE severity " + " ".join(
            f"WHEN '{name}' THEN {value}" for name, value in SEVERITY_RANK.items()
        ) + " ELSE 0 END"
        return [_case_body(row[0]) for row in self._read(
            f"SELECT body FROM security_incidents ORDER BY {rank} DESC, last_seen DESC LIMIT ?",
            (self.max_incidents,),
        )]

    def _count(self, critical=False):
        suffix = " AND severity='critical'" if critical else ""
        return self._read(
            "SELECT COUNT(*) FROM security_incidents WHERE status NOT IN "
            "('Resolved','Recovered','Dismissed')" + suffix,
        )[0][0]

    def open_count(self):
        return self._count()

    def critical_count(self):
        return self._count(critical=True)

    def update_case(self, incident_id, *, actor, status=None, response=None,
                    assignment=None, acknowledge=False, note=None, closure_reason=None):
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("case changes require an actor")
        if status is not None and status not in CASE_STATUSES:
            raise ValueError("unsupported case status")
        if status in {"Resolved", "Dismissed"} and not str(closure_reason or "").strip():
            raise ValueError("closing a case requires a reason")
        for value in (response, assignment, note, closure_reason):
            if value is not None and (not isinstance(value, str) or len(value) > 16_384):
                raise ValueError("case text must be a string of at most 16384 characters")
        with self._transaction():
            stored = self.conn.execute(
                "SELECT correlation_key, body FROM security_incidents WHERE incident_id=?",
                (str(incident_id),),
            ).fetchone()
            if not stored:
                return False
            case = json.loads(stored["body"])
            changes = {}
            for name, value in (("status", status), ("response", response),
                                ("assignment", assignment), ("closure_reason", closure_reason)):
                if value is not None:
                    changes[name] = value
            if acknowledge:
                changes["acknowledged_by"] = actor
            case.update(changes)
            self._write_case(stored["correlation_key"], case)
            if note is not None:
                changes["note"] = note
            self._audit(str(incident_id), "case_change", changes, actor, time.time())
            return True

    def set_incident_status(self, incident_id, status, response=None):
        return self.update_case(
            incident_id, actor="local-console", status=status, response=response,
            closure_reason=response or "Status changed by local console"
            if status in {"Resolved", "Dismissed"} else None,
        )

    def _set_matching_status(self, column, value, status, response):
        # column is supplied only by the two fixed public methods below.
        ids = [row[0] for row in self._read(
            f"SELECT incident_id FROM security_incidents WHERE {column}=? "
            "AND status NOT IN ('Resolved','Recovered','Dismissed')", (str(value),),
        )]
        return sum(self.set_incident_status(case_id, status, response) for case_id in ids)

    def set_target_status(self, target, status, response=None):
        return self._set_matching_status("target", _target_text(target), status, response)

    def set_action_status(self, action, status, response=None):
        return self._set_matching_status("action", action, status, response)

    def link(self, incident_id, kind, reference, *, actor):
        if kind not in {"detection", "evidence", "asset", "response"}:
            raise ValueError("unsupported case link")
        if not isinstance(reference, str) or not reference or len(reference) > 4096:
            raise ValueError("case reference must be nonempty bounded text")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("case links require an actor")
        with self._transaction():
            inserted = self.conn.execute("INSERT OR IGNORE INTO security_case_links VALUES (?, ?, ?)",
                                         (str(incident_id), kind, reference)).rowcount
            if inserted:
                self._audit(str(incident_id), "link", {"kind": kind, "reference": reference},
                            actor, time.time())
            return bool(inserted)

    def audit(self, incident_id, limit=300):
        rows = self._read(
            "SELECT * FROM security_case_audit WHERE incident_id=? ORDER BY sequence DESC LIMIT ?",
            (str(incident_id), max(1, min(10_000, int(limit)))),
        )
        return [dict(row) | {"body": json.loads(row["body"])} for row in reversed(rows)]

    def detections(self, incident_id, limit=1000):
        rows = self._read(
            "SELECT * FROM security_detections WHERE incident_id=? ORDER BY received_at DESC LIMIT ?",
            (str(incident_id), max(1, min(10_000, int(limit)))),
        )
        return [dict(row) | {"payload": json.loads(row["payload"])} for row in reversed(rows)]

    def _read_in(self, sql, values):
        values = list(dict.fromkeys(values))
        return self._read(sql.format(",".join("?" * len(values))), values) if values else []

    def case_audit_after(self, after, limit):
        return self._read("SELECT * FROM security_case_audit WHERE sequence>? ORDER BY sequence LIMIT ?",
                          (after, limit))

    def action_audit_after(self, after, limit):
        return self._read("SELECT * FROM security_action_audit WHERE sequence>? ORDER BY sequence LIMIT ?",
                          (after, limit))

    def feed(self, after_case=0, after_action=0, limit=200):
        """Every case and action change after two audit cursors, for a remote console's cache.

        reset=True means a cursor ran past this store (rebuilt or pruned): the reader
        must drop what it holds and resync from zero, which this reply already starts.
        """
        limit = max(1, min(1000, int(limit)))
        high_case = self._read("SELECT COALESCE(MAX(sequence), 0) FROM security_case_audit")[0][0]
        high_action = self._read("SELECT COALESCE(MAX(sequence), 0) FROM security_action_audit")[0][0]
        reset = after_case > high_case or after_action > high_action
        if reset:
            after_case = after_action = 0
        case_audit = [dict(row) | {"body": json.loads(row["body"])} for row in self.case_audit_after(after_case, limit)]
        action_audit = [dict(row) | {"body": json.loads(row["body"])}
                        for row in self.action_audit_after(after_action, limit)]
        cases = [_case_body(row["body"]) for row in self._read_in(
            "SELECT body FROM security_incidents WHERE incident_id IN ({})", [row["incident_id"] for row in case_audit])]
        detections = [dict(row) | {"payload": json.loads(row["payload"])} for row in self._read_in(
            "SELECT * FROM security_detections WHERE event_id IN ({})",
            [row["body"].get("event_id") for row in case_audit if row["operation"] == "detection"])]
        actions = [_readback(json.loads(row["body"])) for row in self._read_in(
            "SELECT body FROM security_response_actions WHERE action_id IN ({})",
            [row["action_id"] for row in action_audit])]
        return {"cases": cases, "detections": detections, "actions": actions,
                "case_audit": case_audit, "action_audit": action_audit, "reset": reset,
                "cursor": f"{case_audit[-1]['sequence'] if case_audit else after_case}:"
                          f"{action_audit[-1]['sequence'] if action_audit else after_action}",
                "more": len(case_audit) == limit or len(action_audit) == limit}

    def get_action(self, action_id):
        rows = self._read(
            "SELECT body FROM security_response_actions WHERE action_id=?", (str(action_id),))
        if not rows:
            return None
        return _readback(json.loads(rows[0]["body"]))

    def list_actions(self, *, case_id=None, state=None, limit=1000):
        clauses, params = [], []
        if case_id is not None:
            clauses.append("case_id=?")
            params.append(str(case_id))
        if state is not None:
            clauses.append("state=?")
            params.append(str(state))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(1000, int(limit))))
        rows = self._read(
            "SELECT body FROM security_response_actions" + where +
            " ORDER BY requested_at, action_id LIMIT ?", params)
        return [_readback(json.loads(row["body"])) for row in rows]

    def action_audit(self, action_id, limit=300):
        rows = self._read(
            """SELECT sequence, action_id, timestamp, actor, operation, state, body
               FROM security_action_audit WHERE action_id=? ORDER BY sequence ASC LIMIT ?""",
            (str(action_id), max(1, min(10_000, int(limit)))),
        )
        return [dict(row) | {"body": json.loads(row["body"])} for row in rows]

    def rule_stats(self):
        """The loaded rule pack with per-rule join and false-positive closure counts.

        Counts are derived from retained case audit and case bodies, so they cover
        the case retention window, not all time.
        """
        rules = []
        for rule in self.rules:
            matches = self._read("""SELECT COUNT(*) FROM security_case_audit WHERE operation='correlation'
                AND json_extract(body,'$.rule')=?""", (rule["id"],))[0][0]
            false_positives = self._read("""SELECT COUNT(*) FROM security_incidents
                WHERE status IN ('Resolved','Dismissed')
                AND lower(json_extract(body,'$.closure_reason')) LIKE '%false positive%'
                AND EXISTS (SELECT 1 FROM json_each(body,'$.rules') WHERE value=?)""", (rule["id"],))[0][0]
            rules.append({**rule, "matches": matches, "false_positive_closures": false_positives})
        return {"pack_version": self.rule_pack["version"] if self.rule_pack else None, "rules": rules}

    @staticmethod
    def _hunt_filters(target, filters):
        allowed = HUNT_SOURCE_FILTERS if target == "source_events" else HISTORY_FILTERS
        if not isinstance(filters, dict) or set(filters) - set(allowed) or len(filters) > len(allowed):
            raise ValueError("unsupported hunt filter")
        for value in filters.values():
            if not (isinstance(value, str) and len(value) <= 256 or isinstance(value, int | float)
                    and not isinstance(value, bool) and math.isfinite(value)):
                raise ValueError("hunt filter values must be bounded scalars")
        return filters

    def create_hunt(self, name, target, filters, *, actor, limit=100, description=""):
        if not isinstance(name, str) or not HUNT_NAME.fullmatch(name):
            raise ValueError("hunt name must be 1-64 letters, digits, '.', '_' or '-'")
        if target not in {"source_events", "ledger"}:
            raise ValueError("hunt target must be source_events or ledger")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= HUNT_LIMIT:
            raise ValueError(f"hunt limit must be 1..{HUNT_LIMIT}")
        if not isinstance(description, str) or len(description) > 1024:
            raise ValueError("hunt description must be at most 1024 characters")
        body = {"name": name, "target": target, "filters": self._hunt_filters(target, filters),
                "limit": limit, "description": description, "created_by": actor}
        with self._transaction():
            if self.conn.execute("SELECT 1 FROM security_hunts WHERE name=?", (name,)).fetchone():
                raise ValueError("hunt already exists")
            self.conn.execute("INSERT INTO security_hunts VALUES (?, ?, ?, ?)",
                              (name, time.time(), actor, _encode(body)))
        return body

    def list_hunts(self):
        return [json.loads(row[0]) for row in self._read("SELECT body FROM security_hunts ORDER BY name LIMIT 1000")]

    def run_hunt(self, name, params=None, *, actor, ledger_path=None):
        """Run a saved hunt; ``params`` override its filters. One audit row per run."""
        rows = self._read("SELECT body FROM security_hunts WHERE name=?", (str(name),))
        if not rows:
            raise ValueError("unknown hunt")
        hunt = json.loads(rows[0][0])
        filters = {**hunt["filters"], **self._hunt_filters(hunt["target"], params or {})}
        if hunt["target"] == "ledger":
            history = HistoryStore(ledger_path) if ledger_path else None
            try:
                results = history.query(filters, limit=hunt["limit"]) if history else []
            finally:
                if history:
                    history.close()
        else:
            where = " AND ".join(HUNT_SOURCE_FILTERS[key] for key in filters)  # Fixed fragments only.
            results = [dict(row) | {"normalized": json.loads(row["normalized"])} for row in self._read(
                "SELECT event_id, source, sensor_id, event_type, event_time, received_at, normalized "
                "FROM security_source_events" + (" WHERE " + where if where else "")
                + " ORDER BY received_at DESC LIMIT ?", (*filters.values(), hunt["limit"]))]
        with self._transaction():
            self.conn.execute("INSERT INTO security_hunt_runs(name, timestamp, actor, body) VALUES (?, ?, ?, ?)",
                              (hunt["name"], time.time(), actor,
                               _encode({"filters": filters, "rows": len(results)})))
        return {"hunt": hunt["name"], "target": hunt["target"], "filters": filters,
                "limit": hunt["limit"], "rows": results}

    def hunt_runs(self, name, limit=100):
        return [dict(row) | {"body": json.loads(row["body"])} for row in self._read(
            "SELECT * FROM security_hunt_runs WHERE name=? ORDER BY sequence DESC LIMIT ?",
            (str(name), max(1, min(1000, int(limit)))))]

    WAL_CHECKPOINT_SEC = 5.0
    SPOOL_GAP_DETECTION_SEC = 60.0

    def _checkpoint_wal(self, stop):
        conn = sqlite3.connect(self.path, isolation_level=None, timeout=0, check_same_thread=False)
        conn.execute(f"PRAGMA journal_size_limit={WAL_MAX_BYTES}")
        last_error = None
        try:
            while not stop.wait(self.WAL_CHECKPOINT_SEC):
                try:  # PASSIVE never blocks writers; a busy result just waits for the next turn.
                    conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                    last_error = None
                except sqlite3.Error as exc:
                    if str(exc) != last_error:  # on change only: this runs every 5 s
                        last_error = str(exc)
                        _component_logger().warning("WAL checkpoint failed: %s", exc)
        finally:
            conn.close()

    def close(self):
        if self._checkpointer is not None:
            self._checkpointer.set()
        with self._lock:
            self.conn.close()

    def cursor(self, source_key):
        rows = self._read("SELECT body FROM security_source_cursors WHERE source_key=?", (source_key,))
        return json.loads(rows[0][0]) if rows else None

    def channel_has_cursor(self, channel):
        return bool(self._read("SELECT 1 FROM security_source_cursors WHERE body LIKE ? LIMIT 1",
                               ('%"channel":"' + channel + '"%',)))

    def channel_cursors(self, channel):
        rows = self._read("SELECT source_key, body FROM security_source_cursors WHERE body LIKE ?",
                          ('%"channel":"' + channel + '"%',))
        return [(key, json.loads(body)) for key, body in rows]

    def checkpoint(self, source_key, cursor):
        with self._transaction():
            self._checkpoint(source_key, cursor)

    def initialize_cursor(self, source_key, cursor):
        with self._transaction():
            self.conn.execute("INSERT OR IGNORE INTO security_source_cursors VALUES (?, ?)",
                              (source_key, _encode(cursor)))
            return self.cursor(source_key)

    def _checkpoint(self, source_key, cursor):
        self.conn.execute("""INSERT INTO security_source_cursors VALUES (?, ?)
                             ON CONFLICT(source_key) DO UPDATE SET body=excluded.body""",
                          (source_key, _encode(cursor)))

    def accept_source_record(self, source_key, cursor, normalized, native, detection=None):
        """Atomically accept native evidence, optional finding and next file offset."""
        encoded = _encode(normalized)
        raw = json.dumps(native, default=_json_default, allow_nan=False,
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if len(raw.encode("utf-8")) > 1_048_576:
            raise ValueError("native record exceeds one MiB")
        with self._transaction():
            pruned = self.conn.execute("SELECT native_sha256 FROM security_native_pruned WHERE event_id=?",
                                       (normalized["event_id"],)).fetchone()
            if pruned:
                if pruned[0] != hashlib.sha256(raw.encode()).hexdigest():
                    raise ValueError("pruned source identity reused with different content")
                self._checkpoint(source_key, cursor)
                return False
            existing = self.conn.execute(
                "SELECT native FROM security_source_events WHERE event_id=?",
                (normalized["event_id"],),
            ).fetchone()
            if existing and existing[0] != raw:
                raise ValueError("native source identity reused with different content")
            if not existing:
                self.conn.execute("INSERT INTO security_source_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                  (normalized["event_id"], normalized["source"], normalized["sensor_id"],
                                   normalized["event_type"], normalized["event_time"],
                                   normalized["received_at"], encoded, raw))
                self.conn.execute("INSERT INTO security_source_order(event_id) VALUES (?)", (normalized["event_id"],))
                if detection is not None:
                    self._add(detection, now=normalized["received_at"])
            self._checkpoint(source_key, cursor)
        return not bool(existing)

    def native_hold(self, event_id, *, actor, reason, enabled=True):
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 512:
            raise ValueError("a native hold requires an actor")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 4096:
            raise ValueError("a native hold requires a bounded reason")
        with self._transaction():
            if not self.conn.execute("SELECT 1 FROM security_source_events WHERE event_id=?", (event_id,)).fetchone():
                raise ValueError("native record is unavailable")
            if enabled:
                self.conn.execute("INSERT INTO security_native_holds VALUES (?,?,?) ON CONFLICT(event_id) "
                                  "DO UPDATE SET actor=excluded.actor, reason=excluded.reason", (event_id, actor, reason))
            else:
                self.conn.execute("DELETE FROM security_native_holds WHERE event_id=?", (event_id,))
            self.conn.execute("INSERT INTO security_native_audit(timestamp,actor,operation,body) VALUES (?,?,?,?)",
                              (time.time(), actor, "hold" if enabled else "release", _encode({"event_id": event_id, "reason": reason})))

    def native_retention_status(self, event_id):
        held = self._read("SELECT actor,reason FROM security_native_holds WHERE event_id=?", (event_id,))
        pruned = self._read("SELECT pruned_at,body FROM security_native_pruned WHERE event_id=?", (event_id,))
        audit = self._read("""SELECT * FROM security_native_audit WHERE
            json_extract(body,'$.event_id')=? OR EXISTS
            (SELECT 1 FROM json_each(body,'$.event_ids') WHERE value=?)
            ORDER BY sequence DESC LIMIT 100""", (event_id, event_id))
        return {"hold": dict(held[0]) if held else None,
                "pruned": {"pruned_at": pruned[0]["pruned_at"], **json.loads(pruned[0]["body"])} if pruned else None,
                "audit": [dict(row) | {"body": json.loads(row["body"])} for row in reversed(audit)]}

    def prune_control_records(self, *, max_rows=200_000, max_bytes=268_435_456, retention_days=7,
                              arp_enabled=True, batch=128, totals=None, now=None):
        return self.prune_native_records("CONTROL", max_rows=max_rows, max_bytes=max_bytes,
                                         retention_days=retention_days, arp_enabled=arp_enabled,
                                         batch=batch, totals=totals, now=now)

    def prune_native_records(self, source, *, max_rows, max_bytes, retention_days, arp_enabled=False,
                             batch=128, totals=None, now=None):
        """Bounded payload retention for one native source; pins win over quota targets.

        ``totals`` is the (rows, payload_bytes) a previous call of the same pass
        returned, so a backlog drained over many turns scans the payloads once.
        """
        now = time.time() if now is None else float(now)
        if not math.isfinite(now) or any(not math.isfinite(float(v)) or float(v) < 0
                                        for v in (max_rows, max_bytes, retention_days)):
            raise ValueError("retention limits and time must be finite and nonnegative")
        # The quota scan reads every native payload byte; it and the candidate
        # windows run as plain reads so the shared writer lock is held only for
        # the deletes, never across a cold-cache scan of the ledger.
        rows, size = totals or self._read(
            # octet_length reads only the record header, not each payload's overflow pages (same byte count).
            "SELECT COUNT(*), COALESCE(SUM(octet_length(native)+"
            # Gap rows are never pruned, so counting them could hold a source over quota for good.
            "octet_length(normalized)),0) FROM security_source_events WHERE source=? AND event_type!='collector_gap'",
            (source,))[0]
        over = (max_rows > 0 and rows > max_rows) or (max_bytes > 0 and size > max_bytes)
        # Retained packet evidence names its triggering native record. Uncorrelated, so the catalog's
        # JSON is read once per window rather than once per candidate (215 ms per 16 rows on the sensor).
        evidence_pin = """AND s.event_id NOT IN (SELECT json_extract(t.value,'$.source_event_id')
                    FROM evidence_items e, json_each(e.body,'$.triggers') t WHERE e.status!='pruned'
                    AND json_extract(t.value,'$.source_event_id') IS NOT NULL)"""
        # EVE restores health from the newest record of each type at startup.
        # rowid DESC matches source_events()' backward index scan on receipt-time ties.
        newest_pin = ("""AND s.event_id != (SELECT n.event_id FROM security_source_events n
                    WHERE n.source=s.source AND n.sensor_id=s.sensor_id AND n.event_type=s.event_type
                    ORDER BY n.received_at DESC, n.rowid DESC LIMIT 1)"""
                      if source != "CONTROL" else "")
        # Pins run only on a bounded window of the oldest candidates: checked against every
        # row of an over-quota source, they held one read for hours on the sensor VM.
        query = """SELECT s.*, w.sequence, (1
                AND NOT EXISTS (SELECT 1 FROM security_native_holds h WHERE h.event_id=s.event_id)
                AND NOT EXISTS (SELECT 1 FROM security_case_links l WHERE l.kind='native' AND l.reference=s.event_id)
                AND NOT EXISTS (SELECT 1 FROM security_source_cursors c, json_each(c.body,'$.bindings') b
                    WHERE c.source_key LIKE 'ARP_STATE:v1:%'
                    AND json_extract(b.value,'$.native_event_id')=s.event_id)
                AND NOT EXISTS (SELECT 1 FROM security_source_cursors c, json_each(c.body,'$.pending_rebinds') p,
                    json_each(p.value,'$.native_event_ids') n WHERE c.source_key LIKE 'ARP_STATE:v1:%' AND n.value=s.event_id)
                AND NOT EXISTS (SELECT 1 FROM security_detections d CROSS JOIN security_incidents c
                    ON c.incident_id=d.incident_id WHERE d.source_event_id=s.event_id AND d.sensor_id=s.sensor_id
                    AND c.status NOT IN ('Resolved','Recovered','Dismissed'))
                AND NOT EXISTS (SELECT 1 FROM security_detections d CROSS JOIN security_incidents c
                    ON c.incident_id=d.incident_id WHERE CAST(json_extract(d.payload,'$.data.native_event_id') AS TEXT)=s.event_id
                    AND c.status NOT IN ('Resolved','Recovered','Dismissed'))
                AND s.event_id NOT IN (SELECT n.value FROM security_detections d CROSS JOIN security_incidents c
                    ON c.incident_id=d.incident_id, json_each(d.payload,'$.data.native_event_ids') n
                    WHERE json_type(d.payload,'$.data.native_event_ids') IS NOT NULL
                    AND c.status NOT IN ('Resolved','Recovered','Dismissed') AND n.value IS NOT NULL)
                {evidence_pin} {newest_pin}) AS prunable
                FROM (SELECT o.sequence, o.event_id FROM security_source_order o {join} security_source_events s
                    ON s.event_id=o.event_id WHERE o.sequence>? AND s.source=? AND s.event_type!='collector_gap' {only}
                    AND (? OR (? > 0 AND s.received_at < ?))
                    AND NOT (? AND s.event_type='arp' AND o.sequence>?)
                    ORDER BY o.sequence LIMIT ?) w
                CROSS JOIN security_source_events s ON s.event_id=w.event_id ORDER BY w.sequence"""
        limit = max(1, min(1000, int(batch)))

        def select(only="", ids=(), after=0):
            cursor = self.cursor("ANALYSIS:ARP:v1") or {"sequence": 0}
            # Over quota every row is a candidate, so walk the order table from the oldest and stop
            # at the window; under quota only expired rows qualify and the source index finds them.
            # The re-check seeks its ids through the order table instead of rescanning the source.
            sql = query.format(only=only, evidence_pin=evidence_pin, newest_pin=newest_pin,
                               join="CROSS JOIN" if over or only else "JOIN")
            picked, first = [], None
            while True:
                with self._lock:
                    window = self.conn.execute(sql, (after, source, *ids, int(bool(over)), retention_days,
                                                     now - retention_days * 86400, int(bool(arp_enabled)),
                                                     int(cursor["sequence"]), limit)).fetchall()
                if first is None and window:
                    first = window[0]["sequence"]
                picked += [row for row in window if row["prunable"]]
                if len(picked) >= limit or len(window) < limit:
                    if over and not only and first is not None:
                        # Over quota the walk starts at the source's oldest candidate, pinned or not, so
                        # the next pass need not re-walk the other sources' rows below it (264k SURICATA
                        # order rows, 5 s a batch, on the sensor). ARP rows past the cursor are filtered out
                        # now but qualify once it advances, so the floor never passes the cursor.
                        self._prune_floor[source] = min(first - 1, int(cursor["sequence"])) if arp_enabled \
                            else first - 1
                    return picked[:limit]
                after = window[-1]["sequence"]  # A fully pinned window is stepped past, never re-read.

        first_pass = select(after=self._prune_floor.get(source, 0) if over else 0)
        ids = [row["event_id"] for row in first_pass]
        if not ids:
            return {"rows": rows, "payload_bytes": size, "pruned": 0,
                    "over_quota": bool(over), "protected_or_pending": bool(over)}
        with self._transaction():
            # Re-check the pins under the lock: a hold or binding may have landed since.
            candidates = select(f"AND o.event_id IN ({','.join('?' * len(ids))})", ids,
                                after=min(row["sequence"] for row in first_pass) - 1)
            removed = []
            for row in candidates:
                expired = retention_days > 0 and row["received_at"] < now - retention_days * 86400
                over = (max_rows > 0 and rows > max_rows) or (max_bytes > 0 and size > max_bytes)
                if not expired and not over:
                    continue
                digest = hashlib.sha256(row["native"].encode()).hexdigest()
                body = {"source": row["source"], "sensor_id": row["sensor_id"], "event_type": row["event_type"],
                        "event_time": row["event_time"], "received_at": row["received_at"], "sequence": row["sequence"],
                        "reason": "age" if expired else "quota", "native_sha256": digest}
                if source != "CONTROL":
                    # CONTROL ids are random per frame, so a tombstone can never catch a replay; at
                    # ~270k prunes an hour on the sensor they outgrew what metadata retention removes.
                    # The batch's prune audit below still names every pruned id.
                    self.conn.execute("INSERT INTO security_native_pruned VALUES (?,?,?,?)",
                                      (row["event_id"], digest, now, _encode(body)))
                self.conn.execute("DELETE FROM security_source_events WHERE event_id=?", (row["event_id"],))
                # Readers only join order rows to live events; the tombstone keeps the sequence.
                self.conn.execute("DELETE FROM security_source_order WHERE event_id=?", (row["event_id"],))
                rows -= 1
                size -= len(row["native"].encode()) + len(row["normalized"].encode())
                removed.append(row["event_id"])
            if removed:
                self.conn.execute("INSERT INTO security_native_audit(timestamp,actor,operation,body) VALUES (?,?,?,?)",
                                  (now, f"{source.lower()}-retention", "prune", _encode({"source": source, "event_ids": removed,
                                   "max_rows": max_rows, "max_bytes": max_bytes, "retention_days": retention_days})))
            over = (max_rows > 0 and rows > max_rows) or (max_bytes > 0 and size > max_bytes)
            return {"rows": rows, "payload_bytes": size, "pruned": len(removed),
                    "over_quota": bool(over), "protected_or_pending": bool(over and not removed)}

    def prune_metadata(self, *, retention_days=30, case_retention_days=365, batch_rows=1000,
                       max_batches=None, native_retention_days=0, now=None):
        """Bounded deletes of metadata that otherwise grows without limit.

        Each batch is its own short transaction, like ``prune_network_events``.
        Tombstones and prune audit age out after
        ``retention_days``; SURICATA and CONTROL tombstones and prune audit after the
        shorter ``native_retention_days`` when it is set. Closed cases older than ``case_retention_days`` go
        with their detections, audit and links unless a response action, a
        retained (unpruned) evidence link or a native hold pins them. Open cases,
        holds, hold audit, actions and spool gaps are never deleted here.
        Returns ``(removed, more_pending)``.
        """
        now = time.time() if now is None else float(now)
        batch_rows = max(1, int(batch_rows))
        budget = float("inf") if max_batches is None else max(1, int(max_batches))
        # Linked evidence pins its case until the catalog records the payload as pruned.
        evidence_pin = ("AND NOT EXISTS (SELECT 1 FROM evidence_items e WHERE e.evidence_id=l.reference "
                        "AND e.status='pruned')")
        case = f"""c.status IN ('Resolved','Recovered','Dismissed') AND c.last_seen < :case_cutoff
            AND NOT EXISTS (SELECT 1 FROM security_response_actions a WHERE a.case_id=c.incident_id)
            AND NOT EXISTS (SELECT 1 FROM security_case_links l WHERE l.incident_id=c.incident_id
                AND l.kind='evidence' {evidence_pin})
            AND NOT EXISTS (SELECT 1 FROM security_native_holds h CROSS JOIN security_detections d
                WHERE d.source_event_id=h.event_id AND d.incident_id=c.incident_id)
            AND NOT EXISTS (SELECT 1 FROM security_native_holds h CROSS JOIN security_detections d
                WHERE CAST(json_extract(d.payload,'$.data.native_event_id') AS TEXT)=h.event_id AND d.incident_id=c.incident_id)
            AND NOT EXISTS (SELECT 1 FROM security_detections d, json_each(d.payload,'$.data.native_event_ids') n
                WHERE d.incident_id=c.incident_id AND json_type(d.payload,'$.data.native_event_ids') IS NOT NULL
                AND n.value IN (SELECT event_id FROM security_native_holds))"""
        statements = []
        if retention_days > 0:
            statements += [
                """DELETE FROM security_native_pruned WHERE event_id IN (SELECT event_id
                   FROM security_native_pruned WHERE pruned_at < :native_cutoff AND (pruned_at < :cutoff
                   OR json_extract(body,'$.source') IN ('SURICATA','CONTROL')) LIMIT :limit)""",
                """DELETE FROM security_native_audit WHERE sequence IN (SELECT sequence
                   FROM security_native_audit WHERE operation='prune' AND timestamp < :native_cutoff
                   AND (timestamp < :cutoff OR json_extract(body,'$.source') IN ('SURICATA','CONTROL'))
                   ORDER BY sequence LIMIT :limit)""",
            ]
        if case_retention_days > 0:
            # The uncorrelated IN list is evaluated once per batch, not per child row.
            statements += [f"""DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table}
                WHERE incident_id IN (SELECT c.incident_id FROM security_incidents c WHERE {case})
                LIMIT :limit)""" for table in ("security_correlation_keys", "security_detections",
                                                "security_case_audit", "security_case_links")]
            statements.append(f"""DELETE FROM security_incidents WHERE incident_id IN (SELECT c.incident_id
                FROM security_incidents c WHERE {case}
                AND NOT EXISTS (SELECT 1 FROM security_detections d WHERE d.incident_id=c.incident_id)
                AND NOT EXISTS (SELECT 1 FROM security_correlation_keys x WHERE x.incident_id=c.incident_id)
                AND NOT EXISTS (SELECT 1 FROM security_case_audit x WHERE x.incident_id=c.incident_id)
                AND NOT EXISTS (SELECT 1 FROM security_case_links x WHERE x.incident_id=c.incident_id)
                LIMIT :limit)""")
        # SURICATA and CONTROL prune thousands of records a minute. SURICATA's file cursors already
        # deduplicate replay and CONTROL ids are random per frame, so neither tombstone needs a long
        # window: CONTROL's reached 430k rows in four days on the sensor (2026-10-12).
        native_days = min(retention_days, native_retention_days or retention_days)
        params = {"cutoff": now - retention_days * 86400, "native_cutoff": now - native_days * 86400,
                  "case_cutoff": now - case_retention_days * 86400,
                  "limit": batch_rows}
        removed = batches = 0
        # CONTROL tombstones are no longer written; clear the ones left from before in large
        # batches, whatever their age (~490k on the sensor, 2026-10-12), so they never wait 30 days.
        # The scan reads every tombstone under the writer lock (0.6 s a turn on the sensor), so it stops once
        # a pass finds the table clean; CONTROL writes no new ones.
        for _ in range(0 if self._legacy_tombstones_done else 5):
            with self._transaction():
                count = self.conn.execute("""DELETE FROM security_native_pruned WHERE event_id IN
                    (SELECT event_id FROM security_native_pruned
                     WHERE json_extract(body,'$.source') = 'CONTROL' LIMIT ?)""", (LEGACY_TOMBSTONE_BATCH,)).rowcount or 0
            removed += count
            if count < LEGACY_TOMBSTONE_BATCH:
                self._legacy_tombstones_done = True
                break
        else:
            if not self._legacy_tombstones_done:
                return removed, True
        for sql in statements:
            while True:
                with self._transaction():
                    count = self.conn.execute(sql, params).rowcount or 0
                removed += count
                if count < batch_rows:
                    break
                batches += 1  # Only a full batch can leave work behind.
                if batches >= budget:
                    return removed, True
        return removed, False

    def source_events(self, source=None, *, sensor_id=None, event_type=None, event_id=None,
                      community_id=None, limit=100, include_native=True):
        clauses = []
        values = []
        for key, value in (("source", source), ("sensor_id", sensor_id), ("event_type", event_type),
                           ("event_id", event_id),
                           # Must match idx_source_events_community's expression to use it.
                           ("json_extract(normalized, '$.community_id')", community_id)):
            if value is not None:
                clauses.append(f"{key}=?")
                values.append(value)
        values.append(max(1, min(10_000, int(limit))))
        columns = "*" if include_native else "event_id, source, sensor_id, event_type, event_time, received_at, normalized"
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        # Unfiltered, no index leads with received_at: the sort scanned the whole native
        # ledger under the store lock and stalled every API read (/v1/health too) on the sensor.
        # The newest commit sequences are the newest receipts, so sort only that window.
        sql = (f"SELECT {columns} FROM security_source_events" + where + " ORDER BY received_at DESC LIMIT ?"
               if clauses else
               f"""SELECT * FROM (SELECT {', '.join('s.' + c.strip() for c in columns.split(','))}, o.sequence
                   FROM security_source_order o CROSS JOIN security_source_events s ON s.event_id=o.event_id
                   ORDER BY o.sequence DESC LIMIT ?) ORDER BY received_at DESC, sequence DESC""")
        return [{k: row[k] for k in row.keys() if k != "sequence"} | {"normalized": json.loads(row["normalized"])}
                | ({"native": json.loads(row["native"])} if include_native else {}) for row in self._read(sql, values)]

    def source_stream(self, source, event_type, after=0, limit=32):
        """A stable commit sequence, independent of source/receipt clock ordering."""
        while True:
            rows, scanned_to = self.source_stream_page(source, event_type, after, limit)
            if rows or scanned_to == after:
                return rows
            after = scanned_to

    STREAM_SCAN_WINDOW = 10_000

    def source_stream_page(self, source, event_type, after=0, limit=32):
        """``(rows, scanned_to)``: rows after ``after`` in commit order, and the sequence the scan
        covered. Walks the order table forward from the cursor, so cost tracks unread records,
        not retained ones; a consumer checkpoints ``scanned_to`` to step over other streams' rows.
        """
        after, limit = int(after), max(1, min(1000, int(limit)))
        # Committed sequences form a gap-free prefix (writes serialize), so the
        # snapshot's maximum bounds what a later snapshot could add below it.
        top = self._read("SELECT COALESCE(MAX(sequence), 0) FROM security_source_order")[0][0]
        until = min(top, after + self.STREAM_SCAN_WINDOW)
        rows = [dict(row) | {"normalized": json.loads(row["normalized"]), "native": json.loads(row["native"])}
                for row in self._read("""SELECT o.sequence, s.* FROM security_source_order o
                    CROSS JOIN security_source_events s ON s.event_id=o.event_id
                    WHERE o.sequence>? AND o.sequence<=? AND s.source=? AND s.event_type=?
                    ORDER BY o.sequence LIMIT ?""", (after, until, source, event_type, limit))]
        return rows, (rows[-1]["sequence"] if len(rows) == limit else max(after, until))

    def record_source_health(self, source_key, body, now=None):
        with self._transaction():
            self.conn.execute("""INSERT INTO security_source_health VALUES (?, ?, ?)
                ON CONFLICT(source_key) DO UPDATE SET updated_at=excluded.updated_at, body=excluded.body""",
                              (source_key, time.time() if now is None else now, _encode(body)))

    def source_health(self, source_key):
        rows = self._read("SELECT updated_at, body FROM security_source_health WHERE source_key=?", (source_key,))
        return {"updated_at": rows[0][0], **json.loads(rows[0][1])} if rows else None

    def record_spool_gap(self, spool_id, gap):
        """The gap row is also the durable receipt for its cumulative revision."""
        body = {key: value for key, value in gap.items() if key != "transferred_batches"}
        body["revision"] = gap["loss_batches"]
        if not gap["batch_count_exact"]:
            body["loss_batches"] = None
        # One gap row per reason grows every refused batch; the row keeps the exact count each
        # revision, but a sustained episode adds a detection at most once per interval.
        key = (spool_id, gap["gap_id"])
        last = self._gap_detected.get(key)
        detect = last is None or time.monotonic() - last >= self.SPOOL_GAP_DETECTION_SEC
        with self._transaction():
            receipt = self.conn.execute("""INSERT INTO security_spool_gaps VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(spool_id, gap_id) DO UPDATE SET
                loss_batches=excluded.loss_batches, body=excluded.body
                WHERE excluded.loss_batches>security_spool_gaps.loss_batches""",
                (spool_id, gap["gap_id"], gap["loss_batches"], gap["timestamp"],
                 _encode({**body, "spool_id": spool_id, "action": "SPOOL_COLLECTION_GAP",
                          "containment_eligible": False})))
            if receipt.rowcount and detect:
                self._add(make_message("DB_WORKER", "SPOOL_COLLECTION_GAP", "SYSTEM", {
                    **body,
                    "source_event_id": f"{spool_id}:{gap['gap_id']}:{gap['loss_batches']}",
                    "correlation_entity": hashlib.sha256(_encode([spool_id, gap["gap_id"]]).encode()).hexdigest(),
                    "message": f"Spool collection loss: {gap['reason']}; "
                               f"{gap['dropped_rows']} rows, {gap['dropped_observations']} observations "
                               f"in {body['loss_batches'] if body['loss_batches'] is not None else 'unknown'} batches (cumulative)",
                    "severity": "critical", "containment_eligible": False,
                }))
        if receipt.rowcount and detect:
            if len(self._gap_detected) >= 256:  # each corrupt batch mints a gap id; an expired entry is a missing one
                cut = time.monotonic() - self.SPOOL_GAP_DETECTION_SEC
                self._gap_detected = {k: t for k, t in self._gap_detected.items() if t > cut}
            self._gap_detected[key] = time.monotonic()

    def spool_gaps(self, limit=1000):
        return [json.loads(row[0]) for row in self._read(
            "SELECT body FROM security_spool_gaps ORDER BY timestamp DESC LIMIT ?", (limit,))]
