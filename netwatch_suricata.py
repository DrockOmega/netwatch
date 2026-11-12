"""Optional adapter for Suricata's EVE JSON event stream."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import sqlite3
import time

from netwatch_core import (
    DISK_MIN_FREE_BYTES,
    compile_v4_prefixes,
    compile_v6_prefixes,
    disk_admission,
    is_local_ip,
    make_message,
    try_put_drop_oldest,
    try_put_no_drop,
)
from netwatch_log import setup_logging
from netwatch_security_store import _event_time, security_store_from_config
from netwatch_sources import JSONLinesReader


def eve_freshness_status(timestamp, now, timeout_sec):
    if isinstance(timestamp, bool) or timestamp is None:
        return "UNVERIFIED"
    try:
        age = float(now) - float(timestamp)
    except (TypeError, ValueError, OverflowError):
        return "UNVERIFIED"
    if not math.isfinite(age):
        return "UNVERIFIED"
    return "CLOCK_SKEW" if age < -5 else "STALE" if age > timeout_sec else "FRESH"


def apply_lag(status, readers, now, window_sec, event_time):
    """Tell a collector that is behind a growing file from an engine that stopped writing.

    STALE with unread bytes in a file written within ``window_sec`` becomes LAGGING; every other
    status keeps its meaning. Returns (status, fields merged into the health row)."""
    lags = [reader.lag(now) for reader in readers]
    ages = [age for _, age in lags if age is not None]
    file_age = min(ages, default=None)
    growing = file_age is not None and file_age <= window_sec
    lag_bytes = sum(behind for behind, _ in lags)
    if status == "STALE" and lag_bytes > 0 and growing:
        status = "LAGGING"
    return status, {"lag_bytes": lag_bytes, "file_age_sec": file_age, "file_growing": growing,
                    "lag_sec": None if event_time is None else now - event_time}


def classify_endpoints(src_ip, dst_ip, local_networks=()):
    """Return (source, destination, direction, target, offender) for one record.

    ``target`` is packed bytes only when a single offending address is
    unambiguous; otherwise it is "SYSTEM" and containment must not be offered.
    """
    v4 = compile_v4_prefixes(local_networks)
    v6 = compile_v6_prefixes(local_networks)
    try:
        src_address = ipaddress.ip_address(str(src_ip))
        dst_address = ipaddress.ip_address(str(dst_ip))
    except ValueError:
        src_address = dst_address = None
    src_local = bool(src_address and is_local_ip(src_address.packed, v4, v6))
    dst_local = bool(dst_address and is_local_ip(dst_address.packed, v4, v6))
    if src_local and not dst_local:
        direction, target, offender = "egress", dst_address, src_address
    elif not src_local and dst_local:
        direction, target, offender = "ingress", src_address, src_address
    elif src_local and dst_local:
        direction, target, offender = "lateral", src_address, src_address
    else:
        direction, target, offender = "ambiguous", None, None
    try:
        target = target.packed if target is not None else "SYSTEM"
    except (AttributeError, ValueError):
        target = "SYSTEM"
    return src_address, dst_address, direction, target, offender


# Priority-1 rules that only describe the traffic (app/OS identification, policy) stay "alert".
_INFORMATIONAL_PREFIXES = ("ET INFO ", "ET POLICY ", "ET USER_AGENTS ", "ET HUNTING ", "ET GAMES ",
                           "ET CHAT ", "ET P2P ", "GPL INFO ", "GPL POLICY ")


_POLICY_CATEGORY = "Potential Corporate Privacy Violation"


def _informational(signature, category):
    return signature.startswith(_INFORMATIONAL_PREFIXES) or category == _POLICY_CATEGORY


def _mitre(alert):
    """ET rule metadata (alert.metadata.mitre_*, lists of strings) as up to 5 attack tags."""
    meta = alert.get("metadata") if isinstance(alert.get("metadata"), dict) else {}

    def values(name):
        raw = meta.get(name)
        raw = raw if isinstance(raw, list) else [raw]
        return [str(v).replace("_", " ")[:120] for v in raw if isinstance(v, str)]

    ids, names, tactics = values("mitre_technique_id"), values("mitre_technique_name"), values("mitre_tactic_name")
    return [{"technique_id": tid.replace(" ", "_"), "technique_name": names[i] if i < len(names) else "",
             "tactic": ", ".join(tactics)} for i, tid in enumerate(ids[:5])]


def normalize_eve_event(event, local_networks=()):
    """Convert one EVE alert/anomaly/drop record to NetWatch's IPC envelope."""
    if not isinstance(event, dict):
        return None
    event_type = str(event.get("event_type") or "").lower()
    if event_type not in {"alert", "anomaly", "drop"}:
        return None
    alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
    anomaly = event.get("anomaly") if isinstance(event.get("anomaly"), dict) else {}
    signature = str(alert.get("signature") or anomaly.get("event") or event_type)
    verdict = event.get("verdict") if isinstance(event.get("verdict"), dict) else {}
    action = str(alert.get("action") or verdict.get("action") or event_type).lower()
    severity_value = alert.get("severity")
    severity = "critical" if action in {"blocked", "drop", "reject"} else "alert"
    if severity == "alert" and alert.get("category") == _POLICY_CATEGORY:
        severity = "info"  # policy/app identification (Steam UA and the like), never a threat finding
    try:
        if int(severity_value) == 1 and not _informational(signature, alert.get("category")):
            severity = "critical"
    except (TypeError, ValueError, OverflowError):
        pass
    _, _, direction, target, offender = classify_endpoints(
        event.get("src_ip"), event.get("dest_ip"), local_networks)
    message = f"SURICATA {action.upper()}: {signature}"
    source_event_id = hashlib.sha256(json.dumps(
        event, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()
    return make_message(
        "SURICATA",
        "SURICATA_ALERT",
        target,
        {
            "source_event_id": source_event_id,
            "message": message,
            "severity": severity,
            "signature": signature,
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            "attack": _mitre(alert),
            "suricata_action": action,
            "flow_id": event.get("flow_id"),
            "community_id": event.get("community_id"),
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "dst_ip": event.get("dest_ip"),
            "dst_port": event.get("dest_port"),
            "app_proto": event.get("app_proto"),
            "timestamp": event.get("timestamp"),
            "direction": direction,
            "offender_ip": str(offender) if offender is not None else None,
            "containment_eligible": target != "SYSTEM",
        },
        correlation_id=source_event_id,
    )


def normalize_eve_record(event, *, event_id, sensor_id, reference, received_at, local_networks=()):
    """Retain native EVE and a versioned common envelope, without inventing data."""
    event_type = str(event.get("event_type") or "unknown").lower()
    category = {"alert": "detection", "anomaly": "detection", "drop": "detection",
                "flow": "network_session", "stats": "source_health",
                "collector_gap": "collection_gap", "collector_error": "collection_error"}.get(
                    event_type, "network_protocol")
    source, destination, direction, _, _ = classify_endpoints(
        event.get("src_ip"), event.get("dest_ip"), local_networks)
    family = source.version if source and source.version == destination.version else None
    ports = []
    for key in ("src_port", "dest_port"):
        value = event.get(key)
        ports.append(value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535 else None)
    source_time = _event_time(event.get("timestamp"), None)
    return {
        "schema_version": 1, "event_id": event_id, "source_event_id": event_id,
        "source": "SURICATA", "sensor_id": sensor_id, "collector_version": "0.1.0",
        "event_type": event_type, "category": category,
        "event_time": received_at if source_time is None else source_time,
        "source_timestamp": event.get("timestamp"), "received_at": received_at,
        "address_family": family, "src_ip": str(source) if source else None,
        "dst_ip": str(destination) if destination else None,
        "source_port": ports[0], "destination_port": ports[1],
        "protocol": event.get("proto"), "application": event.get("app_proto"),
        "flow_id": event.get("flow_id"), "community_id": event.get("community_id"),
        "interface": event.get("in_iface"), "vlan_ids": event.get("vlan"),
        "zone": None, "tenant_id": event.get("tenant_id"), "direction": direction,
        "asset_ids": [], "user": None, "process": None,
        "raw_reference": reference, "coverage": "configured-EVE-outputs",
        "integrity_flags": ["receipt-time-fallback"] if source_time is None else [],
        "ruleset": None,
        "rule_id": (event.get("alert") or {}).get("signature_id") if isinstance(event.get("alert"), dict) else None,
        "rule_revision": (event.get("alert") or {}).get("rev") if isinstance(event.get("alert"), dict) else None,
    }


class EveCollector:
    """Persist native records, findings and file checkpoints in one transaction."""

    def __init__(self, store, config):
        self.store = store
        self.local_networks = (*config.get("LOCAL_PREFIXES", ()), *config.get("LOCAL_PREFIXES6", ()))
        self.reader = JSONLinesReader(config["SURICATA_EVE_PATH"], store, "SURICATA",
                                      start_at_end=config.get("SURICATA_EVE_START_AT_END", False))
        self.freshness_sec = max(1.0, float(config.get("SURICATA_SOURCE_TIMEOUT_SEC", 60)))
        self.last_event_time = None
        self.last_stats_time = None
        self.counters = {}
        self.counter_deltas = {}
        self.counter_reset = False
        self.error = None
        self.disk = {"admitted": True, "free_bytes": None,
                     "floor_bytes": config.get("DISK_MIN_FREE_BYTES", DISK_MIN_FREE_BYTES)}
        for event_type in ("stats", None):
            recent = store.source_events("SURICATA", sensor_id=store.sensor_id,
                                         event_type=event_type, limit=1)
            if recent:
                self._observe(recent[0]["native"], recent[0]["event_time"])

    def _observe(self, event, event_time):
        self.last_event_time = event_time
        if event.get("event_type") != "stats":
            return
        self.last_stats_time = _event_time(event.get("timestamp"), None)
        stats = event.get("stats") if isinstance(event.get("stats"), dict) else {}
        capture = stats.get("capture") if isinstance(stats.get("capture"), dict) else {}
        current = {key: value for key, value in capture.items()
                   if isinstance(value, int) and not isinstance(value, bool) and value >= 0}
        self.counter_reset = any(current[key] < value for key, value in self.counters.items() if key in current)
        self.counter_deltas = {key: max(0, value - self.counters[key])
                               for key, value in current.items() if key in self.counters}
        self.counters = current

    def poll(self, notify=None, now=None):
        self.error = None
        admitted, free = disk_admission(self.store.path, self.disk["floor_bytes"])
        self.disk.update(admitted=admitted, free_bytes=free)
        if not admitted:
            return 0  # Offsets stay put: the EVE file is the backlog, nothing is lost here.

        pending = []  # Side effects wait for the batch commit; a failed batch drops them.

        def accept(key, cursor, native, reference):
            received = time.time() if now is None else float(now)
            identity = [key, reference["generation"], reference["offset"], reference.get("sha256"),
                        native.get("reason") if reference["length"] == 0 else None]
            event_id = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
            normalized = normalize_eve_record(native, event_id=event_id, sensor_id=self.store.sensor_id,
                                               reference=reference, received_at=received,
                                               local_networks=self.local_networks)
            detection = normalize_eve_event(native, self.local_networks)
            if normalized["category"] in {"collection_error", "collection_gap"}:
                detection = make_message("SURICATA", "SOURCE_COLLECTION_ERROR", "SYSTEM", {
                    "message": f"Suricata collection gap: {native.get('reason', 'invalid record')}",
                    "severity": "anomaly", "containment_eligible": False,
                })
            if detection is not None:
                detection["correlation_id"] = event_id
                detection["data"].update({"source_event_id": event_id, "sensor_id": self.store.sensor_id,
                                           "raw_event_id": event_id, "raw_reference": reference})
            accepted = self.store.accept_source_record(key, cursor, normalized, native, detection)
            pending.append(lambda: self._observe(native, normalized["event_time"]))
            if accepted and detection is not None and notify is not None:
                pending.append(lambda: notify(detection))

        def committed():
            # Each batch's side effects run once: a poll commits several batches.
            effects = pending[:]
            pending.clear()
            for effect in effects:
                effect()

        try:
            return self.reader.poll(accept, transaction=self.store._transaction, committed=committed)
        except Exception as exc:
            self.error = str(exc)
            raise

    def health(self, now=None):
        now = time.time() if now is None else float(now)
        stats_age = None if self.last_stats_time is None else now - self.last_stats_time
        fresh = eve_freshness_status(self.last_stats_time, now, self.freshness_sec)
        if (fresh != "STALE" and (self.error or self.reader.errors or not self.disk["admitted"]
                                  or self.counter_deltas.get("kernel_drops", 0) > 0)):
            status = "DEGRADED"  # A stale engine outranks it: errors stay listed, STALE must not hide.
        elif not self.reader.handles and not self.reader.visible_files:
            status = "WAITING"
        elif fresh != "STALE" and self.reader.partial_lines:
            status = "PARTIAL_WRITE"
        else:
            status = fresh
        status, lag = apply_lag(status, [self.reader], now, self.freshness_sec, self.last_stats_time)
        return {**lag, "source": "SURICATA", "sensor_id": self.store.sensor_id,
                "status": status, "engine_fresh": status == "FRESH", "reader_alive": True,
                "last_event_time": self.last_event_time, "last_stats_time": self.last_stats_time,
                "stats_age_sec": stats_age, "capture_counters": self.counters,
                "capture_deltas": self.counter_deltas, "counter_reset": self.counter_reset,
                "partial_lines": self.reader.partial_lines, "disk": dict(self.disk),
                "errors": ([self.error] if self.error else []) + self.reader.errors}

    def close(self):
        self.reader.close()


def suricata_eve_process(alert_queue, evidence_queue, config, worker_status_queue, shutdown_event=None):
    """Follow configured EVE files with durable native events and engine freshness."""
    log = setup_logging("suricata", config)
    store = security_store_from_config(config)
    # Its own process reading files from a checkpoint: a longer wait for the shared writer
    # lock delays intake slightly instead of failing the batch and re-reading it.
    with store._lock:
        store.conn.execute("PRAGMA busy_timeout=15000")
    collector = EveCollector(store, config)
    heartbeat_sec = max(1.0, float(config.get("SURICATA_HEARTBEAT_SEC", 5)))

    def notify(payload):
        try:
            try_put_drop_oldest(alert_queue, payload)
            if config.get("EVIDENCE_CAPTURE_ENABLED", True) and payload["action"] == "SURICATA_ALERT":
                try_put_no_drop(evidence_queue, make_message(
                    "SURICATA", "EVIDENCE_CAPTURE", "IO_WORKER",
                    {"trigger_ts": _event_time(payload["data"].get("timestamp"), time.time()), "action": "SURICATA_ALERT",
                     "correlation_id": payload["correlation_id"],
                     "source_event_id": payload["data"].get("source_event_id") or payload["correlation_id"],
                     "source": payload["source"],
                     "sensor_id": payload["data"].get("sensor_id") or config.get("SENSOR_ID", "unknown"),
                     "message": payload["data"].get("message", "Suricata alert")},
                    correlation_id=payload["correlation_id"],
                ))
        except Exception as exc:
            log.warning("presentation notification failed; committed record remains available: %s", exc)

    run_collector_loop(log, store, collector, collector.reader.channel, "SURICATA", heartbeat_sec,
                       notify, worker_status_queue, shutdown_event)


def run_collector_loop(log, store, collector, health_key, source, heartbeat_sec, notify,
                       worker_status_queue, shutdown_event):
    """Shared native-source worker loop: poll, commit, then heartbeat health."""
    from netwatch_privilege import get_privilege_state

    privilege_state = get_privilege_state()
    last_heartbeat = 0.0
    try:
        while shutdown_event is None or not shutdown_event.is_set():
            try:
                consumed = collector.poll(notify)
            except Exception as exc:
                log.error("native collection stalled; checkpoint unchanged: %s", exc)
                consumed = 0
            now = time.time()
            if now - last_heartbeat >= heartbeat_sec:
                health = collector.health(now)
                try:
                    store.record_source_health(health_key, health, now)
                except sqlite3.OperationalError as exc:  # busy store: the next heartbeat re-records it
                    log.warning("%s health not recorded this turn: %s", source, exc)
                try_put_drop_oldest(worker_status_queue, make_message(
                    source, "WORKER_HEARTBEAT", "UI_SHELL", {"timestamp": now, **health, "privilege": privilege_state},
                ))
                last_heartbeat = now
            if not consumed:
                if shutdown_event is not None:
                    shutdown_event.wait(0.1)
                else:
                    time.sleep(0.1)
    finally:
        collector.close()
        store.close()
