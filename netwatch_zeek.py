"""Optional adapter for Zeek JSON logs (LogAscii::use_json=T), mirroring the EVE adapter."""

from __future__ import annotations

import hashlib
import json
import os
import time

from netwatch_core import DISK_MIN_FREE_BYTES, disk_admission, make_message, try_put_drop_oldest
from netwatch_log import setup_logging
from netwatch_security_store import _event_time, security_store_from_config
from netwatch_sources import JSONLinesReader
from netwatch_suricata import apply_lag, classify_endpoints, eve_freshness_status, run_collector_loop

_CATEGORIES = {"conn": "network_session", "conn_interim": "network_session", "notice": "detection",
               "collector_gap": "collection_gap", "collector_error": "collection_error"}


def zeek_log_type(native, path):
    """Zeek JSON has no log name; conn.log, conn.<rotation>.log and conn.log.1 are all "conn"."""
    if native.get("event_type") in ("collector_gap", "collector_error"):  # tuple: the value may be unhashable
        return native["event_type"]
    return str(native.get("_path") or os.path.basename(path).split(".")[0] or "unknown").lower()


def _endpoints(native):
    # notice.log may carry only src/dst when the notice is not tied to one connection.
    return (native.get("id.orig_h", native.get("src")), native.get("id.orig_p"),
            native.get("id.resp_h", native.get("dst")), native.get("id.resp_p"))


def _port(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535 else None


def normalize_zeek_record(native, log_type, *, event_id, sensor_id, reference, received_at, local_networks=()):
    """Retain native Zeek and the same versioned common envelope as EVE, without inventing data."""
    src_ip, src_port, dst_ip, dst_port = _endpoints(native)
    source, destination, direction, _, _ = classify_endpoints(src_ip, dst_ip, local_networks)
    family = source.version if source and source.version == destination.version else None
    source_time = _event_time(native.get("ts"), None)
    proto = native.get("proto")
    return {
        "schema_version": 1, "event_id": event_id, "source_event_id": event_id,
        "source": "ZEEK", "sensor_id": sensor_id, "collector_version": "0.1.0",
        "event_type": log_type, "category": _CATEGORIES.get(log_type, "network_protocol"),
        "event_time": received_at if source_time is None else source_time,
        "source_timestamp": native.get("ts"), "received_at": received_at,
        "address_family": family, "src_ip": str(source) if source else None,
        "dst_ip": str(destination) if destination else None,
        "source_port": _port(src_port), "destination_port": _port(dst_port),
        "protocol": proto.upper() if isinstance(proto, str) else proto,
        "application": native.get("service") or (log_type if log_type in {"dns", "http", "ssl"} else None),
        "flow_id": native.get("uid"), "community_id": native.get("community_id"),
        "interface": None, "vlan_ids": None,
        "zone": None, "tenant_id": None, "direction": direction,
        "asset_ids": [], "user": None, "process": None,
        "raw_reference": reference, "coverage": "configured-Zeek-logs",
        "integrity_flags": ["receipt-time-fallback"] if source_time is None else [],
        "ruleset": None, "rule_id": native.get("note") if log_type == "notice" else None,
        "rule_revision": None,
    }


def normalize_zeek_notice(native, local_networks=()):
    """A notice.log record becomes a detection; other Zeek logs are evidence only."""
    src_ip, src_port, dst_ip, dst_port = _endpoints(native)
    _, _, direction, target, offender = classify_endpoints(src_ip, dst_ip, local_networks)
    note = str(native.get("note") or "notice")
    message = f"ZEEK NOTICE: {note}"
    if native.get("msg"):
        message += f": {native['msg']}"
    return make_message("ZEEK", "ZEEK_NOTICE", target, {
        "message": message, "severity": "alert", "note": note,
        "msg": native.get("msg"), "sub": native.get("sub"),
        "flow_id": native.get("uid"), "community_id": native.get("community_id"),
        "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port,
        "timestamp": native.get("ts"), "direction": direction,
        "offender_ip": str(offender) if offender is not None else None,
        "containment_eligible": target != "SYSTEM",
    })


class ZeekCollector:
    """One durable JSONLinesReader per configured path/glob; same commit path as EveCollector."""

    def __init__(self, store, config):
        self.store = store
        self.local_networks = (*config.get("LOCAL_PREFIXES", ()), *config.get("LOCAL_PREFIXES6", ()))
        paths = config.get("ZEEK_LOG_PATHS") or ()
        if isinstance(paths, str):
            paths = [paths]
        self.readers = [JSONLinesReader(path, store, "ZEEK",
                                        start_at_end=config.get("ZEEK_START_AT_END", False))
                        for path in dict.fromkeys(paths)]
        self.channel = "SOURCE:ZEEK:" + str(store.sensor_id)
        self.freshness_sec = max(1.0, float(config.get("ZEEK_SOURCE_TIMEOUT_SEC", 300)))
        self.last_event_time = None
        self.last_conn_time = None
        self.error = None
        self.disk = {"admitted": True, "free_bytes": None,
                     "floor_bytes": config.get("DISK_MIN_FREE_BYTES", DISK_MIN_FREE_BYTES)}
        for event_type in ("conn", None):
            recent = store.source_events("ZEEK", sensor_id=store.sensor_id, event_type=event_type, limit=1)
            if recent:
                self._observe(recent[0]["event_type"], recent[0]["native"], recent[0]["event_time"])

    def _observe(self, log_type, native, event_time):
        self.last_event_time = event_time
        if log_type == "conn":
            self.last_conn_time = _event_time(native.get("ts"), None)

    def poll(self, notify=None, now=None):
        self.error = None
        admitted, free = disk_admission(self.store.path, self.disk["floor_bytes"])
        self.disk.update(admitted=admitted, free_bytes=free)
        if not admitted:
            return 0  # Offsets stay put: the Zeek logs are the backlog, nothing is lost here.
        pending = []  # Side effects wait for the batch commit; a failed batch drops them.

        def accept(key, cursor, native, reference):
            received = time.time() if now is None else float(now)
            # A record is its bytes at its offset; a re-read after an anchor mismatch must not mint new events.
            identity = [key, reference["generation"] if reference["length"] == 0 else None, reference["offset"],
                        reference.get("sha256"), native.get("reason") if reference["length"] == 0 else None]
            event_id = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
            log_type = zeek_log_type(native, reference["path"])
            normalized = normalize_zeek_record(native, log_type, event_id=event_id,
                                               sensor_id=self.store.sensor_id, reference=reference,
                                               received_at=received, local_networks=self.local_networks)
            detection = normalize_zeek_notice(native, self.local_networks) if log_type == "notice" else None
            if normalized["category"] in {"collection_error", "collection_gap"}:
                detection = make_message("ZEEK", "SOURCE_COLLECTION_ERROR", "SYSTEM", {
                    "message": f"Zeek collection gap: {native.get('reason', 'invalid record')}",
                    "severity": "anomaly", "containment_eligible": False,
                })
            if detection is not None:
                detection["correlation_id"] = event_id
                detection["data"].update({"source_event_id": event_id, "sensor_id": self.store.sensor_id,
                                           "raw_event_id": event_id, "raw_reference": reference})
            accepted = self.store.accept_source_record(key, cursor, normalized, native, detection)
            pending.append(lambda: self._observe(log_type, native, normalized["event_time"]))
            if accepted and detection is not None and notify is not None:
                pending.append(lambda: notify(detection))

        consumed = 0
        try:
            for reader in self.readers:
                consumed += reader.poll(accept, transaction=self.store._transaction,
                                        committed=lambda: [f() for f in pending] or pending.clear())
        except Exception as exc:
            self.error = str(exc)
            raise
        return consumed

    def health(self, now=None):
        now = time.time() if now is None else float(now)
        errors = [error for reader in self.readers for error in reader.errors]
        partial = sum(reader.partial_lines for reader in self.readers)
        # Zeek has no default stats record; engine freshness is the newest conn.log record.
        fresh = eve_freshness_status(self.last_conn_time, now, self.freshness_sec)
        if fresh != "STALE" and (self.error or errors or not self.disk["admitted"]):
            status = "DEGRADED"  # A stale engine outranks it: errors stay listed, STALE must not hide.
        elif not any(reader.handles or reader.visible_files for reader in self.readers):
            status = "WAITING"
        elif fresh != "STALE" and partial:
            status = "PARTIAL_WRITE"
        else:
            status = fresh
        status, lag = apply_lag(status, self.readers, now, self.freshness_sec, self.last_conn_time)
        return {**lag, "source": "ZEEK", "sensor_id": self.store.sensor_id,
                "status": status, "engine_fresh": status == "FRESH", "reader_alive": True,
                "last_event_time": self.last_event_time, "last_conn_time": self.last_conn_time,
                "conn_age_sec": None if self.last_conn_time is None else now - self.last_conn_time,
                "paths": [reader.pattern for reader in self.readers], "partial_lines": partial, "disk": dict(self.disk),
                "errors": ([self.error] if self.error else []) + errors}

    def close(self):
        for reader in self.readers:
            reader.close()


def zeek_log_process(alert_queue, config, worker_status_queue, shutdown_event=None):
    """Follow configured Zeek JSON logs with durable native records and conn.log freshness."""
    log = setup_logging("zeek", config)
    store = security_store_from_config(config)
    collector = ZeekCollector(store, config)

    def notify(payload):
        try:
            try_put_drop_oldest(alert_queue, payload)
        except Exception as exc:
            log.warning("presentation notification failed; committed record remains available: %s", exc)

    run_collector_loop(log, store, collector, collector.channel, "ZEEK",
                       max(1.0, float(config.get("ZEEK_HEARTBEAT_SEC", 5))),
                       notify, worker_status_queue, shutdown_event)
