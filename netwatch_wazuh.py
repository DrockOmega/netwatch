"""Optional adapter for Wazuh manager alerts.json (JSON lines), mirroring the EVE and Zeek adapters."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time

from netwatch_core import community_id_v1, make_message, try_put_drop_oldest
from netwatch_log import setup_logging
from netwatch_security_store import _event_time, security_store_from_config
from netwatch_sources import JSONLinesReader
from netwatch_suricata import apply_lag, classify_endpoints, eve_freshness_status, run_collector_loop
from netwatch_zeek import _port

_CATEGORIES = {"collector_gap": "collection_gap", "collector_error": "collection_error"}
_PROTOCOLS = {"tcp": 6, "udp": 17}
_MAX_TEXT, _MAX_LIST = 4096, 32  # alerts.json is untrusted: bound every retained field


def _get(obj, *keys):
    for key in keys:
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def _text(value, limit=_MAX_TEXT):
    if isinstance(value, int | float) and not isinstance(value, bool):
        value = str(value)
    return value[:limit] if isinstance(value, str) and value else None


def _list(value):
    return [text for item in (value if isinstance(value, list) else [])[:_MAX_LIST] if (text := _text(item, 256))]


def _level(native):
    level = _get(native, "rule", "level")
    return level if isinstance(level, int) and not isinstance(level, bool) and 0 <= level <= 15 else 0


def _hashes(value):
    """Sysmon "SHA256=..,MD5=.." into {"sha256": ".."}; unparseable parts are dropped."""
    parts = value[:_MAX_TEXT].split(",")[:_MAX_LIST] if isinstance(value, str) else []
    pairs = (part.partition("=") for part in parts)
    return {name.lower(): digest for name, sep, digest in pairs if sep and 0 < len(name) <= 16 and 0 < len(digest) <= 128}


def _endpoints(native):
    """Sysmon network (eventID 3) fields first, then generic decoder fields."""
    event = _get(native, "data", "win", "eventdata")
    if isinstance(event, dict) and event.get("sourceIp"):
        return (event.get("sourceIp"), event.get("sourcePort"), event.get("destinationIp"),
                event.get("destinationPort"), event.get("protocol"))
    data = _get(native, "data")
    return (_get(data, "srcip"), _get(data, "srcport"), _get(data, "dstip"), _get(data, "dstport"),
            _get(data, "protocol"))


def _int_port(value):
    try:
        return _port(int(value))
    except (TypeError, ValueError):
        return None


def agent_address(reported, name, mapping):
    """The reported agent IP, unless it is loopback/unspecified/"any" and the name has a configured LAN address."""
    try:
        usable = not (ip := ipaddress.ip_address(reported)).is_loopback and not ip.is_unspecified
    except ValueError:
        usable = False
    return reported if usable else mapping.get(name) or reported


def normalize_wazuh_record(native, *, event_id, sensor_id, reference, received_at, local_networks=(), min_level=7,
                           agent_addresses=None):
    """Retain native Wazuh and the common envelope; endpoint fields stay None when absent."""
    src_ip, src_port, dst_ip, dst_port, proto = _endpoints(native)
    source, destination, direction, _, _ = classify_endpoints(src_ip, dst_ip, local_networks)
    src_port, dst_port = _int_port(src_port), _int_port(dst_port)
    proto = proto.lower() if isinstance(proto, str) else None
    community = None
    if source and destination and proto in _PROTOCOLS and src_port is not None and dst_port is not None:
        community = community_id_v1(_PROTOCOLS[proto], str(source), src_port, str(destination), dst_port)
    family = source.version if source and source.version == destination.version else None
    source_time = _event_time(native.get("timestamp"), None)
    event_type = native["event_type"] if native.get("event_type") in ("collector_gap", "collector_error") else "alert"
    level = _level(native)
    event = _get(native, "data", "win", "eventdata")
    event = event if isinstance(event, dict) else {}
    agent_name, agent_ip = _text(_get(native, "agent", "name"), 256), _text(_get(native, "agent", "ip"), 64)
    process = None
    if event.get("image"):
        process = {"image": _text(event.get("image")), "command_line": _text(event.get("commandLine")),
                   "pid": _text(event.get("processId"), 32), "hashes": _hashes(event.get("hashes")),
                   "parent_image": _text(event.get("parentImage"))}
    return {
        "schema_version": 1, "event_id": event_id, "source_event_id": event_id,
        "source": "WAZUH", "sensor_id": sensor_id, "collector_version": "0.1.0",
        "event_type": event_type,
        "category": _CATEGORIES.get(event_type, "detection" if level >= min_level else "endpoint_event"),
        "event_time": received_at if source_time is None else source_time,
        "source_timestamp": _text(native.get("timestamp"), 64), "received_at": received_at,
        "address_family": family, "src_ip": str(source) if source else None,
        "dst_ip": str(destination) if destination else None,
        "source_port": src_port, "destination_port": dst_port,
        "protocol": proto.upper() if proto else None, "application": None,
        "flow_id": None, "community_id": community, "interface": None, "vlan_ids": None,
        "zone": None, "tenant_id": None, "direction": direction,
        "asset_ids": [], "user": _text(event.get("user")), "process": process,
        "agent": {"id": _text(_get(native, "agent", "id"), 64), "name": agent_name,
                  "ip": agent_ip, "address": agent_address(agent_ip, agent_name, agent_addresses or {})},
        "rule": {"id": _text(_get(native, "rule", "id"), 64), "level": level,
                 "description": _text(_get(native, "rule", "description")),
                 "groups": _list(_get(native, "rule", "groups")),
                 "mitre_ids": _list(_get(native, "rule", "mitre", "id"))},
        "raw_reference": reference, "coverage": "configured-Wazuh-alerts",
        "integrity_flags": ["receipt-time-fallback"] if source_time is None else [],
        "ruleset": "wazuh", "rule_id": _text(_get(native, "rule", "id"), 64), "rule_revision": None,
    }


def normalize_wazuh_alert(normalized):
    """A rule at or above the configured level becomes a detection (never containment-eligible)."""
    rule, agent = normalized["rule"], normalized["agent"]
    return make_message("WAZUH", "WAZUH_ALERT", "SYSTEM", {
        "message": f"WAZUH ALERT: {rule['description'] or rule['id'] or 'alert'} "
                   f"(rule {rule['id']}, level {rule['level']}, agent {agent['name']})",
        "severity": "critical" if rule["level"] >= 12 else "alert",
        "rule_id": rule["id"], "rule_level": rule["level"], "groups": rule["groups"], "mitre_ids": rule["mitre_ids"],
        "agent_id": agent["id"], "agent_name": agent["name"], "agent_ip": agent["ip"], "agent_address": agent["address"],
        "process": normalized["process"], "community_id": normalized["community_id"],
        "src_ip": normalized["src_ip"], "src_port": normalized["source_port"],
        "dst_ip": normalized["dst_ip"], "dst_port": normalized["destination_port"],
        "timestamp": normalized["event_time"], "direction": normalized["direction"],
        "containment_eligible": False,
    })


class WazuhCollector:
    """One durable JSONLinesReader over WAZUH_ALERTS_PATH; same commit path as ZeekCollector."""

    def __init__(self, store, config):
        self.store = store
        self.local_networks = (*config.get("LOCAL_PREFIXES", ()), *config.get("LOCAL_PREFIXES6", ()))
        self.min_level = int(config.get("WAZUH_MIN_ALERT_LEVEL", 7))
        self.agent_addresses = config.get("WAZUH_AGENT_ADDRESSES") or {}
        self.reader = JSONLinesReader(config["WAZUH_ALERTS_PATH"],
                                      store, "WAZUH", start_at_end=config.get("WAZUH_START_AT_END", False))
        self.channel = "SOURCE:WAZUH:" + str(store.sensor_id)
        self.freshness_sec = max(1.0, float(config.get("WAZUH_SOURCE_TIMEOUT_SEC", 900)))
        self.last_event_time = None
        self.invalid_records = 0  # malformed lines skipped since this process started
        self.error = None
        recent = store.source_events("WAZUH", sensor_id=store.sensor_id, event_type="alert", limit=1)
        if recent:
            self.last_event_time = recent[0]["event_time"]

    def poll(self, notify=None, now=None):
        self.error = None
        pending = []  # Side effects wait for the batch commit; a failed batch drops them.

        def accept(key, cursor, native, reference):
            received = time.time() if now is None else float(now)
            # A record is its bytes at its offset; a re-read after an anchor mismatch must not mint new events.
            identity = [key, reference["generation"] if reference["length"] == 0 else None, reference["offset"],
                        reference.get("sha256"), native.get("reason") if reference["length"] == 0 else None]
            event_id = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
            normalized = normalize_wazuh_record(native, event_id=event_id, sensor_id=self.store.sensor_id,
                                                reference=reference, received_at=received,
                                                local_networks=self.local_networks, min_level=self.min_level,
                                                agent_addresses=self.agent_addresses)
            detection = None
            if normalized["category"] == "detection":
                detection = normalize_wazuh_alert(normalized)
            elif normalized["category"] in {"collection_error", "collection_gap"}:
                pending.append(lambda: setattr(self, "invalid_records", self.invalid_records
                                               + (normalized["category"] == "collection_error")))
                detection = make_message("WAZUH", "SOURCE_COLLECTION_ERROR", "SYSTEM", {
                    "message": f"Wazuh collection gap: {native.get('reason', 'invalid record')}",
                    "severity": "anomaly", "containment_eligible": False,
                })
            if detection is not None:
                detection["correlation_id"] = event_id
                detection["data"].update({"source_event_id": event_id, "sensor_id": self.store.sensor_id,
                                          "raw_event_id": event_id, "raw_reference": reference})
            accepted = self.store.accept_source_record(key, cursor, normalized, native, detection)
            if normalized["event_type"] == "alert":
                pending.append(lambda: setattr(self, "last_event_time", normalized["event_time"]))
            if accepted and detection is not None and notify is not None:
                pending.append(lambda: notify(detection))

        try:
            return self.reader.poll(accept, transaction=self.store._transaction,
                                    committed=lambda: [f() for f in pending] or pending.clear())
        except Exception as exc:
            self.error = str(exc)
            raise

    def health(self, now=None):
        now = time.time() if now is None else float(now)
        errors = self.reader.errors
        if self.error or errors:
            status = "DEGRADED"
        elif not (self.reader.handles or self.reader.visible_files):
            status = "WAITING"
        elif self.reader.partial_lines:
            status = "PARTIAL_WRITE"
        else:  # A quiet manager looks STALE; the timeout is the quiet period worth noticing.
            status = eve_freshness_status(self.last_event_time, now, self.freshness_sec)
        status, lag = apply_lag(status, [self.reader], now, self.freshness_sec, self.last_event_time)
        return {**lag, "source": "WAZUH", "sensor_id": self.store.sensor_id,
                "status": status, "engine_fresh": status == "FRESH", "reader_alive": True,
                "last_event_time": self.last_event_time,
                "alert_age_sec": None if self.last_event_time is None else now - self.last_event_time,
                "paths": [self.reader.pattern], "partial_lines": self.reader.partial_lines,
                "invalid_records": self.invalid_records,
                "errors": ([self.error] if self.error else []) + errors}

    def close(self):
        self.reader.close()


def wazuh_alert_process(alert_queue, config, worker_status_queue, shutdown_event=None):
    """Follow Wazuh alerts.json with durable native records and alert-recency freshness."""
    log = setup_logging("wazuh", config)
    store = security_store_from_config(config)
    collector = WazuhCollector(store, config)

    def notify(payload):
        try:
            try_put_drop_oldest(alert_queue, payload)
        except Exception as exc:
            log.warning("presentation notification failed; committed record remains available: %s", exc)

    run_collector_loop(log, store, collector, collector.channel, "WAZUH",
                       max(1.0, float(config.get("WAZUH_HEARTBEAT_SEC", 5))),
                       notify, worker_status_queue, shutdown_event)
