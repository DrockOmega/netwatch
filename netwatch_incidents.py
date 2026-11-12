"""GUI-free incident correlation shared by collectors and the console."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from netwatch_core import compile_v4_prefixes, compile_v6_prefixes, is_local_ip, is_message_payload

SEVERITY_RANK = {
    "info": 0,
    "recovered": 0,
    "notice": 1,
    "anomaly": 2,
    "alert": 3,
    "critical": 4,
}

_CLOSED_INCIDENT_STATUSES = {"Resolved", "Recovered", "Dismissed"}
INCIDENT_SCOPES = ("OPEN INCIDENTS", "CRITICAL ONLY", "ALL INCIDENTS")


def filter_incident_rows(rows, scope="OPEN INCIDENTS"):
    """Return incident rows matching an operator drill-down scope."""
    scope = str(scope).upper()
    if scope not in INCIDENT_SCOPES:
        scope = "OPEN INCIDENTS"
    snapshot = [dict(row) for row in rows if isinstance(row, dict)]
    if scope == "ALL INCIDENTS":
        return snapshot
    active = [row for row in snapshot if row.get("status") not in _CLOSED_INCIDENT_STATUSES]
    if scope == "CRITICAL ONLY":
        return [row for row in active if row.get("severity") == "critical"]
    return active

_ACTION_SEVERITY = {
    "DEVICE_NEW": "notice",
    "WIRELESS_DEVICE_NEW": "notice",
    "WIRELESS_DEVICE_QUIET": "info",
    "ACCEPTED_EGRESS": "info",
    "ACCEPTED_EGRESS_EXPIRED": "info",
    "WIRELESS_AP_MODE": "alert",
    "BASELINE_ANOMALY": "anomaly",
    "DNS_ANOMALY": "anomaly",
    "ARP_ANOMALY": "critical",
    "JA3_ANOMALY": "alert",
    "BEACON_ANOMALY": "alert",
    "POLICY_DECISION": "alert",
    "SURICATA_ALERT": "alert",
    "CAPTURE_LOSS": "anomaly",
    "CAPTURE_RECOVERED": "recovered",
    "SIGNATURE_UPDATE_RECOVERED": "recovered",
    "EVIDENCE_SAVED": "notice",
    "EVIDENCE_FAILED": "anomaly",
    "CONTROL_REVIEW": "anomaly",
    "CONTROL_COLLECTION_GAP": "anomaly",
}

_ACTION_TITLES = {
    "DEVICE_NEW": "New device observed",
    "WIRELESS_DEVICE_NEW": "New device first seen (wireless watch)",
    "WIRELESS_DEVICE_QUIET": "Known device went quiet",
    "ACCEPTED_EGRESS": "Accepted egress (known safe)",
    "ACCEPTED_EGRESS_EXPIRED": "Accepted egress entry expired",
    "WIRELESS_AP_MODE": "Access point left AP mode",
    "BASELINE_ANOMALY": "Behavioral baseline anomaly",
    "ARP_ANOMALY": "ARP identity anomaly",
    "DNS_ANOMALY": "DNS behavior anomaly",
    "JA3_ANOMALY": "Known-bad TLS fingerprint",
    "BEACON_ANOMALY": "Periodic command-and-control beacon",
    "POLICY_DECISION": "Network policy violation",
    "SURICATA_ALERT": "Suricata inspection finding",
    "CONTROL_REVIEW": "Control-plane observation needs review",
    "CONTROL_COLLECTION_GAP": "Control-plane collection gap",
    "POLICY_LOAD_FAILED": "Network policy unavailable",
    "POLICY_UPDATE_RECOVERED": "Network policy updated",
    "CAPTURE_LOSS": "Capture integrity degraded",
    "CAPTURE_RECOVERED": "Capture integrity recovered",
    "SIGNATURE_UPDATE_FAILED": "Threat signatures unavailable",
    "SIGNATURE_UPDATE_RECOVERED": "Threat signatures restored",
    "DB_WRITE_FAILURE": "Telemetry persistence failure",
    "DB_BACKPRESSURE": "Telemetry persistence backpressure",
    "ARENA_CAPACITY": "Analytics capacity pressure",
    "ARENA_EVICTION_ACTIVE": "Active analytics state evicted",
}

_MESSAGE_TITLES = (
    ("THREAT INTEL", "Known-bad destination contacted"),
    ("THREAT DOMAIN", "Threat-listed domain contacted"),
    ("THREAT PORT", "Restricted port contacted"),
    ("GEO-THREAT", "Flagged geography contacted"),
    ("UDP_FLOOD", "UDP flood detected"),
    ("PORT_SWEEP", "Port sweep detected"),
    ("EXFIL", "Volumetric egress anomaly"),
)

_IPV4_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
_VOLATILE_NUMBER_RE = re.compile(r"(?<![0-9a-f:.])\d+(?:\.\d+)?(?![0-9a-f:.])", re.IGNORECASE)


def severity_for(action, data=None, default="alert"):
    """Return the normalized severity for one IPC action."""
    data = data if isinstance(data, dict) else {}
    explicit = data.get("severity")
    if explicit in SEVERITY_RANK:
        return explicit
    return _ACTION_SEVERITY.get(str(action), default)


def incident_title(action, message):
    """Map low-level detector output to an operator-facing incident title."""
    action = str(action)
    if action in _ACTION_TITLES:
        return _ACTION_TITLES[action]
    upper = str(message).upper()
    for prefix, title in _MESSAGE_TITLES:
        if upper.startswith(prefix):
            return title
    prefix = str(message).partition(":")[0].strip().replace("_", " ")
    return prefix.title() if prefix else action.replace("_", " ").title()


def _target_text(target):
    if isinstance(target, bytes | bytearray) and len(target) in {4, 16}:
        try:
            return str(ipaddress.ip_address(bytes(target)))
        except ValueError:
            return "system"
    if target is None:
        return "system"
    if isinstance(target, str) and target in {"", "0", "SYSTEM", "UI_SHELL"}:
        return "system"
    if isinstance(target, int | float) and target == 0:
        return "system"
    return str(target)


def _message_entity(message):
    text = str(message)
    match = _IPV4_RE.search(text) or _MAC_RE.search(text)
    return match.group(0).lower() if match else ""


def _message_signature(message):
    text = str(message).strip().lower()
    text = _VOLATILE_NUMBER_RE.sub("#", text)
    return text[:120]


CONFIDENCE_ORDER = ("Observed", "Low", "Medium", "High")
_RULE_KEYS = {"id", "version", "description", "sources", "join", "window_sec", "match", "attack"}
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


ATTACK_MAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_map.json")
_MAX_ATTACK = 20


@lru_cache(maxsize=1)
def load_attack_map(path=ATTACK_MAP_PATH):
    """The committed detector-kind -> ATT&CK map; a missing file means no tags, a malformed one raises."""
    if not os.path.isfile(path):
        return {"techniques": {}, "kinds": []}
    with open(path, encoding="utf-8") as handle:
        pack = json.load(handle)
    techniques = pack["techniques"]
    for kind in pack["kinds"]:
        if not isinstance(kind["demonstrated"], bool):
            raise ValueError(f"{kind['kind']}: demonstrated must be a boolean")
        for technique in kind["techniques"]:
            if technique not in techniques or not _TECHNIQUE_RE.fullmatch(technique):
                raise ValueError(f"{kind['kind']}: unknown technique {technique}")
    return pack


def _tag(technique_id, name, tactic, source, demonstrated=False):
    return {"technique_id": technique_id, "technique_name": name, "tactic": tactic,
            "source": source, "demonstrated": demonstrated}


def map_attack(action, message="", *, pack=None):
    """ATT&CK tags for one detection kind: the first kind matching action (and message prefix)."""
    pack = pack or load_attack_map()
    upper = str(message).upper()
    for kind in pack["kinds"]:
        if kind["action"] == action and upper.startswith(kind.get("prefix", "")):
            return [_tag(t, pack["techniques"][t]["name"], pack["techniques"][t]["tactic"], "map",
                         kind["demonstrated"]) for t in kind["techniques"]]
    return []


def rule_attack(rule, *, pack=None):
    """Tags from a correlation rule's own `attack` list (names come from the map's catalog)."""
    pack = pack or load_attack_map()
    out = []
    for item in rule.get("attack", ()):
        info = pack["techniques"].get(item["technique"], {})
        out.append(_tag(item["technique"], info.get("name", ""), info.get("tactic", ""), "map",
                        item["demonstrated"]))
    return out


def suricata_attack(data):
    """Tags carried from the ET rule's alert.metadata by netwatch_suricata (vendor metadata, not demonstrated)."""
    out = []
    for item in data.get("attack") or ():
        if isinstance(item, dict) and isinstance(item.get("technique_id"), str) \
                and _TECHNIQUE_RE.fullmatch(item["technique_id"]):
            out.append(_tag(item["technique_id"], str(item.get("technique_name") or "")[:120],
                            str(item.get("tactic") or "")[:120], "suricata"))
    return out


def merge_attack(current, tags):
    merged = list(current)
    for tag in tags:
        if len(merged) < _MAX_ATTACK and not any(
                (m["technique_id"], m["source"]) == (tag["technique_id"], tag["source"]) for m in merged):
            merged.append(tag)
    return merged


def validate_rule_pack(pack):
    """Reject anything outside the small cross-source rule format instead of guessing."""
    if not isinstance(pack, dict) or set(pack) != {"version", "rules"} or pack["version"] != 1:
        raise ValueError("rule pack must be {version: 1, rules: [...]}")
    if not isinstance(pack["rules"], list):
        raise ValueError("rule pack rules must be a list")
    seen = set()
    for rule in pack["rules"]:
        if not isinstance(rule, dict) or set(rule) - _RULE_KEYS or \
                {"id", "version", "description", "sources", "join", "window_sec"} - set(rule):
            raise ValueError("rule has unknown or missing keys")
        rule_id = rule["id"]
        if not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", rule_id) or rule_id in seen:
            raise ValueError(f"rule id invalid or duplicated: {rule_id!r}")
        seen.add(rule_id)
        if not isinstance(rule["version"], int) or isinstance(rule["version"], bool) or rule["version"] < 1:
            raise ValueError(f"{rule_id}: version must be a positive integer")
        if not isinstance(rule["description"], str) or not rule["description"].strip():
            raise ValueError(f"{rule_id}: description required")
        sources = rule["sources"]
        if not isinstance(sources, list) or len(set(sources)) < 2 or len(set(sources)) != len(sources) \
                or not all(isinstance(item, str) and item for item in sources):
            raise ValueError(f"{rule_id}: sources must name at least two distinct sources")
        if rule["join"] not in {"community_id", "asset"}:
            raise ValueError(f"{rule_id}: join must be community_id or asset")
        window = rule["window_sec"]
        if not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= 86_400:
            raise ValueError(f"{rule_id}: window_sec must be 1..86400")
        match = rule.get("match", {})
        if not isinstance(match, dict) or not all(
                isinstance(key, str) and isinstance(values, list) and values
                and all(isinstance(v, str | int) and not isinstance(v, bool) for v in values)
                for key, values in match.items()):
            raise ValueError(f"{rule_id}: match must map field names to nonempty value lists")
        attack = rule.get("attack", [])
        if not isinstance(attack, list) or not all(
                isinstance(item, dict) and set(item) == {"technique", "demonstrated"}
                and isinstance(item["technique"], str) and _TECHNIQUE_RE.fullmatch(item["technique"])
                and isinstance(item["demonstrated"], bool) for item in attack):
            raise ValueError(f"{rule_id}: attack entries need technique and demonstrated")
    return pack


def load_rule_pack(path):
    with open(path, encoding="utf-8") as handle:
        return validate_rule_pack(json.load(handle))


def _address(value):
    if isinstance(value, dict) and set(value) == {"$binary"}:  # Stored payloads encode bytes this way.
        try:
            value = bytes.fromhex(value["$binary"])
        except (TypeError, ValueError):
            return None
    try:
        if isinstance(value, bytes | bytearray):
            return ipaddress.ip_address(bytes(value)) if len(value) in {4, 16} else None
        return ipaddress.ip_address(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _scalar(value):
    return isinstance(value, str | int | bool) or isinstance(value, float) and math.isfinite(value)


def detection_fields(payload, local_networks=()):
    """Normalized detection fields rules match on: data scalars plus community_id and local asset."""
    data = payload["data"]
    fields = {key: value for key, value in data.items() if _scalar(value)}
    fields.update(source=payload["source"], action=payload["action"],
                  severity=severity_for(payload["action"], data))
    cid = data.get("community_id")
    fields["community_id"] = cid if isinstance(cid, str) and 0 < len(cid) <= 128 else None
    v4, v6 = compile_v4_prefixes(local_networks), compile_v6_prefixes(local_networks)
    fields["asset"] = None
    for value in (data.get("src_ip"), data.get("dst_ip"), payload.get("target_id"), data.get("offender_ip")):
        address = _address(value)
        if address is not None and is_local_ip(address.packed, v4, v6):
            fields["asset"] = str(address)
            break
    return fields


def rule_match(rule, new, candidate, age):
    """Return the recorded reason when one rule joins two detections, else None."""
    if new["source"] == candidate["source"] or {new["source"], candidate["source"]} - set(rule["sources"]):
        return None
    if abs(age) > rule["window_sec"]:
        return None
    value = new.get(rule["join"])
    if value is None or value != candidate.get(rule["join"]):
        return None
    for side in (new, candidate):
        if any(side.get(name) not in allowed for name, allowed in rule.get("match", {}).items()):
            return None
    return (f"{rule['id']} v{rule['version']}: {candidate['source']} and {new['source']} share "
            f"{rule['join']} {value} within {rule['window_sec']}s")


@dataclass(slots=True)
class Incident:
    incident_id: str
    action: str
    title: str
    detail: str
    target: str
    severity: str
    status: str
    first_seen: float
    last_seen: float
    count: int
    confidence: str
    response: str
    sources: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    attack: list = field(default_factory=list)


class IncidentStore:
    """Pure incident correlation keyed by detector family and target.

    DurableIncidentStore builds a throwaway instance per detection from stored
    candidates; this class holds no persistence and does no trimming.

    With a rule pack, a detection whose own key has no case may join a recent
    open case from a different source (shared Community ID or local asset).
    """

    def __init__(self, *, rules=(), local_networks=()):
        self._incidents = {}
        self._sequence = 0
        self.rules = list(rules or ())
        self.local_networks = tuple(local_networks or ())
        self._recent = deque(maxlen=1000)  # (case key, detection fields, receipt time)
        self.last_correlation = None

    def _join(self, fields, now):
        for rule in self.rules:
            for key, candidate, seen in reversed(self._recent):
                incident = self._incidents.get(key)
                if incident is None or incident.status in _CLOSED_INCIDENT_STATUSES:
                    continue
                reason = rule_match(rule, fields, candidate, now - seen)
                if reason:
                    return key, rule, reason, candidate["source"]
        return None

    @staticmethod
    def correlation_key(payload):
        if not is_message_payload(payload) or not payload["action"]:
            return None
        data = payload["data"]
        action = payload["action"]
        message = str(data.get("message") or action)
        target = _target_text(payload.get("target_id"))
        if target == "system" and data.get("offender_ip"):
            target = str(data["offender_ip"])
        context = data.get("correlation_entity")
        context = context if isinstance(context, str) and 0 < len(context) <= 1024 else None
        entity = (f"{context}:{target}" if context and target != "system" else
                  target if target != "system" else context or _message_entity(message))
        return action, entity or _message_signature(message), incident_title(action, message)

    def add(self, payload, severity=None, now=None):
        if not is_message_payload(payload) or not payload["action"]:
            return None
        data = payload["data"]
        action = payload["action"]
        message = str(data.get("message") or action)
        severity = severity or severity_for(action, data)
        if severity not in SEVERITY_RANK:
            severity = "alert"
        now = float(time.time() if now is None else now)
        key = self.correlation_key(payload)
        _, _, title = key
        target = _target_text(payload.get("target_id"))
        if target == "system" and data.get("offender_ip"):
            target = str(data["offender_ip"])
        entity = target if target != "system" else _message_entity(message)
        incident = self._incidents.get(key)
        source = payload["source"]
        fields = detection_fields(payload, self.local_networks) if self.rules else None
        join = self._join(fields, now) if incident is None and self.rules else None
        self.last_correlation = None
        if join:
            key, incident = join[0], self._incidents[join[0]]
        if incident is None:
            self._sequence += 1
            incident = Incident(
                incident_id=f"NW-{self._sequence:05d}",
                action=action,
                title=title,
                detail=message,
                target=entity or target,
                severity=severity,
                status="Recovered" if severity == "recovered" else (
                    "Acknowledged" if action == "ACCEPTED_EGRESS" else "Open"),
                first_seen=now,
                last_seen=now,
                count=1,
                confidence=self._confidence(data),
                response=self._response(action, severity),
                sources=[source],
            )
            self._incidents[key] = incident
        else:
            incident.detail = message
            incident.first_seen = min(incident.first_seen, now)
            incident.last_seen = max(incident.last_seen, now)
            incident.count += 1
            # Severity stays the highest member detection's own severity; a join never adds to it.
            if SEVERITY_RANK[severity] > SEVERITY_RANK[incident.severity]:
                incident.severity = severity
            confidence = self._confidence(data)
            if (join or incident.rules) and \
                    CONFIDENCE_ORDER.index(incident.confidence) > CONFIDENCE_ORDER.index(confidence):
                confidence = incident.confidence  # A later member does not undo corroboration.
            incident.confidence = confidence
            if severity == "recovered":
                incident.status = "Recovered"
            elif incident.status in _CLOSED_INCIDENT_STATUSES:
                incident.status = "Open"
        if join:
            _, rule, reason, joined_source = join
            if joined_source not in incident.sources:  # Cases written before sources were recorded.
                incident.sources.insert(0, joined_source)
            correlation = {"rule": rule["id"], "rule_version": rule["version"], "join": rule["join"],
                           "value": fields[rule["join"]], "reason": reason}
            if source not in incident.sources:
                before = incident.confidence
                incident.confidence = CONFIDENCE_ORDER[min(CONFIDENCE_ORDER.index(before) + 1,
                                                           len(CONFIDENCE_ORDER) - 1)]
                correlation["confidence"] = {"from": before, "to": incident.confidence,
                                             "reason": f"independent corroboration by {source}"}
            if rule["id"] not in incident.rules:
                incident.rules.append(rule["id"])
            self.last_correlation = correlation
        if source not in incident.sources:
            incident.sources.append(source)
        tags = [*map_attack(action, message), *suricata_attack(data)]
        if join:
            tags += rule_attack(join[1])
        incident.attack = merge_attack(incident.attack, tags)
        if fields is not None:
            self._recent.append((key, fields, now))
        return asdict(incident)

    @staticmethod
    def _confidence(data):
        explicit = str(data.get("confidence") or "").strip().title()
        return explicit if explicit in {"High", "Medium", "Low", "Observed"} else "Observed"

    @staticmethod
    def _response(action, severity):
        if action == "ARP_ANOMALY":
            return "Quarantine ready"
        if action == "ALERT":
            return "Block eligible"
        if action == "ACCEPTED_EGRESS":
            return "No action"
        if severity == "recovered":
            return "No action"
        return "Investigate"
