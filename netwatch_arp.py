"""ARP-spoof / MITM detection via passive MAC<->IP binding tracking (roadmap #3).

Every ARP packet asserts a claim: "IP X is at MAC Y" (the sender's protocol and
hardware addresses). On a healthy LAN each IP maps to exactly one stable MAC. ARP
spoofing breaks that: an attacker forges ARP so a victim's traffic for the gateway
(or any host) is sent to the attacker's MAC instead — a man-in-the-middle.

Detection here is passive — two signals computed from ARP already on the wire,
adding no traffic. (Active response to what it finds — isolating the offending LAN
device — lives in ``netwatch_quarantine``.)

1. **Rebinding** — an IP that was bound to one MAC is suddenly claimed by a
   different MAC. A rebind of the *gateway* IP is the textbook MITM and is escalated.
2. **MAC fan-out** — one MAC claiming many distinct IPs at once, which is what
   full-duplex subnet poisoning looks like from a passive vantage point.

The runtime replays committed native frames and persists scoped binding state,
pending confirmations and findings together. The standalone watcher retains JSON
support for the read-only CLI.
ARP anomalies are surfaced as alerts, not auto-mitigation triggers — the offender
is a LAN device (which mitigation allowlists anyway), and cutting it off blindly is
not the right response to a MITM.
"""

import ipaddress
import json
import math
import time

from netwatch_inventory import is_usable_mac, normalize_mac
from netwatch_security_store import note_notify_failure

# Binding event classification from ArpWatch.observe.
STABLE = "STABLE"   # same IP->MAC as before
NEW = "NEW"         # first time this IP is seen
REBIND_CANDIDATE = "REBIND_CANDIDATE"  # unconfirmed alternate owner
REBIND = "REBIND"   # this IP is now claimed by a different MAC (spoof signal)

# Sender IPs that are not a real binding claim (ARP probe / unspecified / broadcast).
_SKIP_IPS = {"0.0.0.0", "255.255.255.255"}


def _valid_ipv4(ip):
    try:
        address = ipaddress.IPv4Address(str(ip))
        return not address.is_multicast
    except ValueError:
        return False


class ArpWatch:
    """Tracks IP->MAC bindings observed in ARP and flags spoofing signals.

    ``observe(sender_ip, sender_mac)`` is the entry point (fed one ARP sender claim
    at a time). It returns a result dict whose ``suspicious`` flag is set on a rebind
    or when a MAC's fan-out exceeds the threshold."""

    def __init__(
        self,
        *,
        gateway_ip="",
        mac_fanout_threshold=4,
        max_bindings=4096,
        rebind_confirmations=3,
        rebind_min_sec=2.0,
        rebind_window_sec=10.0,
        ignored_macs=(),
    ):
        self.gateway_ip = gateway_ip or ""
        self.mac_fanout_threshold = mac_fanout_threshold
        self.max_bindings = max_bindings
        self.rebind_confirmations = max(2, int(rebind_confirmations))
        self.rebind_min_sec = max(0.0, float(rebind_min_sec))
        self.rebind_window_sec = max(self.rebind_min_sec, float(rebind_window_sec))
        self.ignored_macs = {
            normalized for value in ignored_macs
            if (normalized := normalize_mac(value))
        }
        self.bindings = {}   # ip -> {mac, first_seen, last_seen, flaps}
        self.mac_ips = {}    # mac -> set(ips)  (in-memory only; rebuilt on load)
        self.pending_rebinds = {}  # ip -> {mac, first_seen, last_seen, count}

    def observe(self, sender_ip, sender_mac, now=None):
        """Record an ARP "sender_ip is at sender_mac" claim and classify it.

        Returns ``None`` for unusable inputs (probe/broadcast IP, non-individual
        MAC). Otherwise a dict with ``event`` (NEW/STABLE/REBIND), ``fanout`` (how
        many IPs this MAC now claims), ``is_gateway``, ``suspicious``, and a
        recommended ``severity``."""
        now = time.time() if now is None else now
        if not isinstance(now, int | float) or not math.isfinite(now):
            return None
        sender_ip = str(sender_ip)
        if not _valid_ipv4(sender_ip) or sender_ip in _SKIP_IPS or not is_usable_mac(sender_mac):
            return None
        mac = normalize_mac(sender_mac)
        if mac in self.ignored_macs:
            return None

        entry = self.bindings.get(sender_ip)
        if entry is not None and now < entry["last_seen"]:
            return None  # Retain the native observation; older timestamps cannot confirm a new owner.
        event = STABLE
        prev_mac = None
        if entry is None:
            event = NEW
            entry = {"mac": mac, "first_seen": now, "last_seen": now, "flaps": 0}
            self.bindings[sender_ip] = entry
            self._evict_if_needed()
        else:
            entry["last_seen"] = now
            if entry["mac"] != mac:
                prev_mac = entry["mac"]
                candidate = self.pending_rebinds.get(sender_ip)
                if (candidate is None or candidate["mac"] != mac
                        or now - candidate["last_seen"] > self.rebind_window_sec):
                    candidate = {"mac": mac, "first_seen": now, "last_seen": now, "count": 1}
                    self.pending_rebinds[sender_ip] = candidate
                else:
                    candidate["last_seen"] = now
                    candidate["count"] += 1
                age = max(0.0, now - candidate["first_seen"])
                if candidate["count"] >= self.rebind_confirmations and age >= self.rebind_min_sec:
                    event = REBIND
                    entry["mac"] = mac
                    entry["flaps"] += 1
                    self.pending_rebinds.pop(sender_ip, None)
                else:
                    event = REBIND_CANDIDATE
            else:
                candidate = self.pending_rebinds.get(sender_ip)
                if candidate and now - candidate["last_seen"] > self.rebind_window_sec:
                    self.pending_rebinds.pop(sender_ip, None)

        # Maintain the reverse map; on a rebind, detach the IP from its old MAC.
        if event == REBIND and prev_mac is not None:
            old = self.mac_ips.get(prev_mac)
            if old is not None:
                old.discard(sender_ip)
                if not old:
                    self.mac_ips.pop(prev_mac, None)
        confirmed_mac = entry["mac"]
        self.mac_ips.setdefault(confirmed_mac, set()).add(sender_ip)

        fanout = len(self.mac_ips.get(confirmed_mac, ())) if event != REBIND_CANDIDATE else 0
        is_gateway = bool(self.gateway_ip) and sender_ip == self.gateway_ip
        suspicious = event == REBIND or fanout > self.mac_fanout_threshold
        if is_gateway and event == REBIND:
            severity = "critical"
        elif suspicious:
            severity = "alert"
        else:
            severity = "info"

        return {
            "ip": sender_ip,
            "mac": mac,
            "prev_mac": prev_mac,
            "event": event,
            "flaps": entry["flaps"],
            "fanout": fanout,
            "is_gateway": is_gateway,
            "suspicious": suspicious,
            "severity": severity,
            "candidate_count": candidate["count"] if event == REBIND_CANDIDATE else 0,
            "required_confirmations": self.rebind_confirmations,
        }

    def snapshot(self):
        """Sorted, copied view of the binding table for a CLI/UI."""
        return [
            {
                "ip": ip,
                "mac": e["mac"],
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
                "flaps": e["flaps"],
                "fanout": len(self.mac_ips.get(e["mac"], ())),
            }
            for ip, e in sorted(self.bindings.items(), key=lambda kv: _ip_sort_key(kv[0]))
        ]

    # --- internals -------------------------------------------------------
    def _evict_if_needed(self):
        while len(self.bindings) > self.max_bindings:
            candidates = [ip for ip in self.bindings if ip != self.gateway_ip]
            if not candidates:
                break  # only the pinned gateway binding remains
            victim = min(candidates, key=lambda ip: self.bindings[ip]["last_seen"])
            mac = self.bindings[victim]["mac"]
            self.bindings.pop(victim, None)
            self.pending_rebinds.pop(victim, None)
            s = self.mac_ips.get(mac)
            if s is not None:
                s.discard(victim)
                if not s:
                    self.mac_ips.pop(mac, None)

    def _rebuild_mac_ips(self):
        self.mac_ips = {}
        for ip, e in self.bindings.items():
            self.mac_ips.setdefault(e["mac"], set()).add(ip)


def _ip_sort_key(ip):
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (0, 0, 0, 0)


MAX_SCOPES = 64
FANOUT_COOLDOWN_SEC = 300


class DurableArpAnalyzer:
    """Replay committed ARP frames with transactional state, findings and position."""

    cursor_key = "ANALYSIS:ARP:v1"

    def __init__(self, store, config, notify=None):
        self.store = store
        self.config = config
        self.gateway_ip = config.get("GATEWAY_IP", "")
        self.notify = notify
        self.last_error = None
        self.skipped = 0
        self.scope_overflow = 0
        self.notify_failures = 0
        self._fanout_seen = {}  # (scope, mac) -> last fan-out finding time

    def health(self):
        cursor = self.store.cursor(self.cursor_key) or {"sequence": 0}
        return {"status": "DEGRADED" if self.last_error or self.scope_overflow else "RUNNING",
                "sequence": cursor["sequence"], "last_error": self.last_error,
                "skipped_records": self.skipped, "scope_overflow": self.scope_overflow,
                "notify_failures": self.notify_failures}

    def poll(self, limit=32):
        from netwatch_capture import parse_ethernet_frame
        from netwatch_core import make_message

        notifications = []
        processed = 0
        # Peek without the writer lock: an empty poll every 0.5 s otherwise waited out other
        # writers each time and stalled the core loop (sensor VM 2026-10-08).
        after = (self.store.cursor(self.cursor_key) or {"sequence": 0})["sequence"]
        if self.store.source_stream_page("CONTROL", "arp", after, limit)[1] <= after:
            return 0
        # ponytail: bounded transactional replay, JSON snapshots per scope;
        # normalized binding rows if measured ARP throughput outgrows snapshots.
        with self.store._transaction():
            cursor = self.store.cursor(self.cursor_key) or {"sequence": 0}
            rows, scanned_to = self.store.source_stream_page("CONTROL", "arp", cursor["sequence"], limit)
            # Each scope's table is loaded once and saved once per poll, in this transaction:
            # per-row JSON reload and rewrite of up to 4096 bindings held the writer lock
            # ~2.4 s a poll on the sensor and starved packet analysis (2026-10-12).
            watches, persisted_scopes, last = {}, None, cursor["sequence"]
            for row in rows:
                last = max(last or 0, row["sequence"] or 0)
                normalized = row["normalized"]
                try:  # Only decoding is guarded; sqlite errors must still roll back and retry.
                    raw = bytes.fromhex(row["native"]["frame"])
                    parsed = parse_ethernet_frame(raw, normalized["event_time"])
                    if parsed is None or parsed[0] != "arp":
                        raise ValueError("native ARP frame cannot be replayed")
                    claim = parsed[1]
                    scope = json.dumps([normalized["sensor_id"], normalized["capture_interface"], claim["vlan_ids"]])
                except (ValueError, KeyError, TypeError, AttributeError):
                    self.skipped += 1
                    continue
                key = "ARP_STATE:v1:" + scope
                watch = watches.get(key)
                if watch is None:
                    state = self.store.cursor(key)
                    if state is None:
                        if persisted_scopes is None:
                            persisted_scopes = self.store.conn.execute(
                                "SELECT COUNT(*) FROM security_source_cursors WHERE source_key LIKE 'ARP_STATE:v1:%'"
                            ).fetchone()[0]
                        new_scopes = sum(1 for k in watches if self.store.cursor(k) is None)
                        if persisted_scopes + new_scopes >= MAX_SCOPES:  # Attacker-chosen VLAN tags must not mint endless scopes.
                            self.scope_overflow += 1
                            continue
                    state = state or {}
                    watch = ArpWatch(
                        gateway_ip=self.gateway_ip,
                        mac_fanout_threshold=self.config.get("ARP_MAC_FANOUT_THRESHOLD", 4),
                        rebind_confirmations=self.config.get("ARP_REBIND_CONFIRMATIONS", 3),
                        rebind_min_sec=self.config.get("ARP_REBIND_MIN_SEC", 2),
                        rebind_window_sec=self.config.get("ARP_REBIND_WINDOW_SEC", 10),
                        ignored_macs=(self.config.get("QUARANTINE_SINK_MAC", "02:00:00:00:de:ad"),),
                    )
                    watch.bindings = {ip: entry for ip, entry in state.get("bindings", {}).items()
                                      if entry["mac"] not in watch.ignored_macs}
                    watch.pending_rebinds = {ip: entry for ip, entry in state.get("pending_rebinds", {}).items()
                                            if ip in watch.bindings and entry["mac"] not in watch.ignored_macs}
                    watch._rebuild_mac_ips()
                    watches[key] = watch
                previous_id = watch.bindings.get(claim["sender_ip"], {}).get("native_event_id")
                prior_candidate = watch.pending_rebinds.get(claim["sender_ip"], {})
                candidate_ids = list(prior_candidate.get("native_event_ids", []))
                result = watch.observe(claim["sender_ip"], claim["sender_mac"], claim["timestamp"]) if claim["op"] in (1, 2) else None
                if result and result["event"] in (NEW, REBIND):
                    watch.bindings[claim["sender_ip"]]["native_event_id"] = row["event_id"]
                elif result and result["event"] == REBIND_CANDIDATE:
                    pending = watch.pending_rebinds[claim["sender_ip"]]
                    if pending["first_seen"] != prior_candidate.get("first_seen") or pending["mac"] != prior_candidate.get("mac"):
                        candidate_ids = []
                    # Keep the first observation plus the latest required confirmations.
                    # ponytail: bounded representative references; the native ledger and
                    # prune audit expose any intervening observations outside this set.
                    ids = candidate_ids + [row["event_id"]]
                    pending["native_event_ids"] = list(dict.fromkeys(
                        ids[:1] + ids[-watch.rebind_confirmations:]))
                if result and result["suspicious"] and result["event"] != REBIND:
                    # fan-out is a standing condition, not an event: one finding per MAC per cooldown
                    last = self._fanout_seen.get((scope, result["mac"]))
                    if last is not None and 0 <= claim["timestamp"] - last < FANOUT_COOLDOWN_SEC:
                        result = None
                    else:
                        if len(self._fanout_seen) > 4096:
                            self._fanout_seen.clear()
                        self._fanout_seen[(scope, result["mac"])] = claim["timestamp"]
                if result and result["suspicious"]:
                    native_ids = ([previous_id] if previous_id else []) + candidate_ids + [row["event_id"]]
                    if result["fanout"] > watch.mac_fanout_threshold:
                        native_ids.extend(entry["native_event_id"] for entry in watch.bindings.values()
                                          if entry["mac"] == result["mac"] and entry.get("native_event_id"))
                    message = (f"ARP binding changed: {result['ip']} {result['prev_mac']} -> {result['mac']}"
                               if result["event"] == REBIND else
                               f"ARP claim fan-out: {result['mac']} claims {result['fanout']} observed addresses")
                    payload = make_message("ARP_ANALYZER", "ARP_ANOMALY", "UI_SHELL", {
                        "source_event_id": row["event_id"], "native_event_id": row["event_id"],
                        "native_event_ids": list(dict.fromkeys(native_ids)),
                        "sensor_id": normalized["sensor_id"], "timestamp": normalized["event_time"],
                        "message": message, "severity": result["severity"], "confidence": "Observed",
                        "offender_ip": result["ip"], "offender_mac": result["mac"],
                        "offender_owned_ips": sorted(watch.mac_ips.get(result["mac"], set()) - {result["ip"]}),
                        "is_gateway": result["is_gateway"], "binding_result": result,
                        "capture_interface": normalized["capture_interface"], "vlan_ids": claim["vlan_ids"],
                        "correlation_entity": scope,
                    }, correlation_id=row["event_id"])
                    self.store._add(payload)
                    notifications.append(payload)
                processed += 1
            for key, watch in watches.items():
                self.store._checkpoint(key, {"bindings": watch.bindings, "pending_rebinds": watch.pending_rebinds})
            # Step over other streams' rows too.
            top = max(last or 0, scanned_to or 0)
            if top > cursor["sequence"]:
                self.store._checkpoint(self.cursor_key, {"sequence": top})
        for payload in notifications:
            if self.notify:
                try:
                    self.notify(payload)
                except Exception:
                    note_notify_failure(self)  # The committed finding remains available to case reconciliation.
        return processed
