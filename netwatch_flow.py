"""Stateful flow tracking and periodic beacon detection.

The packet arena detects endpoint-local bursts.  This module supplies the
missing session boundary: bidirectional five-tuples with duration, direction,
byte/packet counters, and lightweight TCP lifecycle state.  It is pure and does
not import the capture, GUI, or persistence stacks.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import ipaddress
import json
import math
from collections import OrderedDict, deque


def _endpoint(ip, port):
    return bytes(ip), max(0, min(65535, int(port or 0)))


def _flow_id(key, started_at, sequence):
    encoded = json.dumps(
        [key[0], key[1][0].hex(), key[1][1], key[2][0].hex(), key[2][1], started_at, sequence],
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()[:20]


@functools.lru_cache(maxsize=65536)  # a MAC fails the address parse on every packet; the raise is costly
def _canonical_identity_text(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.replace("-", ":")


class FlowTracker:
    """Bounded bidirectional flow table keyed by protocol and endpoint pairs."""

    def __init__(self, *, max_flows=100_000, tcp_idle_sec=300, udp_idle_sec=60):
        self.max_flows = max(1, int(max_flows))
        self.tcp_idle_sec = max(1.0, float(tcp_idle_sec))
        self.udp_idle_sec = max(1.0, float(udp_idle_sec))
        self.flows = OrderedDict()
        self.evicted = deque(maxlen=self.max_flows)  # drained every second; a stalled core must not let it grow
        self.evicted_dropped = 0  # snapshots pushed out unread; the core then reconciles its per-flow state
        self.sequence = 0

    @staticmethod
    def key_for(event):
        protocol = str(event.get("protocol") or "IP").upper()
        left = _endpoint(event["src_ip"], event.get("source_port"))
        right = _endpoint(event["dst_ip"], event.get("port"))
        a, b = sorted((left, right), key=lambda item: (item[0], item[1]))
        return protocol, a, b

    def observe(self, event, *, src_local=False, dst_local=False):
        now = float(event["timestamp"])
        key = self.key_for(event)
        source = _endpoint(event["src_ip"], event.get("source_port"))
        flow = self.flows.get(key)
        created = flow is None
        if created:
            self.sequence += 1
            if len(self.flows) >= self.max_flows:
                _, victim = self.flows.popitem(last=False)
                if len(self.evicted) == self.max_flows:
                    self.evicted_dropped += 1
                self.evicted.append(self.snapshot(victim))
            flow = {
                "flow_id": _flow_id(key, now, self.sequence),
                "protocol": key[0],
                "endpoint_a": key[1],
                "endpoint_b": key[2],
                "initiator": source,
                "initiator_local": bool(src_local),
                "responder_local": bool(dst_local),
                "first_seen": now,
                "last_seen": now,
                "packets_ab": 0,
                "packets_ba": 0,
                "bytes_ab": 0,
                "bytes_ba": 0,
                "tcp_state": "new" if key[0] == "TCP" else "active",
                "domain": self._usable_domain(event.get("sni_domain")),
                "ja4": str(event.get("ja4") or ""),
                "source_mac": str(event.get("mac_src") or ""),
                "identity_revision": 0,
                "seen_egress": False,
            }
            self.flows[key] = flow
        else:
            self.flows.move_to_end(key)

        ab = source == flow["endpoint_a"]
        suffix = "ab" if ab else "ba"
        flow[f"packets_{suffix}"] += 1
        flow[f"bytes_{suffix}"] += max(0, int(event.get("size_bytes") or 0))
        flow["last_seen"] = max(flow["last_seen"], now)
        domain = self._usable_domain(event.get("sni_domain"))
        ja4 = str(event.get("ja4") or "")
        identity_changed = False
        if domain and domain != flow["domain"]:
            flow["domain"] = domain
            identity_changed = True
        if ja4 and ja4 != flow["ja4"]:
            flow["ja4"] = ja4
            identity_changed = True
        if identity_changed:
            flow["identity_revision"] += 1
        first_local_egress = bool(src_local and not dst_local and not flow["seen_egress"])
        if src_local and not dst_local:
            flow["seen_egress"] = True
        self._advance_tcp(flow, str(event.get("tcp_flags") or ""))
        snapshot = self.snapshot(flow)
        snapshot["observation_direction"] = (
            "egress" if src_local and not dst_local
            else "ingress" if not src_local and dst_local
            else "lateral" if src_local and dst_local
            else "any"
        )
        snapshot["first_local_egress"] = first_local_egress
        snapshot["identity_changed"] = identity_changed
        return snapshot, created

    @staticmethod
    def _usable_domain(value):
        value = str(value or "").strip()
        return "" if value.lower() == "encrypted-payload" else value

    @staticmethod
    def _advance_tcp(flow, flags):
        if flow["protocol"] != "TCP":
            return
        if "R" in flags:
            flow["tcp_state"] = "reset"
        elif "F" in flags:
            flow["tcp_state"] = "closing"
        elif "A" in flags:
            flow["tcp_state"] = "established"
        elif "S" in flags:
            flow["tcp_state"] = "opening"

    def expire(self, now):
        now = float(now)
        expired = []
        for key, flow in list(self.flows.items()):
            idle = self.tcp_idle_sec if flow["protocol"] == "TCP" else self.udp_idle_sec
            if now - flow["last_seen"] >= idle or flow["tcp_state"] in {"reset", "closing"}:
                expired.append(self.snapshot(flow))
                del self.flows[key]
        return expired

    def drain_evicted(self):
        snapshots = list(self.evicted)
        self.evicted.clear()
        return snapshots

    @staticmethod
    def snapshot(flow):
        initiator_is_a = flow["initiator"] == flow["endpoint_a"]
        up = "ab" if initiator_is_a else "ba"
        down = "ba" if initiator_is_a else "ab"
        initiator = flow["initiator"]
        responder = flow["endpoint_b"] if initiator_is_a else flow["endpoint_a"]
        return {
            "flow_id": flow["flow_id"],
            "protocol": flow["protocol"],
            "src_ip": initiator[0],
            "source_port": initiator[1],
            "dst_ip": responder[0],
            "destination_port": responder[1],
            "src_local": flow["initiator_local"],
            "dst_local": flow["responder_local"],
            "first_seen": flow["first_seen"],
            "last_seen": flow["last_seen"],
            "duration_sec": max(0.0, flow["last_seen"] - flow["first_seen"]),
            "packets_up": flow[f"packets_{up}"],
            "packets_down": flow[f"packets_{down}"],
            "bytes_up": flow[f"bytes_{up}"],
            "bytes_down": flow[f"bytes_{down}"],
            "tcp_state": flow["tcp_state"],
            "domain": flow["domain"],
            "ja4": flow["ja4"],
            "source_mac": flow["source_mac"],
            "identity_revision": flow["identity_revision"],
        }


def device_endpoint_rule(entry):
    """``{"mac", "networks", "ports"?}`` -> ``(mac, networks, ports)``, or None when unusable.

    A whole address family is refused: that would ignore all of the device's traffic."""
    try:
        mac = str(entry["mac"]).strip().lower()
        nets = tuple(ipaddress.ip_network(str(n), strict=False) for n in entry["networks"])
        ports = frozenset(int(p) for p in entry.get("ports") or ())
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if len(mac) != 17 or not nets or any(net.prefixlen == 0 for net in nets):
        return None
    return mac, nets, ports


def device_window_rule(entry):
    """``{"mac", "networks", "hours": [start, end]}`` -> ``(mac, networks, start, end)``, or None when unusable.

    Hours are local wall-clock, start inclusive, end exclusive; start > end wraps midnight; start == end is refused."""
    parsed = device_endpoint_rule(entry)
    try:
        start, end = (int(h) for h in entry["hours"])
    except (KeyError, TypeError, ValueError):
        return None
    if parsed is None or not (0 <= start < 24 and 0 <= end < 24) or start == end:
        return None
    return parsed[0], parsed[1], start, end


def in_hours(hour, start, end):
    return start <= hour < end if start < end else hour >= start or hour < end


def accepted_egress_rules(entries):
    """``ACCEPTED_EGRESS`` entries -> ``[{macs, domains, nets, note, review_by}]``; unusable entries are skipped.

    An entry needs at least one MAC and one domain or CIDR (never a blanket accept), no /0 CIDR, and a
    ``review_by`` date. It stops applying after that date (end of day, local time)."""
    rules = []
    for entry in entries or ():
        try:
            macs = frozenset(str(m).strip().lower() for m in entry["macs"])
            domains = tuple(str(d).lower().strip(".") for d in entry.get("domains") or () if str(d).strip("."))
            nets = tuple(ipaddress.ip_network(str(n), strict=False) for n in entry.get("cidrs") or ())
            review_by = datetime.date.fromisoformat(str(entry["review_by"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if not macs or any(len(m) != 17 for m in macs) or not (domains or nets) or any(n.prefixlen == 0 for n in nets):
            continue
        rules.append({"macs": macs, "domains": domains, "nets": nets, "note": str(entry.get("note") or ""),
                      "review_by": review_by})
    return rules


def accepted_egress_match(rule, mac, domain, dst):
    """True when the source MAC is listed and the domain (suffix) or destination address is covered."""
    if str(mac or "").lower() not in rule["macs"]:
        return False
    domain = str(domain or "").lower().strip(".")
    if domain and any(domain == d or domain.endswith(f".{d}") for d in rule["domains"]):
        return True
    if not rule["nets"]:
        return False
    addr = ipaddress.ip_address(bytes(dst))
    return any(addr in net for net in rule["nets"])


class BeaconDetector:
    """Detect low-jitter recurring outbound flow starts to one destination."""

    def __init__(self, *, min_samples=6, max_cv=0.12, min_period_sec=5,
                 max_period_sec=3600, cooldown_sec=900, max_keys=20_000,
                 ignored_udp_ports=(), ignored_domains=(), ignored_destinations=(),
                 ignored_device_endpoints=()):
        self.min_samples = max(3, int(min_samples))
        self.max_cv = max(0.0, float(max_cv))
        self.min_period_sec = max(0.1, float(min_period_sec))
        self.max_period_sec = max(self.min_period_sec, float(max_period_sec))
        self.cooldown_sec = max(1.0, float(cooldown_sec))
        self.max_keys = max(1, int(max_keys))
        self.ignored_udp_ports = frozenset(int(port) for port in ignored_udp_ports)
        self.ignored_domains = frozenset(
            str(domain).lower().strip(".") for domain in ignored_domains if str(domain).strip(".")
        )
        normalized_destinations = set()
        for value in ignored_destinations:
            try:
                normalized_destinations.add(ipaddress.ip_address(value).packed)
            except ValueError:
                continue
        self.ignored_destinations = frozenset(normalized_destinations)
        # {mac: [(networks, ports)]}: one device's keepalives to its own vendor/resolver ranges only.
        self.ignored_device_endpoints = {}
        for entry in ignored_device_endpoints:
            parsed = device_endpoint_rule(entry)
            if parsed is not None:
                self.ignored_device_endpoints.setdefault(parsed[0], []).append(parsed[1:])
        self.timestamps = {}
        self.last_alert = {}

    def observe(self, flow, now=None):
        if not flow.get("src_local") or flow.get("dst_local"):
            return None
        # Either end: Tailscale's 41641 is the local node's source port toward a peer's random mapped port.
        if (str(flow.get("protocol") or "").upper() == "UDP"
                and {int(flow.get("destination_port") or 0), int(flow.get("source_port") or 0)} & self.ignored_udp_ports):
            return None
        domain = str(flow.get("domain") or "").lower().strip(".")
        if domain and any(domain == suffix or domain.endswith(f".{suffix}") for suffix in self.ignored_domains):
            return None
        if bytes(flow["dst_ip"]) in self.ignored_destinations:
            return None
        rules = self.ignored_device_endpoints.get(str(flow.get("source_mac") or "").lower())
        if rules:
            dst = ipaddress.ip_address(bytes(flow["dst_ip"]))
            port = int(flow.get("destination_port") or 0)
            if any((not ports or port in ports) and any(dst in net for net in nets) for nets, ports in rules):
                return None
        now = float(flow["first_seen"] if now is None else now)
        key = (
            flow.get("source_mac") or bytes(flow["src_ip"]).hex(),
            bytes(flow["dst_ip"]),
            int(flow.get("destination_port") or 0),
            str(flow.get("protocol") or ""),
        )
        if key not in self.timestamps and len(self.timestamps) >= self.max_keys:
            victim = min(self.timestamps, key=lambda candidate: self.timestamps[candidate][-1])
            self.timestamps.pop(victim, None)
            self.last_alert.pop(victim, None)
        samples = self.timestamps.setdefault(key, deque(maxlen=self.min_samples + 2))
        if samples and now <= samples[-1]:
            return None
        samples.append(now)
        if len(samples) < self.min_samples:
            return None
        intervals = [b - a for a, b in zip(samples, list(samples)[1:], strict=False)]
        mean = sum(intervals) / len(intervals)
        if not self.min_period_sec <= mean <= self.max_period_sec:
            return None
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        cv = math.sqrt(variance) / mean if mean else math.inf
        if cv > self.max_cv or now - self.last_alert.get(key, float("-inf")) < self.cooldown_sec:
            return None
        self.last_alert[key] = now
        return {
            "kind": "BEACONING",
            "severity": "alert",
            "flow_id": flow["flow_id"],
            "period_sec": mean,
            "jitter_cv": cv,
            "samples": len(samples),
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "port": flow["destination_port"],
            "protocol": flow["protocol"],
        }


class HumanWebClassifier:
    """Score one outbound web-session observation as human signal or noise.

    Packet capture cannot see which desktop process owns a flow, so this stays
    probabilistic and explainable: destination novelty, hostname context,
    multi-host fan-out, and recurrence cadence. It emits once per flow.
    """

    WEB_PORTS = frozenset({("TCP", 80), ("TCP", 443), ("UDP", 443)})
    BACKGROUND_LABELS = frozenset({
        "ad", "ads", "analytics", "collector", "crash", "crashes",
        "diagnostic", "diagnostics", "eventstream", "firmware", "fw",
        "heartbeat", "ingest", "keepalive", "logs", "metrics", "ota",
        "pixel", "telemetry", "tracking", "update", "updates",
    })
    BACKGROUND_SUFFIXES = (
        "360yield.com",
        "3lift.com",
        "adsafeprotected.com",
        "adsrvr.org",
        "criteo.com",
        "doubleverify.com",
        "dotmetrics.net",
        "events.data.microsoft.com",
        "id5-sync.com",
        "logs.us5.datadoghq.com",
        "pubmatic.com",
        "ring.amazon.dev",
        "rubiconproject.com",
        "scorecardresearch.com",
        "semasio.net",
        "sentry.io",
        "tapad.com",
        "telemetry.data.nvidia.com",
        "tplinkcloud.com",
        "tplinknbu.com",
    )

    def __init__(self, *, max_flows=50_000, dns_window_sec=5, burst_window_sec=8,
                 novel_window_sec=600, periodic_min_samples=6,
                 periodic_max_cv=0.15, background_domains=(),
                 automation_sources=()):
        self.max_flows = max(100, int(max_flows))
        self.dns_window_sec = max(0.1, float(dns_window_sec))
        self.burst_window_sec = max(0.1, float(burst_window_sec))
        self.novel_window_sec = max(self.burst_window_sec, float(novel_window_sec))
        self.periodic_min_samples = max(4, int(periodic_min_samples))
        self.periodic_max_cv = max(0.0, float(periodic_max_cv))
        configured_domains = tuple(
            domain for domain in (
                self._domain(value) for value in self._configured_values(background_domains)
            )
            if domain
        )
        self.background_suffixes = tuple(dict.fromkeys(
            (*self.BACKGROUND_SUFFIXES, *configured_domains),
        ))
        self.automation_sources = frozenset(
            self._canonical_identity(value)
            for value in self._configured_values(automation_sources)
            if self._canonical_identity(value)
        )
        self.pending = OrderedDict()
        self.emitted = OrderedDict()
        self.recent_dns = OrderedDict()
        self.source_bursts = OrderedDict()
        self.target_starts = OrderedDict()
        self.last_target = OrderedDict()

    @staticmethod
    def _source_key(event):
        mac = HumanWebClassifier._canonical_identity(event.get("mac_src"))
        if mac:
            return mac
        try:
            return bytes(event.get("src_ip") or b"").hex()
        except (TypeError, ValueError):
            return ""

    @staticmethod
    def _canonical_identity(value):
        return _canonical_identity_text(str(value or "").strip().lower())

    @staticmethod
    def _configured_values(value):
        if isinstance(value, list | tuple | set | frozenset):
            return value
        return ()

    @classmethod
    def _source_identities(cls, event):
        identities = set()
        mac = cls._canonical_identity(event.get("mac_src"))
        if mac:
            identities.add(mac)
        try:
            packed = bytes(event.get("src_ip") or b"")
            if len(packed) in {4, 16}:
                identities.add(str(ipaddress.ip_address(packed)))
        except (TypeError, ValueError):
            pass
        return identities

    @staticmethod
    def _domain(value):
        value = str(value or "").strip().lower().strip(".")
        return "" if value == "encrypted-payload" else value

    @staticmethod
    def _put_bounded(mapping, key, value, limit):
        mapping[key] = value
        mapping.move_to_end(key)
        while len(mapping) > limit:
            mapping.popitem(last=False)

    def _remember_dns(self, source, event, now):
        try:
            is_query = int(event.get("dns_qr")) == 0
        except (TypeError, ValueError):
            return
        domain = self._domain(event.get("dns_qname"))
        if not source or not is_query or not domain:
            return
        samples = self.recent_dns.get(source)
        if samples is None:
            samples = deque(maxlen=16)
            self._put_bounded(self.recent_dns, source, samples, self.max_flows)
        else:
            self.recent_dns.move_to_end(source)
        samples.append((now, domain))

    def _has_recent_dns(self, source, now, domain):
        samples = self.recent_dns.get(source)
        if not samples or not domain:
            return False
        while samples and now - samples[0][0] > self.dns_window_sec:
            samples.popleft()
        return any(
            0 <= now - timestamp <= self.dns_window_sec
            and (domain == query or domain.endswith(f".{query}"))
            for timestamp, query in samples
        )

    def _background_domain(self, domain):
        if not domain:
            return False
        labels = set(domain.replace("-", ".").split("."))
        return bool(labels & self.BACKGROUND_LABELS) or any(
            domain == suffix or domain.endswith(f".{suffix}")
            for suffix in self.background_suffixes
        )

    def _cadence(self, key, started_at):
        starts = self.target_starts.get(key)
        if starts is None:
            starts = deque(maxlen=self.periodic_min_samples + 2)
            self._put_bounded(self.target_starts, key, starts, self.max_flows)
        if not starts or started_at > starts[-1]:
            starts.append(started_at)
        if len(starts) < self.periodic_min_samples:
            return False, False, 0.0
        intervals = [
            right - left
            for left, right in zip(starts, list(starts)[1:], strict=False)
            if right > left
        ]
        if len(intervals) < self.periodic_min_samples - 1:
            return False, False, 0.0
        mean = sum(intervals) / len(intervals)
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        cv = math.sqrt(variance) / mean if mean > 0 else math.inf
        ordered = sorted(intervals)
        median = ordered[len(ordered) // 2]
        return median >= 5.0 and cv <= self.periodic_max_cv, cv >= 0.75, median

    def _bursting(self, source, target, now):
        samples = self.source_bursts.get(source)
        if samples is None:
            samples = deque(maxlen=64)
            self._put_bounded(self.source_bursts, source, samples, self.max_flows)
        else:
            self.source_bursts.move_to_end(source)
        while samples and now - samples[0][0] > self.burst_window_sec:
            samples.popleft()
        distinct = {prior_target for _, prior_target in samples if prior_target != target}
        samples.append((now, target))
        return len(distinct) >= 2

    def observe(self, event, flow, *, src_local=False, dst_local=False):
        """Return one scored observation dict, otherwise ``None``."""
        if not isinstance(event, dict) or not isinstance(flow, dict):
            return None
        try:
            now = float(event.get("timestamp"))
            port = int(event.get("port") or 0)
        except (TypeError, ValueError, OverflowError):
            return None
        source = self._source_key(event)
        if src_local:
            self._remember_dns(source, event, now)
        protocol = str(event.get("protocol") or "").upper()
        if not src_local or dst_local or (protocol, port) not in self.WEB_PORTS:
            return None

        flow_id = str(flow.get("flow_id") or "")
        if not flow_id or flow_id in self.emitted:
            return None
        if flow.get("first_local_egress") and flow_id not in self.pending:
            try:
                destination = bytes(event.get("dst_ip") or b"").hex()
            except (TypeError, ValueError):
                destination = ""
            self._put_bounded(self.pending, flow_id, {
                "started_at": now,
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "port": port,
            }, self.max_flows)
        pending = self.pending.get(flow_id)
        if pending is None:
            return None

        domain = self._domain(event.get("sni_domain")) or self._domain(flow.get("domain"))
        if protocol == "TCP" and not domain:
            if int(flow.get("packets_down") or 0) < 1:
                return None

        started_at = float(pending["started_at"])
        target = domain or f"{pending['destination']}:{port}"
        target_key = (source, target, protocol, port)
        last_seen = self.last_target.get(target_key)
        novel = last_seen is None or started_at - last_seen > self.novel_window_sec
        self._put_bounded(self.last_target, target_key, started_at, self.max_flows)
        fanout = self._bursting(source, target, started_at)
        periodic, irregular, period_sec = self._cadence(target_key, started_at)
        recent_dns = self._has_recent_dns(source, started_at, domain)
        background_domain = self._background_domain(domain)
        automated_source = bool(
            self.automation_sources & self._source_identities(event)
        )

        score = 1
        reasons = []
        penalties = []
        if domain:
            score += 2
            reasons.append("named host")
        elif recent_dns:
            score += 1
            reasons.append("recent DNS")
        if novel:
            score += 2
            reasons.append("new destination")
        if fanout:
            score += 2
            reasons.append("multi-host burst")
        if irregular:
            score += 1
            reasons.append("irregular timing")
        if background_domain:
            score -= 5
            penalties.append("background-service hostname")
        if periodic:
            score -= 5
            penalties.append(f"regular {period_sec:.0f}s cadence")
        if automated_source:
            score -= 5
            penalties.append("known automated source")
        if background_domain or periodic or automated_source:
            score = min(score, 2)
        elif not domain:
            score = min(score, 4)
            penalties.append("no hostname attribution")
        score = max(0, min(10, score))
        label = "HUMAN LIKELY" if score >= 5 else "HUMAN POSSIBLE" if score >= 3 else "WEB NOISE"
        evidence = penalties + reasons if label == "WEB NOISE" else reasons + penalties

        self.pending.pop(flow_id, None)
        self._put_bounded(self.emitted, flow_id, True, self.max_flows)
        return {
            "label": label,
            "score": score,
            "reason": " · ".join(evidence) or "outbound web session",
            "domain": domain,
            "flow_id": flow_id,
            "started_at": started_at,
        }
