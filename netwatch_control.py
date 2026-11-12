"""Passive Ethernet/IP control evidence; no network transmission or enforcement."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import queue
import sqlite3
import struct
import threading
import time
import uuid

from netwatch_core import DISK_MIN_FREE_BYTES, disk_admission, make_message
from netwatch_inventory import is_usable_mac, normalize_mac
from netwatch_security_store import _event_time, note_notify_failure, retention_status

CONTROL_TYPES = frozenset({"arp", "dhcp", "dhcpv6", "lldp", "stp", "eapol", "lacp", "slow_protocol",
                           "icmp", "icmpv6", "ipv6_rs", "ipv6_ra", "ipv6_ns",
                           "ipv6_na", "ipv6_redirect", "ipv6_fragment"})


def _field_value(value, depth=0):
    """Bound the decoded preview; the complete observed frame remains native evidence."""
    from scapy.packet import Packet

    if depth > 8:
        return {"preview_truncated": True}
    if isinstance(value, bytes):
        return {"hex": value[:4096].hex(), "bytes": len(value), "preview_truncated": len(value) > 4096}
    if isinstance(value, dict):
        return {str(key): _field_value(item, depth + 1) for key, item in value.items()}
    if isinstance(value, tuple | list):
        items = [_field_value(item, depth + 1) for item in value[:128]]
        return items if len(value) <= 128 else {"items": items, "preview_truncated": True, "count": len(value)}
    if isinstance(value, Packet):
        return {"layer": type(value).__name__, "fields": _field_value(value.fields, depth + 1)}
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    try:
        return int(value)  # Scapy flag fields.
    except (ValueError, TypeError):
        return {"preview": str(value)[:1024], "preview_truncated": True}


def _nd_issues(data, packet):
    from scapy.layers.inet6 import in6_chksum

    payload = data["control_payload"]
    minimum = {133: 8, 134: 16, 135: 24, 136: 24, 137: 40}[data["icmp_type"]]
    problems = []
    if len(payload) < minimum:
        return ["Neighbor Discovery header is truncated"]
    if data["ttl"] != 255:
        problems.append("Neighbor Discovery hop limit is not 255")
    if data["icmp_code"] != 0:
        problems.append("Neighbor Discovery code is not zero")
    if data["fragmented"]:
        problems.append("Neighbor Discovery carries a forbidden fragment header")
    source = ipaddress.ip_address(data["src_ip"])
    destination = ipaddress.ip_address(data["dst_ip"])
    if data["icmp_type"] in (134, 137) and not source.is_link_local:
        problems.append("Router advertisement or redirect source is not link-local")
    if data["icmp_type"] in (135, 136):
        target = ipaddress.ip_address(payload[8:24])
        if target.is_multicast:
            problems.append("Neighbor Discovery target is multicast")
        if data["icmp_type"] == 136 and destination.is_multicast and payload[4] & 0x40:
            problems.append("Solicited neighbor advertisement has a multicast destination")
    # Pass the complete upper-layer bytes; do not include Ethernet padding.
    upper = packet.getlayer({133: "ICMPv6ND_RS", 134: "ICMPv6ND_RA", 135: "ICMPv6ND_NS",
                             136: "ICMPv6ND_NA", 137: "ICMPv6ND_Redirect"}[data["icmp_type"]])
    if upper is None:
        problems.append("Installed decoder did not interpret the Neighbor Discovery header")
    elif in6_chksum(58, upper, payload) != 0:
        problems.append("Neighbor Discovery checksum does not verify; capture offload may affect it")
    offset = minimum
    while offset < len(payload):
        if offset + 2 > len(payload) or not payload[offset + 1]:
            problems.append("Neighbor Discovery option has a truncated or zero length")
            break
        option_type, length = payload[offset], payload[offset + 1] * 8
        if offset + length > len(payload):
            problems.append("Neighbor Discovery option exceeds the captured message")
            break
        if source.is_unspecified and option_type == 1:
            problems.append("Unspecified source carries a source link-layer option")
        if option_type == 3:
            if length != 32:
                problems.append("Prefix Information option length is not 32 bytes")
            elif payload[offset + 2] > 128 or struct.unpack_from("!I", payload, offset + 8)[0] > struct.unpack_from("!I", payload, offset + 4)[0]:
                problems.append("Prefix Information length or advertised lifetimes are inconsistent")
        offset += length
    return problems


def decode_control_frame(raw, data):
    """Use the installed protocol implementation only on selected control frames."""
    import scapy.contrib.lacp  # noqa: F401 — register LACP dissection
    import scapy.contrib.lldp  # noqa: F401 — register LLDP dissection
    import scapy.layers.dhcp6  # noqa: F401 — register DHCPv6 dissection
    import scapy.layers.eap  # noqa: F401 — register EAPOL dissection
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.l2 import Dot3, Ether
    from scapy.packet import NoPayload

    kind = data.get("control_type") or "arp"
    payload = data.get("control_payload", b"")
    minimum = {"dhcp": 240, "dhcpv6": 4, "eapol": 4, "stp": 7, "lldp": 2, "lacp": 2}.get(kind, 0)
    if len(payload) < minimum:
        raise ValueError("control protocol header is truncated")
    packet = (Dot3 if struct.unpack_from("!H", raw, 12)[0] <= 1500 else Ether)(raw)
    layers = []
    uninterpreted = False
    current = packet
    for _ in range(128):
        if isinstance(current, NoPayload):
            break
        if type(current).__name__ not in {"Raw", "Padding"}:
            layers.append({"layer": type(current).__name__, "fields": _field_value(current.fields)})
        if type(current).__name__ == "Raw":
            uninterpreted = True
        current = current.payload
    summary = {"layers": layers, "preview_truncated": not isinstance(current, NoPayload), "issues": [],
               "uninterpreted_payload": uninterpreted,
               "validation": "partial protocol checks; identity matches are not authentication"}
    expected = {"arp": "ARP", "eapol": "EAPOL", "stp": "STP", "lldp": "LLDPDU", "lacp": "LACP"}.get(kind)
    if expected and not packet.haslayer(expected):
        summary["issues"].append("Installed decoder did not interpret the expected control protocol")
    if kind == "dhcpv6" and not any(entry["layer"].startswith("DHCP6") for entry in layers):
        summary["issues"].append("Installed decoder did not interpret the DHCPv6 message")
    if kind == "dhcp":
        if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
            raise ValueError("DHCP packet lacks a complete BOOTP header or DHCP options")
        options = {item[0]: item[1:] for item in packet[DHCP].options if isinstance(item, tuple) and len(item) > 1}
        summary.update(message_type=options.get("message-type", (None,))[0],
                       server_id=options.get("server_id", (None,))[0],
                       offered_ip=packet[BOOTP].yiaddr, client_mac=bytes(packet[BOOTP].chaddr)[:packet[BOOTP].hlen].hex(":"),
                       transaction_id=packet[BOOTP].xid, relay_ip=packet[BOOTP].giaddr)
        # Client-asserted identity for the asset model; neither is authenticated.
        hostname, client_id = options.get("hostname", (None,))[0], options.get("client_id", (None,))[0]
        summary.update(hostname=hostname[:255].decode("utf-8", "replace") if isinstance(hostname, bytes) else None,
                       client_id=bytes(client_id[:255]).hex() if isinstance(client_id, bytes) else None)
    elif kind == "dhcpv6":
        if payload[0] in (12, 13) and len(payload) < 34:
            raise ValueError("DHCPv6 relay header is truncated")
        server = packet.getlayer("DHCP6OptServerId")
        summary.update(message_type=payload[0], server_duid=bytes(server.duid).hex() if server is not None else None)
        # ponytail: bounded repeated option lookup; traverse once if measured
        # DHCPv6 option volume makes the 128-option ceiling expensive.
        for name, output in (("DHCP6OptIAPrefix", "delegated_prefixes"), ("DHCP6OptIAAddress", "leases")):
            summary[output] = []
            for index in range(1, 129):
                option = packet.getlayer(name, nb=index)
                if option is None:
                    break
                summary[output].append(_field_value(option.fields))
    elif kind.startswith("ipv6_") and kind != "ipv6_fragment":
        summary["issues"] = _nd_issues(data, packet)
        summary["prefixes"] = [entry["fields"] for entry in layers if entry["layer"] == "ICMPv6NDOptPrefixInfo"]
    elif kind == "eapol" and struct.unpack_from("!H", payload, 2)[0] > len(payload) - 4:
        raise ValueError("EAPOL payload is truncated")
    return summary


class ControlCollector:
    """Native frames and passive review findings commit together before notification."""

    def __init__(self, store, config, notify=None):
        self.store = store
        self.sensor_id = str(config.get("SENSOR_ID") or "unknown")
        self.interface = str(config.get("NIC_INTERFACE") or "unknown")
        self.source_key = f"CONTROL:{self.sensor_id}:{self.interface}"
        self.session = uuid.uuid4().hex
        self.notify = notify
        self.notify_failures = 0
        self.config = config
        self.dhcp_servers = {str(ipaddress.IPv4Address(value)) for value in config.get("CONTROL_TRUSTED_DHCP_SERVERS", [])}
        self.ra_macs = set()
        for value in config.get("CONTROL_TRUSTED_RA_MACS", []):
            normalized = normalize_mac(value)
            if not is_usable_mac(normalized):
                raise ValueError("trusted RA identities must be MAC addresses")
            self.ra_macs.add(normalized)
        self.dhcp6_duids = {bytes.fromhex(value.replace(":", "")).hex() for value in config.get("CONTROL_TRUSTED_DHCPV6_DUIDS", [])}
        if any(len(value) < 4 for value in self.dhcp6_duids):
            raise ValueError("trusted DHCPv6 identities require at least a DUID type")

    @staticmethod
    def decode(raw, data):
        try:
            return decode_control_frame(raw, data)
        except Exception as exc:
            return {"layers": [], "issues": [f"Decoder could not interpret this frame: {type(exc).__name__}"],
                    "decode_error": str(exc)[:1000]}

    def process(self, raw, data, *, event_id=None, received_at=None, decoded=None):
        received = time.time() if received_at is None else received_at
        event_id = event_id or uuid.uuid4().hex
        kind = data.get("control_type") or "arp"
        if kind not in CONTROL_TYPES or len(raw) > 65535 or len(raw) < 14:
            raise ValueError("unsupported control record or oversized frame")
        decoded = self.decode(raw, data) if decoded is None else decoded
        reasons = list(decoded["issues"])
        trust = "not_applicable"
        if kind == "dhcp" and decoded.get("message_type") in (2, 5, 6):
            trust = "unconfigured" if not self.dhcp_servers else "matched" if decoded.get("server_id") in self.dhcp_servers else "unexpected"
        elif kind == "ipv6_ra":
            trust = "unconfigured" if not self.ra_macs else "matched" if data.get("mac_src") in self.ra_macs else "unexpected"
        elif kind == "dhcpv6" and decoded.get("message_type") in (2, 7, 10, 13):
            trust = "unconfigured" if not self.dhcp6_duids else "matched" if decoded.get("server_duid") in self.dhcp6_duids else "unexpected"
        if trust == "unexpected":
            reasons.append("Observed server/router identity is outside the configured allowlist")
        decoded["trust"] = trust
        src = data.get("src_ip") or data.get("sender_ip")
        dst = data.get("dst_ip") or data.get("target_ip")
        src = str(ipaddress.ip_address(src)) if src else None
        dst = str(ipaddress.ip_address(dst)) if dst else None
        normalized = {
            "schema_version": 1, "event_id": event_id, "source_event_id": event_id,
            "source": "CONTROL", "sensor_id": self.sensor_id, "event_type": kind,
            "collector_version": "0.1.0", "address_family": ipaddress.ip_address(src).version if src else None,
            "category": "network_control", "event_time": _event_time(data.get("timestamp"), received),
            "received_at": received, "capture_interface": self.interface,
            "src_ip": src, "dst_ip": dst, "source_port": data.get("source_port"),
            "destination_port": data.get("port"), "mac_src": data.get("mac_src"), "mac_dst": data.get("mac_dst"),
            "vlan_ids": data.get("vlan_ids", []), "direction": "link_observation",
            "capture_bytes": len(raw), "frame_sha256": hashlib.sha256(raw).hexdigest(),
            "summary": decoded,
        }
        native = {"encoding": "hex", "frame": raw.hex(), "capture_timestamp": data.get("timestamp"),
                  "session": self.session, "interface": self.interface}
        finding = None
        if reasons:
            finding = make_message("CONTROL", "CONTROL_REVIEW", "SYSTEM", {
                "source_event_id": event_id, "sensor_id": self.sensor_id,
                "timestamp": normalized["event_time"], "message": f"{kind.upper()} review: " + "; ".join(reasons),
                "severity": "anomaly", "confidence": "Observed", "reasons": reasons,
                "native_event_id": event_id, "containment_eligible": False,
                "correlation_entity": json.dumps([self.source_key, normalized["vlan_ids"], kind, data.get("mac_src")]),
                "capture_interface": self.interface, "vlan_ids": normalized["vlan_ids"],
            }, correlation_id=event_id)
        accepted = self.store.accept_source_record(self.source_key, {"session": self.session, "last_event_id": event_id},
                                                    normalized, native, finding)
        if accepted and finding and self.notify:
            try:
                self.notify(finding)
            except Exception:
                note_notify_failure(self)  # Presentation does not revoke the durable acceptance.
        return normalized

    def gap(self, reason, count=None):
        now, event_id = time.time(), uuid.uuid4().hex
        normalized = {"schema_version": 1, "event_id": event_id, "source": "CONTROL",
                      "sensor_id": self.sensor_id, "event_type": "collector_gap", "category": "collection_gap",
                      "event_time": now, "received_at": now, "capture_interface": self.interface,
                      "reason": reason, "count": count}
        finding = make_message("CONTROL", "CONTROL_COLLECTION_GAP", "SYSTEM", {
            "source_event_id": event_id, "sensor_id": self.sensor_id, "message": reason,
            "correlation_entity": self.source_key,
            "severity": "anomaly", "count": count, "containment_eligible": False,
        }, correlation_id=event_id)
        self.store.accept_source_record(self.source_key, {"session": self.session, "last_event_id": event_id},
                                        normalized, {"reason": reason, "count": count}, finding)
        if self.notify:
            try:
                self.notify(finding)
            except Exception:
                note_notify_failure(self)


CONTROL_COMMIT_FRAMES = 64


class ControlCaptureWorker:
    """A bounded pre-commit buffer; queued frames are not durable acknowledgments."""

    def __init__(self, collector, *, max_pending=1024, heartbeat_sec=5):
        self.collector = collector
        self.pending = queue.Queue(maxsize=max(1, int(max_pending)))
        self.heartbeat_sec = max(0.1, float(heartbeat_sec))
        self.stop_event = threading.Event()
        self.deadline = float("inf")
        self.lock = threading.Lock()
        self.dropped = 0
        self.pending_drops = 0
        self.accepted = 0
        self.last_error = None
        self.last_event_time = None
        self.retention = {}
        self.disk_drops = 0
        self.disk = {"admitted": True, "free_bytes": None,
                     "floor_bytes": collector.config.get("DISK_MIN_FREE_BYTES", DISK_MIN_FREE_BYTES)}
        previous = self.collector.store.source_health(self.collector.source_key)
        self.startup_gap = bool(previous and previous.get("state") != "stopped")
        try:
            self.collector.store.record_source_health(self.collector.source_key, self.health())
        except sqlite3.OperationalError:
            pass  # A busy store must not stop capture start; the collector thread re-records health.
        self.thread = threading.Thread(target=self._run, name="control-collector", daemon=True)
        self.thread.start()

    def submit(self, raw, data):
        with self.lock:
            if self.stop_event.is_set():
                return False
            if (len(raw) > 65535 or len(raw) < 14 or not isinstance(data, dict)
                    or (data.get("control_type") or "arp") not in CONTROL_TYPES
                    or _event_time(data.get("timestamp"), None) is None):
                self.dropped += 1
                self.pending_drops += 1
                return False
            try:
                self.pending.put_nowait((bytes(raw), dict(data), uuid.uuid4().hex, time.time()))
                return True
            except queue.Full:
                self.dropped += 1
                self.pending_drops += 1
                return False

    def health(self):
        with self.lock:
            degraded = (self.last_error or self.pending_drops or self.disk_drops
                        or not self.disk["admitted"] or (self.retention and retention_status(
                            self.retention, self.collector.config.get("CONTROL_MAX_ROWS", 200_000),
                            self.collector.config.get("CONTROL_MAX_BYTES", 268_435_456)) == "DEGRADED"))
            return {"session": self.collector.session, "state": "running", "status": "DEGRADED" if degraded else "RUNNING",
                    "accepted": self.accepted, "dropped": self.dropped, "backlog": self.pending.unfinished_tasks,
                    "last_error": self.last_error, "last_event_time": self.last_event_time,
                    "notify_failures": self.collector.notify_failures,
                    "retention": dict(self.retention), "disk": dict(self.disk, refused_frames=self.disk_drops),
                    "policy": {"dhcp": bool(self.collector.dhcp_servers), "ra": bool(self.collector.ra_macs),
                               "dhcpv6": bool(self.collector.dhcp6_duids)}}

    def _disk_admitted(self):
        admitted, free = disk_admission(self.collector.store.path, self.disk["floor_bytes"])
        with self.lock:
            self.disk.update(admitted=admitted, free_bytes=free)
        return admitted

    def _run(self):
        startup_gap = self.startup_gap
        jobs = []
        last_health = 0.0
        last_retention = float("-inf")  # not 0.0: monotonic() is host uptime, < the interval on a fresh runner
        retention_totals = None
        backlog_after = 0.0  # backlog batches rest between turns so other writers get the lock
        while (not self.stop_event.is_set() or jobs or not self.pending.empty() or startup_gap
               or self.pending_drops or self.disk_drops):
            if time.monotonic() >= self.deadline:
                return  # Leave running health: restart records an unclean-session gap.
            try:
                if startup_gap:
                    self.collector.gap("Previous control collector ended without a clean drain; missing frame count is unknown")
                    startup_gap = False
                with self.lock:
                    lost = self.pending_drops
                if lost:
                    self.collector.gap("Control capture buffer overflow; these observed frames were not committed", lost)
                    with self.lock:
                        self.pending_drops -= lost
                admitted = self._disk_admitted()
                with self.lock:
                    # One exact gap per low-space episode, written on recovery or stop.
                    refused = self.disk_drops if admitted or self.stop_event.is_set() else 0
                if refused:
                    self.collector.gap("Data volume free space was below DISK_MIN_FREE_BYTES; "
                                       "these observed frames were not committed", refused)
                    with self.lock:
                        self.disk_drops -= refused
                # Frames first: a backlog batch every turn starved commits and overflowed the buffer.
                if ((retention_totals is not None and self.pending.empty() and time.monotonic() >= backlog_after)
                        or time.monotonic() - last_retention
                        >= max(1, float(self.collector.config.get("CONTROL_PRUNE_INTERVAL_SEC", 60)))):
                    batch = self.collector.config.get("CONTROL_PRUNE_BATCH_ROWS", 128)
                    # Taken before the call: a pass that raises waits the interval instead of
                    # repeating every turn and blocking commits (the sensor's damaged store, 2026-10-11).
                    totals, retention_totals = retention_totals, None
                    last_retention = time.monotonic()
                    report = self.collector.store.prune_control_records(
                        max_rows=self.collector.config.get("CONTROL_MAX_ROWS", 200_000),
                        max_bytes=self.collector.config.get("CONTROL_MAX_BYTES", 268_435_456),
                        retention_days=self.collector.config.get("CONTROL_RETENTION_DAYS", 7),
                        arp_enabled=self.collector.config.get("ARP_DETECTION_ENABLED", True),
                        batch=batch, totals=totals,
                    )
                    with self.lock:
                        self.retention = report
                    # A full batch can leave work behind: take the next one next turn on the same
                    # quota totals. One batch a minute fell behind the sensor's ~19k control rows/hour.
                    retention_totals = (report["rows"], report["payload_bytes"]) if report["pruned"] >= batch else None
                    # Rest 3x the batch's own time: back-to-back batches held the shared writer lock
                    # nearly always on the sensor and starved every other writer past its busy timeout.
                    backlog_after = time.monotonic() + 3 * (time.monotonic() - last_retention)
                if time.monotonic() - last_health >= self.heartbeat_sec:
                    self.collector.store.record_source_health(self.collector.source_key, self.health())
                    last_health = time.monotonic()
                    with self.lock:
                        self.last_error = None
                if not jobs:
                    try:
                        jobs = [self.pending.get(timeout=0.1)]
                    except queue.Empty:
                        continue
                    while len(jobs) < CONTROL_COMMIT_FRAMES:
                        try:
                            jobs.append(self.pending.get_nowait())
                        except queue.Empty:
                            break
                if not self._disk_admitted():
                    with self.lock:
                        self.dropped += len(jobs)
                        self.disk_drops += len(jobs)
                    for _ in jobs:
                        self.pending.task_done()
                    jobs = []
                    continue
                # One commit (one fsync) per burst, not per frame: per-frame commits held the shared
                # writer lock ~1 s each on the sensor VM and starved the core for 30 s. Findings are
                # presented only after the commit, as before.
                # Scapy decoding stays outside the lock (it was the slow part of a held burst).
                decoded = [self.collector.decode(raw, data) for raw, data, _, _ in jobs]
                notify, held = self.collector.notify, []
                self.collector.notify = held.append if notify else None
                try:
                    with self.collector.store._transaction():
                        last = [self.collector.process(raw, data, event_id=event_id, received_at=received,
                                                       decoded=frame)
                                for (raw, data, event_id, received), frame in zip(jobs, decoded, strict=True)][-1]
                finally:
                    self.collector.notify = notify
                for finding in held:
                    try:
                        notify(finding)
                    except Exception:
                        note_notify_failure(self.collector)  # Presentation does not revoke the durable acceptance.
                with self.lock:
                    self.accepted += len(jobs)
                    self.last_error = None
                    self.last_event_time = last["event_time"]
                for _ in jobs:
                    self.pending.task_done()
                jobs = []
            except Exception as exc:
                with self.lock:
                    self.last_error = str(exc)[:1000]
                time.sleep(0.1)
        try:
            health = self.health() | {"state": "stopped", "status": "STOPPED"}
            self.collector.store.record_source_health(self.collector.source_key, health)
        except Exception:
            pass  # An uncommitted clean-stop marker is treated as an unclean stop.

    def close(self, timeout=3):
        self.deadline = time.monotonic() + max(0, timeout)
        self.stop_event.set()
        self.thread.join(timeout=max(0, timeout) + 0.2)
        return not self.thread.is_alive() and self.pending.unfinished_tasks == 0 and not self.last_error
