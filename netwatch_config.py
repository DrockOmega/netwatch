"""Configuration: defaults, on-disk overlays, and network self-discovery.

The runtime config used to be a dict literal buried inside ``main.py``'s
``__main__`` block, which meant two hosts capturing on two different NICs could
not share one checkout without editing source. This module makes it data:

    DEFAULTS  ->  netwatch.config.json  ->  netwatch.<hostname>.json  ->  $NETWATCH_CONFIG

Each layer is a shallow JSON overlay on the one before it, so an overlay only
names the keys it changes. Relative paths in path-shaped keys are resolved
against the base directory (next to the script / frozen exe).

Also here: the two pieces of network self-discovery the config depends on — the
default gateway (so ARP rebinds of *the* gateway can be escalated) and the host's
delegated global IPv6 prefixes (so LAN IPv6 is recognised as local). Both are
best-effort and degrade to empty without raising.
"""

import ipaddress
import json
import os
import socket
import subprocess
from typing import Any

from netwatch_core import DISK_MIN_FREE_BYTES, compile_networks

# Config keys whose value is a filesystem path; a relative value is resolved
# against the base dir so an overlay can say "telemetry.db" and mean "next to the
# app", while an absolute value is honoured verbatim.
PATH_KEYS = (
    "DB_NAME", "INCIDENT_DB", "SIG_FILE", "GEO_DB", "OUI_DB", "DEVICE_LEDGER", "BASELINE_LEDGER",
    "DNS_LEDGER", "JA3_LEDGER", "JA3_BLOCKLIST", "THREATINTEL_CACHE",
    "BLOCK_LEDGER", "QUARANTINE_LEDGER", "RESPONSE_MODE_LEDGER", "LOG_DIR",
    "POLICY_FILE", "POLICY_DECISION_LEDGER", "EVIDENCE_DIR",
    "SURICATA_EVE_PATH", "SPOOL_PATH", "CORRELATION_RULES",
)

BUNDLED_RESOURCE_KEYS = frozenset({"SIG_FILE", "OUI_DB", "JA3_BLOCKLIST", "POLICY_FILE", "CORRELATION_RULES"})

CAPTURE_PROFILES = {
    "full": None,  # No kernel exclusions: control planes, tags and fragments survive.
    "balanced": "not (tcp and len < 80 and tcp[13] == 0x10)",
}

DEFAULTS: dict[str, Any] = {
    "INCIDENT_DB": "telemetry_security.db",
    # --- capture ---------------------------------------------------------
    # scapy 2.7.0 sniff() resolves EITHER the adapter description string or the
    # connection name ("Ethernet 3"). To re-enumerate (note: get_windows_if_list
    # moved out of scapy.all):
    #   python -c "from scapy.arch.windows import get_windows_if_list; [print(i['name'],'|',i['description']) for i in get_windows_if_list()]"
    "NIC_INTERFACE": "Realtek Gaming USB 2.5GbE Family Controller",
    "CAPTURE_PROFILE": "full",
    # None uses the named profile. An explicit filter is an intentional coverage
    # restriction; full capture includes ACKs rather than claiming complete totals
    # after dropping them. balanced is available when measured load requires it.
    "BPF_FILTER": None,
    "SENSOR_ID": "",  # default: hostname; use a stable enrolled ID centrally
    # Packets are shipped to the analytics core in batches. One IPC message per
    # packet made pickle/pipe overhead — not detection — the throughput ceiling.
    "INGEST_BATCH_MAX": 512,     # flush a batch once it holds this many events
    "INGEST_BATCH_SEC": 0.1,     # ...or this long after the batch was opened
    "CORE_SHARDS": 4,  # analytics shard processes plus one merge; 1 = the single core
    "PCAP_STATS_INTERVAL_SEC": 10,  # how often to report kernel-level capture drops
    "PCAP_BUFFER_BYTES": 268_435_456,  # 256 MiB Npcap buffer absorbs multi-second bursts
    "PCAP_DRAIN_BATCH": 2048,          # raw frames drained per readiness wake
    "PCAP_IDLE_BACKOFF_SEC": 0.001,    # prevent stale Npcap readiness from busy-spinning
    "PCAP_ALERT_MIN_LOSS_PCT": 0.1,   # UI degrades above this interval loss rate
    "PCAP_UI_ALERT_INTERVAL_SEC": 60, # repeat persistent loss at most once/minute
    "PCAP_RECOVERY_SAMPLES": 2,       # clean intervals required before recovery

    # --- storage ---------------------------------------------------------
    "DB_NAME": "telemetry_ledger.db",
    "DB_BATCH_CEILING": 5000,
    "DB_QUEUE_BATCHES": 128,
    "DB_RETENTION_DAYS": 7,          # 0 disables age-based pruning
    "DB_MAX_ROWS": 20_000_000,       # bounded target enforced at prune intervals; 0 disables
    "DB_PRUNE_INTERVAL_SEC": 600,
    "DB_PRUNE_BATCH_ROWS": 25_000,   # bounded commits keep ingestion/watchdogs responsive
    "DB_HEARTBEAT_TIMEOUT_SEC": 10,  # tolerates maintenance, not a dead worker
    "DB_WAL_MAX_BYTES": 67_108_864,  # cap reusable WAL high-water space at 64 MiB
    "WEB_OBSERVATION_MAX_ROWS": 100_000,  # durable derived sessions, independent of packet tail
    "WEB_OBSERVATION_BUFFER_MAX": 10_000, # bounded retry buffer during DB backpressure
    "SPOOL_PATH": "telemetry_spool.db",
    "SPOOL_MAX_BYTES": 67_108_864,   # 64 MiB hard admission ceiling for spooled rows
    "SPOOL_WAL_MAX_BYTES": 16_777_216,
    "SPOOL_RETRY_INTERVAL_SEC": 1.0,
    # Free-space floor on each data volume; below it telemetry, evidence and
    # native records are refused and only gap/health records are written.
    "DISK_MIN_FREE_BYTES": DISK_MIN_FREE_BYTES,
    "METADATA_RETENTION_DAYS": 30,   # prune tombstones/prune audit/orphan order rows; 0 disables
    "CASE_RETENTION_DAYS": 365,      # delete unpinned closed cases after this; 0 disables
    "ASSET_RETENTION_DAYS": 90,      # delete idle assets unless a case, action or open finding pins them; 0 disables
    # SURICATA native payload targets; 0 disables a bound.
    "NATIVE_RETENTION_DAYS": 7,
    "NATIVE_MAX_ROWS": 1_000_000,
    "NATIVE_MAX_BYTES": 1_073_741_824,
    "NATIVE_METADATA_RETENTION_DAYS": 1,  # SURICATA and CONTROL tombstones/prune audit; 0 = METADATA_RETENTION_DAYS

    # --- locality --------------------------------------------------------
    # Canonical RFC1918 networks. Loopback, link-local, multicast, broadcast and
    # unspecified addresses are structurally local in the shared classifier.
    # Existing overlays may still supply legacy dotted prefixes.
    "LOCAL_PREFIXES": [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    ],
    # Globally-routable IPv6 prefixes that are nonetheless YOUR LAN (the ISP's
    # delegated prefix). Left empty + auto-detected from the host's own global
    # addresses; set explicitly to pin a delegation that changes on reconnect.
    "LOCAL_PREFIXES6": [],
    "LOCAL_PREFIXES6_AUTO": True,
    "LOCAL_PREFIX6_LEN": 64,

    # --- detectors -------------------------------------------------------
    "DETECTOR_BUCKETS": 20,      # sub-buckets per window; resolution = window/this
    "MAX_ENTITIES": 2048,
    "EXFIL_THRESHOLD_BYTES": 100_000_000,
    "EXFIL_WINDOW_SEC": 10,
    "EXFIL_ALERT_COOLDOWN_SEC": 900,
    "SWEEP_WINDOW_SEC": 5,
    "SWEEP_THRESHOLD_PORTS": 50,
    "SWEEP_IGNORE_SOURCES": [],
    "UDP_FLOOD_WINDOW_SEC": 2,
    "UDP_FLOOD_THRESHOLD": 10000,
    "UDP_FLOOD_IGNORE_DEVICE_ENDPOINTS": [],
    "EXFIL_IGNORE_DEVICE_WINDOWS": [],
    "TUNNEL_UDP_PORTS": [],
    "GC_INTERVAL_SEC": 60,
    "GC_STALE_SEC": 120,
    "ARENA_ALERT_INTERVAL_SEC": 60,  # suppress repeated capacity notices
    "DETECTOR_ALERT_COOLDOWN_SEC": 60,  # one incident per detector/key/minute
    "OS_THRESHOLD_NIX": 64,
    "OS_THRESHOLD_WIN": 128,
    "SIG_FILE": "threat_signatures.json",
    "GEO_DB": "GeoLite2-Country.mmdb",

    # --- device inventory (roadmap #1; passive) ---------------------------
    "DEVICE_INVENTORY_ENABLED": True,
    "DEVICE_NEW_ALERT": True,
    "OUI_DB": "oui_db.json",
    "DEVICE_LEDGER": "telemetry_devices.json",
    "DEVICE_SAVE_INTERVAL_SEC": 10,

    # --- wireless/IoT (passive; no AP telemetry) --------------------------
    "WIRELESS_AP_ADDRESSES": [],  # access points that must stay bridges (never serve DHCP / NAT)
    "WIRELESS_AP_MACS": [],
    "WIRELESS_QUIET_SEC": 86400,  # a known non-private device silent this long is reported once

    # --- per-device baselining (roadmap #2; passive) ----------------------
    "BASELINE_ENABLED": True,
    "BASELINE_WINDOW_SEC": 60,
    "BASELINE_ALPHA": 0.1,
    "BASELINE_WARMUP": 10,
    "BASELINE_Z": 4.0,
    "BASELINE_ABS_FLOOR": 50_000,
    "BASELINE_REL_FLOOR": 0.15,
    "BASELINE_LEDGER": "telemetry_baseline.json",

    # --- ARP-spoof / MITM (roadmap #3; passive) ---------------------------
    "ARP_DETECTION_ENABLED": True,
    "GATEWAY_IP": "",            # "" => auto-detect at boot and refresh periodically
    "GATEWAY_REFRESH_SEC": 300,  # re-detect so a DHCP/network change re-anchors MITM escalation
    # Protected-set pins for service response actions; "" => OWN_IP auto-detected, MACs unchecked.
    "OWN_IP": "",
    "OWN_MAC": "",
    "GATEWAY_MAC": "",
    "ARP_MAC_FANOUT_THRESHOLD": 4,
    "ARP_REBIND_CONFIRMATIONS": 3,
    "ARP_REBIND_MIN_SEC": 2.0,
    "ARP_REBIND_WINDOW_SEC": 10.0,

    # Passive control records share INCIDENT_DB; queued frames are not commits.
    "CONTROL_CAPTURE_ENABLED": True,
    "CONTROL_CAPTURE_MAX_PENDING": 1024,
    "CONTROL_HEARTBEAT_SEC": 5,
    "CONTROL_MAX_ROWS": 200_000,
    "CONTROL_MAX_BYTES": 268_435_456,
    "CONTROL_RETENTION_DAYS": 7,
    "CONTROL_PRUNE_INTERVAL_SEC": 60,
    # Each batch is one write transaction on the shared security store: at 128 rows the
    # deletes, tombstones and hashing held the lock past other writers' 5 s busy timeout.
    "CONTROL_PRUNE_BATCH_ROWS": 128,
    "RUNTIME_HEARTBEAT_TIMEOUT_SEC": 10,
    "RUNTIME_START_GRACE_SEC": 120,  # first heartbeat allowance for a new generation
    # Ordered service-stop budget: collectors, capture/core drain, then up to 8 s of spool replay
    # plus fsyncs. Keep it under the unit's TimeoutStopSec (90) or systemd kills the drain.
    "RUNTIME_STOP_GRACE_SEC": 60,
    "CONTROL_TRUSTED_DHCP_SERVERS": [],
    "CONTROL_TRUSTED_RA_MACS": [],
    "CONTROL_TRUSTED_DHCPV6_DUIDS": [],

    # --- DNS analytics (roadmap #4; passive) ------------------------------
    "DNS_ANALYTICS_ENABLED": True,
    "DNS_DGA_THRESHOLD": 0.7,
    "DNS_NXDOMAIN_WINDOW_SEC": 30,
    "DNS_NXDOMAIN_THRESHOLD": 10,
    "DNS_IGNORE_SUFFIXES": [],
    "DNS_TUNNEL_IGNORE_SUFFIXES": [],
    "DNS_TUNNEL_IGNORE_DEVICE_SUFFIXES": [],
    "DNS_LEDGER": "telemetry_dns.json",

    # --- JA3/JA3S (roadmap #5; passive) -----------------------------------
    "JA3_ENABLED": True,
    "JA3_BLOCKLIST": "ja3_blocklist.json",
    "JA3_LEDGER": "telemetry_ja3.json",

    # --- threat intel (roadmap #6; reads a local cache only) --------------
    "THREATINTEL_ENABLED": True,
    "THREATINTEL_CACHE": "threatintel_cache.json",
    "THREATINTEL_RELOAD_SEC": 300,

    # --- stateful flow/session analytics --------------------------------
    "FLOW_TRACKING_ENABLED": True,
    "FLOW_MAX_ACTIVE": 100_000,
    "FLOW_TCP_IDLE_SEC": 300,
    "FLOW_UDP_IDLE_SEC": 60,
    # Extend the built-in service/telemetry suffixes or mark known autonomous
    # source IPs/MACs. These sessions remain visible under WEB NOISE.
    "WEB_BACKGROUND_DOMAINS": [],
    "WEB_AUTOMATION_SOURCES": [],
    "BEACONING_ENABLED": True,
    "BEACON_MIN_SAMPLES": 6,
    "BEACON_MAX_CV": 0.12,
    "BEACON_MIN_PERIOD_SEC": 5,
    "BEACON_MAX_PERIOD_SEC": 3600,
    "BEACON_COOLDOWN_SEC": 900,
    # Periodic infrastructure is a poor generic-beacon signal. These services
    # remain observable through their protocol and policy layers.
    "BEACON_IGNORE_UDP_PORTS": [123, 3478, 5349],
    "BEACON_IGNORE_DOMAINS": [],
    "BEACON_IGNORE_DESTINATIONS": [],
    "BEACON_IGNORE_DEVICE_ENDPOINTS": [],
    "ACCEPTED_EGRESS": [],

    # --- ordered IPS policy control plane -------------------------------
    # Policy runs in MANUAL so every block intent reaches the UI response plane.
    # RESPONSE_MODE is the live authority that ignores, queues, or enforces it.
    "POLICY_ENABLED": True,
    "POLICY_MODE": "manual",
    "POLICY_FILE": "policy_rules.json",
    "POLICY_RELOAD_SEC": 5,
    "POLICY_DECISION_LEDGER": "telemetry_policy_decisions.jsonl",
    # Cross-source correlation rule pack (committed); a missing file disables cross-source joins.
    "CORRELATION_RULES": "correlation_rules.json",
    "POLICY_LEDGER_MAX_BYTES": 20_000_000,

    # --- packet evidence capture ----------------------------------------
    "EVIDENCE_CAPTURE_ENABLED": True,
    "EVIDENCE_DIR": "evidence",
    "EVIDENCE_PRE_SEC": 15,
    "EVIDENCE_POST_SEC": 5,
    "EVIDENCE_RING_MAX_BYTES": 67_108_864,
    "EVIDENCE_MAX_FILES": 100,
    "EVIDENCE_MAX_BYTES": 2_147_483_648,
    "EVIDENCE_RETENTION_DAYS": 7,
    "EVIDENCE_MAX_PENDING": 32,
    "EVIDENCE_MAX_WRITE_JOBS": 8,
    "EVIDENCE_COALESCE_SEC": 2.0,
    "EVIDENCE_CAPTURE_COOLDOWN_SEC": 900,
    "EVIDENCE_CAPTURE_ACTIONS": [
        "ALERT", "ARP_ANOMALY", "DNS_ANOMALY", "JA3_ANOMALY",
        "BEACON_ANOMALY", "POLICY_DECISION", "SURICATA_ALERT",
    ],

    # --- optional Suricata EVE integration ------------------------------
    "SURICATA_EVE_ENABLED": False,
    "SURICATA_EVE_PATH": "eve.json",
    "SURICATA_EVE_START_AT_END": False,
    "SURICATA_HEARTBEAT_SEC": 5,
    "SURICATA_SOURCE_TIMEOUT_SEC": 60,

    # --- exposure management (phase 4) -----------------------------------
    # CIDRs NetWatch owns. netwatch_scan refuses to ingest nmap results for hosts outside them.
    "EXPOSURE_OWNED_SCOPES": ["10.0.0.0/24"],

    # --- active mitigation ------------------------------------------------
    # Response engines are hot by default. READY queues actions for approval;
    # AUTONOMOUS enforces new eligible findings; IDS_ONLY suppresses new actions.
    "RESPONSE_MODE": "ids_only",
    "RESPONSE_MODE_LEDGER": "telemetry_response_mode.json",
    "MITIGATION_ENABLED": True,
    "MITIGATION_DRY_RUN": False,
    "MITIGATION_TTL_SEC": 3600,
    # Addresses no response may ever target (e.g. the ISP's DNS resolvers).
    "ALLOWLIST_IPS": [],
    "BLOCK_LEDGER": "telemetry_blocks.json",

    # --- active LAN quarantine (ACTIVE EMISSION) --------------------------
    # Severs a local device via ARP cache poisoning from this host — the only
    # enforcement point available behind a locked ISP gateway. READY keeps this
    # live but approval-gated. AUTONOMOUS emits on an eligible trigger.
    # BIDIRECTIONAL also poisons the gateway (return path). SINK_MAC is the black
    # hole the victim's gateway route is redirected to ("" => this host's MAC).
    "QUARANTINE_ENABLED": True,
    "QUARANTINE_DRY_RUN": False,
    "QUARANTINE_TTL_SEC": 1800,
    "QUARANTINE_MAX_ACTIVE": 64,
    "QUARANTINE_REASSERT_SEC": 2.0,
    "QUARANTINE_BIDIRECTIONAL": True,
    "QUARANTINE_SINK_MAC": "02:00:00:00:de:ad",
    "QUARANTINE_IFACE": "",           # "" => reuse NIC_INTERFACE
    "QUARANTINE_ON_ARP_ANOMALY": True,  # enqueue a pending quarantine on ARP-spoof alerts
    "QUARANTINE_LEDGER": "telemetry_quarantine.json",

    # --- UI ---------------------------------------------------------------
    "UI_FRAME_MS": 33,           # GL animation interval; animation pauses when hidden
    "UI_LOG_BLOCKS": 10_000,     # retained/reloaded raw activity summaries
    "UI_OBSERVATION_LOG_BLOCKS": 10_000,  # retained/reloaded derived web sessions
    "UI_OBSERVATION_RELOAD_SEC": 5,       # SQLite reconciliation closes IPC-loss gaps
    "UI_ACTIVITY_RELOAD_SEC": 5,          # durable raw activity reconciliation
    "UI_TRAFFIC_LOOKBACK_SEC": 86_400,    # filtered durable snapshots cover the last 24h
    "CAPTURE_TOPOLOGY": "endpoint",  # endpoint | mirror | bridge | gateway
    "CAPTURE_COVERAGE_ASSERTION": "unverified",  # unverified | partial | complete
    "SENSOR_COVERAGE_WINDOW_SEC": 900,
    "SENSOR_COVERAGE_EMIT_SEC": 5,
    # Optional operator-defined nodes that can be hidden from the Traffic page.
    # Shape: {"Name": {"ips": ["10.0.0.2"], "macs": ["aa:bb:cc:dd:ee:ff"]}}
    # Source-only and either-endpoint exclusion are separate operator modes.
    "SECURE_NODES": {},
    "HISTORY_OVERVIEW_REFRESH_SEC": 60,
    "HISTORY_DETAIL_REFRESH_SEC": 30,

    # --- logging ----------------------------------------------------------
    "LOG_DIR": "logs",
    "LOG_LEVEL": "INFO",
    "LOG_TO_CONSOLE": True,
    "LOG_MAX_BYTES": 5_000_000,
    "LOG_BACKUPS": 3,
}


def detect_default_gateway():
    """Best-effort IPv4 default gateway, used to escalate ARP rebinds of the
    gateway (the classic MITM). Returns "" if undetermined — ARP detection still
    works, just without gateway-specific escalation."""
    if os.name != "nt":
        return _proc_route_gateway()
    try:
        out = subprocess.run(
            ["route", "print", "-4", "0.0.0.0"],
            capture_output=True, text=True, timeout=5, check=True,  # a failed run's output is not a route table
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw = parts[2]
            if gw.count(".") == 3 and gw != "0.0.0.0":
                return gw
    return ""


PROC_NET_ROUTE = "/proc/net/route"


def _proc_route_gateway():
    """Linux default gateway (lowest metric) from the kernel route table; "" if none."""
    best = None
    try:
        with open(PROC_NET_ROUTE, encoding="ascii") as handle:
            for row in (line.split() for line in handle.readlines()[1:]):
                # Iface Destination Gateway Flags RefCnt Use Metric Mask; addresses are little-endian hex.
                if len(row) >= 8 and row[1] == "00000000" and row[7] == "00000000" and int(row[3], 16) & 3 == 3:
                    gw = str(ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(row[2]), "little")))
                    if best is None or int(row[6]) < best[0]:
                        best = (int(row[6]), gw)
    except (OSError, ValueError):
        return ""
    return best[1] if best else ""


def detect_own_ipv4():
    """This host's primary IPv4 (the source address for default-route egress), or
    "". Used so quarantine never targets this host. No packet is sent — connecting
    a UDP socket only selects a route."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.connect(("1.1.1.1", 53))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        if sock is not None:
            sock.close()


def _outbound_v6_address():
    """The source address the OS would pick for global IPv6 egress, or None.
    Connecting a UDP socket only sets a route/source — no packet is sent."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.connect(("2606:4700:4700::1111", 53))
        return sock.getsockname()[0].split("%")[0]
    except OSError:
        return None
    finally:
        if sock is not None:
            sock.close()


def detect_local_v6_prefixes(prefix_len=64):
    """Delegated global IPv6 prefixes belonging to this host's LAN, as CIDR
    strings. Union of the host's own resolvable global addresses and the source
    address the routing table would pick for global egress (which catches the
    common case where ``gethostname()`` does not resolve to the v6 address)."""
    found = []
    candidates = []

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            candidates.append(info[4][0].split("%")[0])
    except (OSError, UnicodeError):
        pass

    outbound = _outbound_v6_address()
    if outbound:
        candidates.append(outbound)

    for addr in candidates:
        try:
            parsed = ipaddress.IPv6Address(addr)
        except ValueError:
            continue
        # Structural locality is already handled in netwatch_core.is_local_ip;
        # only GUAs need a prefix recorded here.
        if (parsed.is_link_local or parsed.is_loopback or parsed.is_private
                or parsed.is_multicast or parsed.is_unspecified):
            continue
        cidr = str(ipaddress.IPv6Network(f"{addr}/{prefix_len}", strict=False))
        if cidr not in found:
            found.append(cidr)
    return found


def _overlay_paths(base_dir, hostname):
    """Overlay files in increasing precedence; absent default files are skipped."""
    candidates = [p for p in (os.path.join(base_dir, "netwatch.config.json"),
                              os.path.join(base_dir, f"netwatch.{hostname}.json")) if os.path.isfile(p)]
    env_path = os.environ.get("NETWATCH_CONFIG")
    if env_path:
        candidates.append(env_path)  # named explicitly: a missing file is reported by load_overlay, not skipped
    return candidates


def load_overlay(path):
    """Read one JSON overlay. A malformed or unreadable overlay is skipped with a
    reason rather than taking startup down. Returns ``(dict, error_or_None)``."""
    try:
        with open(path, encoding="utf-8-sig") as handle:  # Windows tools often write a BOM
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return {}, f"{path}: {type(exc).__name__}: {exc}"
    if not isinstance(data, dict):
        return {}, f"{path}: top level must be a JSON object"
    return data, None


def build_config(base_dir, *, hostname=None, extra=None, resource_dir=None):
    """Assemble the runtime config. Returns ``(config, notes)`` where ``notes`` is
    a list of human-readable lines about what was loaded, skipped, or detected —
    the caller logs them once the logging subsystem exists."""
    hostname = hostname or socket.gethostname()
    config = dict(DEFAULTS)
    notes = []

    for path in _overlay_paths(base_dir, hostname):
        data, error = load_overlay(path)
        if error:
            notes.append(f"WARNING: config overlay SKIPPED, all its settings ignored — {error}")
            continue
        # Keys starting with "_" are annotations (JSON has no comment syntax); the
        # shipped example uses them, so they must not be reported as typos.
        unknown = sorted(k for k in set(data) - set(DEFAULTS) if not str(k).startswith("_"))
        if unknown:
            notes.append(f"config overlay {path}: unknown keys ignored -> {', '.join(unknown)}")
        config.update({k: v for k, v in data.items() if k in DEFAULTS})
        notes.append(f"config overlay applied: {path}")

    if extra:
        config.update(extra)

    profile = str(config.get("CAPTURE_PROFILE", "full")).lower()
    if profile not in CAPTURE_PROFILES:
        raise ValueError(f"unknown CAPTURE_PROFILE: {profile}")
    configured_filter = config.get("BPF_FILTER")
    if configured_filter is not None and not isinstance(configured_filter, str):
        raise ValueError("BPF_FILTER must be a string or null")
    config["BPF_FILTER"] = CAPTURE_PROFILES[profile] if configured_filter is None else configured_filter or None
    config["SENSOR_ID"] = str(config.get("SENSOR_ID") or hostname)
    notes.append(f"capture profile: {profile}; kernel filter: {config['BPF_FILTER'] or '<all Ethernet frames>'}")

    for key in ("DETECTOR_BUCKETS", "EXFIL_WINDOW_SEC", "SWEEP_WINDOW_SEC", "UDP_FLOOD_WINDOW_SEC",
                "MAX_ENTITIES", "DB_BATCH_CEILING", "CORE_SHARDS"):
        value = config.get(key)  # a zero window divides in the detectors and crash-loops the core
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{key} must be an integer of at least 1, got {value!r}")
    cpus = os.cpu_count() or 1
    if config["CORE_SHARDS"] > cpus:  # more shards than cores only adds processes; an overlay may come from a bigger host
        notes.append(f"WARNING: CORE_SHARDS {config['CORE_SHARDS']} exceeds {cpus} CPUs; using {cpus}")
        config["CORE_SHARDS"] = cpus
    for key in ("EXFIL_THRESHOLD_BYTES", "EXFIL_ALERT_COOLDOWN_SEC", "SWEEP_THRESHOLD_PORTS", "UDP_FLOOD_THRESHOLD",
                "GC_INTERVAL_SEC", "GC_STALE_SEC", "ARENA_ALERT_INTERVAL_SEC", "OS_THRESHOLD_NIX", "OS_THRESHOLD_WIN",
                "DETECTOR_ALERT_COOLDOWN_SEC"):
        if not isinstance(config.get(key), int):  # checked once here, not by a crash-looping core
            raise ValueError(f"{key} must be an integer, got {config.get(key)!r}")

    for key in PATH_KEYS:
        value = config.get(key)
        if isinstance(value, str) and value and not os.path.isabs(value):
            base_path = os.path.join(base_dir, value)
            resource_path = os.path.join(resource_dir, value) if resource_dir else None
            if (key in BUNDLED_RESOURCE_KEYS and not os.path.isfile(base_path)
                    and resource_path and os.path.isfile(resource_path)):
                config[key] = resource_path
            else:
                config[key] = base_path

    # All consumers receive canonical CIDRs; legacy overlays remain supported.
    for key, version in (("LOCAL_PREFIXES", 4), ("LOCAL_PREFIXES6", 6)):
        try:
            config[key] = tuple(str(n) for n in compile_networks(config.get(key), version=version, strict=True))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key}: {exc}") from exc
    scopes = config.get("EXPOSURE_OWNED_SCOPES")
    if not isinstance(scopes, list | tuple):
        raise ValueError("EXPOSURE_OWNED_SCOPES must be a list of CIDRs")
    try:
        networks = compile_networks(scopes, strict=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"EXPOSURE_OWNED_SCOPES: {exc}") from exc
    if any(network.prefixlen == 0 for network in networks):
        raise ValueError("EXPOSURE_OWNED_SCOPES: a whole address family is never an owned scope")
    config["EXPOSURE_OWNED_SCOPES"] = tuple(str(network) for network in networks)

    config["BEACON_IGNORE_UDP_PORTS"] = tuple(
        int(port) for port in (config.get("BEACON_IGNORE_UDP_PORTS") or ())
    )

    bad = []
    for value in config.get("BEACON_IGNORE_DESTINATIONS") or ():
        try:
            ipaddress.ip_address(value)
        except ValueError:
            bad.append(value)
    if bad:  # the beacon detector skips them silently
        notes.append(f"WARNING: BEACON_IGNORE_DESTINATIONS entries ignored (not IP addresses): {bad}")
    for value in config.get("SWEEP_IGNORE_SOURCES") or ():
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"SWEEP_IGNORE_SOURCES: {exc}") from exc
    from netwatch_flow import device_endpoint_rule

    for key in ("BEACON_IGNORE_DEVICE_ENDPOINTS", "UDP_FLOOD_IGNORE_DEVICE_ENDPOINTS"):
        bad = [e for e in config.get(key) or () if device_endpoint_rule(e) is None]
        if bad:
            notes.append(f"WARNING: {key} entries ignored (need mac, non-/0 networks): {bad}")
    from netwatch_flow import device_window_rule

    bad = [e for e in config.get("EXFIL_IGNORE_DEVICE_WINDOWS") or () if device_window_rule(e) is None]
    if bad:
        notes.append(f"WARNING: EXFIL_IGNORE_DEVICE_WINDOWS entries ignored (need mac, non-/0 networks, hours [start, end]): {bad}")

    from netwatch_flow import accepted_egress_rules

    entries = config.get("ACCEPTED_EGRESS") or ()
    if len(accepted_egress_rules(entries)) != len(entries):
        notes.append("WARNING: some ACCEPTED_EGRESS entries ignored (need macs, domains or cidrs, review_by YYYY-MM-DD)")

    config["GATEWAY_IP_AUTO"] = not config.get("GATEWAY_IP")  # an explicit GATEWAY_IP is pinned; the core never refreshes it
    if config["GATEWAY_IP_AUTO"]:
        config["GATEWAY_IP"] = detect_default_gateway()
        notes.append(f"gateway auto-detected: {config['GATEWAY_IP'] or '<none>'}")

    v6 = list(config.get("LOCAL_PREFIXES6") or ())
    if config.get("LOCAL_PREFIXES6_AUTO", True):
        for cidr in detect_local_v6_prefixes(int(config.get("LOCAL_PREFIX6_LEN", 64))):
            if cidr not in v6:
                v6.append(cidr)
        notes.append(f"local IPv6 prefixes: {', '.join(v6) or '<none detected>'}")
    config["LOCAL_PREFIXES6"] = tuple(v6)

    return config, notes
