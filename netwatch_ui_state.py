"""Pure presentation state for the NetWatch operator console.

The capture and detector processes emit small IPC messages.  This module turns
those messages into bounded, correlated UI snapshots without importing Qt.
Keeping correlation and filtering pure makes the operator surface deterministic
and testable while the GUI remains a thin model/view layer.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import sqlite3
import time
from datetime import datetime

from netwatch_core import (
    compile_v4_prefixes,
    compile_v6_prefixes,
    is_local_ip,
    ttl_profile,
)
from netwatch_db import EVENT_METADATA_COLUMNS
from netwatch_incidents import (
    INCIDENT_SCOPES as INCIDENT_SCOPES,
)
from netwatch_incidents import (
    SEVERITY_RANK as SEVERITY_RANK,
)
from netwatch_incidents import (
    Incident as Incident,
)
from netwatch_incidents import (
    IncidentStore as IncidentStore,
)
from netwatch_incidents import (
    filter_incident_rows as filter_incident_rows,
)
from netwatch_incidents import (
    incident_title as incident_title,
)
from netwatch_incidents import (
    severity_for as severity_for,
)

RESPONSE_MODE_IDS_ONLY = "ids_only"
RESPONSE_MODE_READY = "ready"
RESPONSE_MODE_AUTONOMOUS = "autonomous"
RESPONSE_MODES = (
    RESPONSE_MODE_READY,
    RESPONSE_MODE_AUTONOMOUS,
    RESPONSE_MODE_IDS_ONLY,
)
RESPONSE_MODE_LABELS = {
    RESPONSE_MODE_IDS_ONLY: "IDS ONLY",
    RESPONSE_MODE_READY: "IDS + IPS READY",
    RESPONSE_MODE_AUTONOMOUS: "IPS AUTONOMOUS",
}


def heartbeat_label(last, now, timeout, status="ALIVE"):
    if last is None:
        return "Awaiting heartbeat"
    age = now - last
    if not math.isfinite(age) or age < 0:
        return "Clock skew"
    if age > timeout:
        return "Heartbeat stale"
    return {"ALIVE": "Active", "IDLE": "Idle", "STARTING": "Starting",
            "DEADLOCK_DETECTED": "Loop stalled", "CAPTURE_UNAVAILABLE": "Read unavailable"}.get(status, "Unverified")


def normalize_response_mode(value, default=RESPONSE_MODE_IDS_ONLY):
    """Return a supported response mode, falling back to the configured default."""
    normalized_default = str(default).strip().lower()
    if normalized_default not in RESPONSE_MODES:
        normalized_default = RESPONSE_MODE_IDS_ONLY
    normalized = str(value).strip().lower()
    return normalized if normalized in RESPONSE_MODES else normalized_default


def response_dispatch(mode):
    """Map an operating mode to the action taken for a new eligible finding."""
    return {
        RESPONSE_MODE_IDS_ONLY: "ignore",
        RESPONSE_MODE_READY: "queue",
        RESPONSE_MODE_AUTONOMOUS: "enforce",
    }[normalize_response_mode(mode)]


def load_response_mode(path, default=RESPONSE_MODE_IDS_ONLY):
    """Load the last operator-selected mode; malformed or absent state fails closed to default."""
    if not path:
        return normalize_response_mode(default)
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError, TypeError):
        return normalize_response_mode(default)
    if not isinstance(document, dict):
        return normalize_response_mode(default)
    return normalize_response_mode(document.get("mode"), default)


def save_response_mode(path, mode):
    """Atomically persist the operator-selected response mode."""
    if not path:
        raise ValueError("response mode state path is required")
    normalized = normalize_response_mode(mode)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temporary = f"{path}.tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "mode": normalized}, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise
    return normalized


def _packed_ip(value):
    if not isinstance(value, bytes | bytearray) or len(value) not in {4, 16}:
        return None
    try:
        return str(ipaddress.ip_address(bytes(value)))
    except ValueError:
        return None


def _canonical_mac(value):
    return str(value or "").strip().lower().replace("-", ":")


def _secure_node_identities(nodes):
    """Flatten validated operator-defined node identities into lookup sets."""
    ips = set()
    macs = set()
    if not isinstance(nodes, dict):
        return ips, macs
    for identity in nodes.values():
        if not isinstance(identity, dict):
            continue
        for value in identity.get("ips") or ():
            try:
                ips.add(str(ipaddress.ip_address(str(value).split("%", 1)[0])))
            except ValueError:
                continue
        for value in identity.get("macs") or ():
            mac = _canonical_mac(value)
            if mac:
                macs.add(mac)
    return ips, macs


_TTL_PROFILE_ALIASES = {
    "---": "UNKNOWN TTL",
    "NIX/MOB": "LOW TTL",
    "WIN": "MID TTL",
    "NET/IOT": "HIGH TTL",
    "ANOMALY/FRAG": "UNKNOWN TTL",
}


def normalize_ttl_profile(value):
    """Translate historical OS-claim labels into evidence-honest TTL profiles."""
    text = str(value or "").strip().upper()
    return _TTL_PROFILE_ALIASES.get(text, text or "UNKNOWN TTL")


def _register_locality_function(conn, local_prefixes=(), local_prefixes6=()):
    v4_prefixes = compile_v4_prefixes(local_prefixes or ())
    v6_prefixes = compile_v6_prefixes(local_prefixes6 or ())

    def netwatch_is_local(value):
        try:
            packed = ipaddress.ip_address(str(value).split("%", 1)[0]).packed
        except (TypeError, ValueError):
            return 0
        return int(is_local_ip(packed, v4_prefixes, v6_prefixes))

    conn.create_function("netwatch_is_local", 1, netwatch_is_local, deterministic=True)


def _append_common_sql_filters(clauses, params, filters, *, web=False,
                               low_threshold=64, mid_threshold=128):
    filters = filters if isinstance(filters, dict) else {}
    family = filters.get("family")
    if family == "IPv4":
        clauses.append("instr(src_ip, ':') = 0")
    elif family == "IPv6":
        clauses.append("instr(src_ip, ':') > 0")

    secure_ips, secure_macs = _secure_node_identities(filters.get("secure_nodes"))

    def identity_clause(ip_column, mac_column):
        parts = []
        values = []
        if secure_ips:
            parts.append(f"{ip_column} IN ({','.join('?' for _ in secure_ips)})")
            values.extend(sorted(secure_ips))
        if secure_macs:
            parts.append(
                f"lower(replace(coalesce({mac_column}, ''), '-', ':')) IN "
                f"({','.join('?' for _ in secure_macs)})"
            )
            values.extend(sorted(secure_macs))
        return parts, values

    source_parts, source_values = identity_clause("src_ip", "mac_src")
    destination_parts, destination_values = identity_clause("dst_ip", "mac_dst")
    node_scope = filters.get("node_scope")
    if node_scope in {"HIDE SECURE SOURCES", "HIDE SECURE NODES"} and source_parts:
        clauses.append(f"NOT ({' OR '.join(source_parts)})")
        params.extend(source_values)
    elif node_scope == "HIDE SECURE ENDPOINTS" and (source_parts or destination_parts):
        identities = []
        if source_parts:
            identities.append(f"({' OR '.join(source_parts)})")
            params.extend(source_values)
        if destination_parts:
            identities.append(f"({' OR '.join(destination_parts)})")
            params.extend(destination_values)
        clauses.append(f"NOT ({' OR '.join(identities)})")

    if filters.get("alerts") == "ALERTS ONLY":
        clauses.append("0")  # alert state is not persisted in these ledgers

    scope = filters.get("scope")
    if scope == "EXTERNAL (HIDE LOCAL)":
        clauses.append("NOT (netwatch_is_local(src_ip) AND netwatch_is_local(dst_ip))")
    elif scope == "INTERNAL ONLY":
        clauses.append("netwatch_is_local(src_ip) AND netwatch_is_local(dst_ip)")

    observation = filters.get("observation")
    if not web and observation in {"ANY OUTBOUND", "UNCLASSIFIED OUTBOUND"}:
        clauses.append("netwatch_is_local(src_ip) AND NOT netwatch_is_local(dst_ip)")
    if web and observation == "HUMAN SIGNAL":
        clauses.append("label IN ('HUMAN LIKELY', 'HUMAN POSSIBLE')")
    elif web and observation == "LIKELY HUMAN":
        clauses.append("label = 'HUMAN LIKELY'")
    elif web and observation == "POSSIBLE HUMAN":
        clauses.append("label = 'HUMAN POSSIBLE'")
    elif web and observation == "WEB NOISE":
        clauses.append("label = 'WEB NOISE'")

    selected_profile = normalize_ttl_profile(filters.get("os"))
    if filters.get("os") not in {None, "ALL OS", "ALL TTL"}:
        if web:
            aliases = {
                "LOW TTL": ("LOW TTL", "NIX/MOB"),
                "MID TTL": ("MID TTL", "WIN"),
                "HIGH TTL": ("HIGH TTL", "NET/IOT"),
                "UNKNOWN TTL": ("UNKNOWN TTL", "ANOMALY/FRAG", "---", ""),
            }.get(selected_profile, (selected_profile,))
            clauses.append(
                f"upper(coalesce(os_guess, '')) IN ({','.join('?' for _ in aliases)})"
            )
            params.extend(aliases)
        else:
            try:
                low_limit = int(low_threshold)
                mid_limit = int(mid_threshold)
            except (TypeError, ValueError, OverflowError):
                low_limit, mid_limit = 64, 128
            ranges = {
                "LOW TTL": ("ttl BETWEEN 1 AND ?", (low_limit,)),
                "MID TTL": ("ttl BETWEEN ? AND ?", (low_limit + 1, mid_limit)),
                "HIGH TTL": ("ttl BETWEEN ? AND 255", (mid_limit + 1,)),
                "UNKNOWN TTL": ("(ttl IS NULL OR ttl < 1 OR ttl > 255)", ()),
            }
            clause, values = ranges.get(selected_profile, ("0", ()))
            clauses.append(clause)
            params.extend(values)


def load_web_observation_events(
        db_path, limit=10_000, *, filters=None, lookback_sec=None,
        local_prefixes=(), local_prefixes6=()):
    """Reload durable derived sessions as renderer-shaped events, newest first."""
    if not isinstance(db_path, str) or not os.path.isfile(db_path):
        return []
    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        _register_locality_function(conn, local_prefixes, local_prefixes6)
        clauses = []
        params = []
        if lookback_sec is not None:
            clauses.append("timestamp >= ?")
            params.append(time.time() - max(1.0, float(lookback_sec)))
        _append_common_sql_filters(clauses, params, filters, web=True)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"""
            SELECT flow_id, timestamp, src_ip, dst_ip, mac_src, mac_dst,
                   protocol, port, domain, label, score, reason,
                   os_guess, country, size_bytes
            FROM web_observations
            {where}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (*params, max(1, int(limit))),
        ).fetchall()
    except (OSError, sqlite3.Error, TypeError, ValueError, OverflowError):
        return []
    finally:
        if conn is not None:
            conn.close()

    events = []
    for row in rows:
        try:
            source = ipaddress.ip_address(row[2])
            destination = ipaddress.ip_address(row[3])
            timestamp = float(row[1])
            time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            port = int(row[7])
            score = int(row[10])
            size = int(row[14])
        except (OSError, TypeError, ValueError, OverflowError):
            continue
        events.append({
            "time_str": time_str,
            "timestamp": timestamp,
            "src": source.packed,
            "dst": destination.packed,
            "mac": str(row[4] or ""),
            "mac_dst": str(row[5] or ""),
            "protocol": str(row[6] or ""),
            "port": port,
            "domain": str(row[8] or ""),
            "size": size,
            "os_guess": normalize_ttl_profile(row[12]),
            "country": str(row[13] or "--"),
            "alert": False,
            "is_lan_to_lan": False,
            "direction": "OUTBOUND",
            "flow_id": str(row[0]),
            "web_observation": {
                "flow_id": str(row[0]),
                "started_at": timestamp,
                "domain": str(row[8] or ""),
                "label": str(row[9] or ""),
                "score": score,
                "reason": str(row[11] or ""),
            },
        })
    return events


def load_recent_traffic_events(
        db_path, limit=10_000, *, local_prefixes=(), local_prefixes6=(),
        os_threshold_nix=64, os_threshold_win=128, filters=None,
        lookback_sec=None):
    """Reload durable packet summaries as renderer events, newest first.

    The live render queue is intentionally lossy.  This read path makes the
    Traffic page an exposure surface over the SQLite ledger as well as a live
    tail, so queue pressure or a dashboard restart cannot erase activity from
    the operator's view.
    """
    if not isinstance(db_path, str) or not os.path.isfile(db_path):
        return []
    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        _register_locality_function(conn, local_prefixes, local_prefixes6)
        clauses = []
        params = []
        if lookback_sec is not None:
            clauses.append("timestamp >= ?")
            params.append(time.time() - max(1.0, float(lookback_sec)))
        _append_common_sql_filters(
            clauses, params, filters,
            low_threshold=os_threshold_nix,
            mid_threshold=os_threshold_win,
        )
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        available = {row[1] for row in conn.execute("PRAGMA table_info(network_events)")}
        metadata_columns = tuple(name for name in EVENT_METADATA_COLUMNS if name in available)
        extra_columns = "".join(f", {name}" for name in metadata_columns)
        rows = conn.execute(
            f"""
            SELECT uuid, timestamp, mac_src, mac_dst, src_ip, dst_ip,
                   protocol, port, tcp_flags, ttl, size_bytes, sni_domain,
                   country, packet_count {extra_columns}
            FROM network_events
            {where}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (*params, max(1, int(limit))),
        ).fetchall()
    except (OSError, sqlite3.Error, TypeError, ValueError, OverflowError):
        return []
    finally:
        if conn is not None:
            conn.close()

    v4_prefixes = compile_v4_prefixes(local_prefixes or ())
    v6_prefixes = compile_v6_prefixes(local_prefixes6 or ())
    try:
        nix_threshold = int(os_threshold_nix)
        win_threshold = int(os_threshold_win)
    except (TypeError, ValueError, OverflowError):
        nix_threshold, win_threshold = 64, 128
    events = []
    for row in rows:
        try:
            source = ipaddress.ip_address(row[4])
            destination = ipaddress.ip_address(row[5])
            timestamp = float(row[1])
            port = int(row[7])
            ttl = int(row[9] or 0)
            size = int(row[10] or 0)
            packet_count = max(1, int(row[13] or 1))
        except (OSError, TypeError, ValueError, OverflowError):
            continue
        source_local = is_local_ip(source.packed, v4_prefixes, v6_prefixes)
        destination_local = is_local_ip(destination.packed, v4_prefixes, v6_prefixes)
        direction = (
            "egress" if source_local and not destination_local
            else "ingress" if not source_local and destination_local
            else "lateral" if source_local and destination_local
            else "other"
        )
        os_guess = ttl_profile(ttl, nix_threshold, win_threshold)
        events.append({
            "event_id": str(row[0] or ""),
            "timestamp": timestamp,
            "time_str": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"),
            "src": source.packed,
            "dst": destination.packed,
            "mac": str(row[2] or ""),
            "mac_dst": str(row[3] or ""),
            "protocol": str(row[6] or ""),
            "port": port,
            "flags": str(row[8] or ""),
            "size": size,
            "packet_count": packet_count,
            "domain": str(row[11] or ""),
            "country": str(row[12] or "--"),
            "os_guess": os_guess,
            "alert": False,
            "is_lan_to_lan": source_local and destination_local,
            "direction": direction,
            "flow_id": "",
            "web_observation": None,
        })
        metadata = dict(zip(metadata_columns, row[14:], strict=False))
        for name in ("source_port", "sensor_id", "capture_interface", "event_version"):
            if name in metadata:
                events[-1][name] = metadata[name]
        for name in ("vlan_ids", "packet_metadata"):
            if name in metadata:
                try:
                    events[-1][name] = json.loads(metadata[name])
                except (TypeError, ValueError):
                    events[-1][name] = None
    return events


def _activity_label(event, destination, web_label):
    if web_label:
        return web_label
    direction = str(event.get("direction") or "").strip().lower()
    try:
        destination_ip = ipaddress.ip_address(destination)
        port = int(event.get("port") or 0)
    except (TypeError, ValueError, OverflowError):
        destination_ip, port = None, 0
    if destination_ip is not None and destination_ip.is_multicast:
        return "DISCOVERY / MULTICAST"
    if port in {67, 68, 1900, 3702, 5353, 5355}:
        return "DISCOVERY / BROADCAST"
    if bool(event.get("is_lan_to_lan")) or direction == "lateral":
        return "LATERAL ACTIVITY"
    if direction in {"egress", "outbound"}:
        return "OUTBOUND UNCLASSIFIED"
    if direction == "ingress":
        return "INBOUND ACTIVITY"
    return "OBSERVED ACTIVITY"


def filter_traffic_events(events, filters=None):
    """Filter and normalize renderer events for a virtualized traffic table."""
    filters = filters if isinstance(filters, dict) else {}
    secure_ips, secure_macs = _secure_node_identities(filters.get("secure_nodes"))
    rows = []
    for event in events if isinstance(events, list) else ():
        if not isinstance(event, dict):
            continue
        src = _packed_ip(event.get("src"))
        dst = _packed_ip(event.get("dst"))
        if src is None or dst is None:
            continue
        family = 6 if ":" in src else 4
        if filters.get("family") == "IPv4" and family != 4:
            continue
        if filters.get("family") == "IPv6" and family != 6:
            continue
        source_mac = _canonical_mac(event.get("mac"))
        destination_mac = _canonical_mac(event.get("mac_dst"))
        source_secure = src in secure_ips or source_mac in secure_macs
        destination_secure = dst in secure_ips or destination_mac in secure_macs
        node_scope = filters.get("node_scope")
        if node_scope in {"HIDE SECURE SOURCES", "HIDE SECURE NODES"} and source_secure:
            continue
        if node_scope == "HIDE SECURE ENDPOINTS" and (source_secure or destination_secure):
            continue
        if filters.get("alerts") == "ALERTS ONLY" and not event.get("alert"):
            continue
        web_observation = event.get("web_observation")
        web_observation = web_observation if isinstance(web_observation, dict) else {}
        web_label = str(web_observation.get("label") or "")
        observation_filter = filters.get("observation")
        direction = str(event.get("direction") or "").strip().lower()
        if observation_filter == "ANY OUTBOUND" and direction not in {"egress", "outbound"}:
            continue
        if (observation_filter == "UNCLASSIFIED OUTBOUND"
                and (direction not in {"egress", "outbound"} or web_label)):
            continue
        if observation_filter == "OUTBOUND WEB" and not web_label:
            continue
        if observation_filter == "HUMAN SIGNAL" and web_label not in {"HUMAN LIKELY", "HUMAN POSSIBLE"}:
            continue
        if observation_filter == "LIKELY HUMAN" and web_label != "HUMAN LIKELY":
            continue
        if observation_filter == "POSSIBLE HUMAN" and web_label != "HUMAN POSSIBLE":
            continue
        if observation_filter == "WEB NOISE" and web_label != "WEB NOISE":
            continue
        if (filters.get("os") not in {None, "ALL OS", "ALL TTL"}
                and normalize_ttl_profile(event.get("os_guess"))
                != normalize_ttl_profile(filters.get("os"))):
            continue
        is_internal = bool(event.get("is_lan_to_lan"))
        if filters.get("scope") == "EXTERNAL (HIDE LOCAL)" and is_internal:
            continue
        if filters.get("scope") == "INTERNAL ONLY" and not is_internal:
            continue
        domain = str(web_observation.get("domain") or event.get("domain") or "")
        target = domain if domain and domain != "encrypted-payload" else dst
        try:
            port = int(event.get("port") or 0)
            size = int(event.get("size") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        activity_label = _activity_label(event, dst, web_label)
        rows.append({
            "time": str(event.get("time_str") or ""),
            "source": src,
            "target": target,
            "destination": dst,
            "protocol": str(event.get("protocol") or "---"),
            "port": port,
            "size": size,
            "os": str(event.get("os_guess") or "---"),
            "mac": str(event.get("mac") or ""),
            "country": str(event.get("country") or "--"),
            "family": family,
            "alert": bool(event.get("alert")),
            "scope": "Internal" if is_internal else "External",
            "signal": (
                f"{web_label} · {web_observation.get('reason', '')}".rstrip(" ·")
                if web_label else activity_label
            ),
        })
    return rows


def load_inventory_snapshot(path):
    """Read the inventory ledger into a stable newest-first UI snapshot."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError, TypeError):
        return []
    devices = raw.get("devices") if isinstance(raw, dict) else None
    if not isinstance(devices, dict):
        return []
    rows = []
    for mac, entry in devices.items():
        if not isinstance(entry, dict):
            continue
        ips = entry.get("ips")
        try:
            first_seen = float(entry.get("first_seen") or 0)
            last_seen = float(entry.get("last_seen") or 0)
            count = int(entry.get("count") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        rows.append({
            "mac": str(mac),
            "vendor": str(entry.get("vendor") or "Unknown"),
            "ips": [str(ip) for ip in ips] if isinstance(ips, list) else [],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "count": count,
        })
    return sorted(rows, key=lambda row: row["last_seen"], reverse=True)


def service_connection_label(client, now=None):
    """A cached snapshot never implies a live service connection."""
    now = time.monotonic() if now is None else now
    if client.last_success is None or now - client.last_success > max(5, 3 * client.poll_interval):
        return "Disconnected / stale"
    return client.state + ("; reconnect gap recorded" if client.gaps else "")
