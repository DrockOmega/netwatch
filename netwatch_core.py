"""Pure, dependency-light core for NetWatch.

This module holds the two pieces of logic that have no business depending on
PyQt6, OpenGL, or Scapy: the cross-process IPC message contract and the
per-entity anomaly detectors. Keeping them here means they can be unit-tested in
isolation (see ``tests/``) and that CI does not need a display server or a raw
socket to exercise the parts most likely to harbour off-by-one bugs.

The detectors operate directly on a NumPy structured-array *row* (one slot of the
DOD core's pre-allocated arena). They mutate only their own fields and never
allocate on the hot path. ``arena_dtype`` below is the single definition of that
row layout, shared by ``main.py`` and the tests.
"""

import base64
import functools
import hashlib
import ipaddress
import json
import multiprocessing as mp
import os
import queue
import shutil
import socket
import struct
import threading
import time
import uuid
import zlib

DISK_MIN_FREE_BYTES = 2_147_483_648


def disk_admission(path, min_free_bytes=DISK_MIN_FREE_BYTES):
    """Return ``(admitted, free_bytes)`` for the volume that holds ``path``.

    Below the floor only critical records (gaps, health) are written. An
    unmeasurable volume admits: refusing would turn a stat error into loss.
    """
    try:
        free = shutil.disk_usage(os.path.dirname(os.path.abspath(path))).free
    except OSError:
        return True, None
    return free >= max(0, int(min_free_bytes or 0)), free


def acquire_single_instance_mutex(name):
    """Acquire a process-lifetime named mutex on Windows; return ``None`` if held."""
    if os.name != "nt":
        return object()
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_bool
    handle = kernel32.CreateMutexW(None, False, str(name))
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return None
    return handle


def release_single_instance_mutex(handle):
    """Release a mutex returned by :func:`acquire_single_instance_mutex`."""
    if handle is None or os.name != "nt":
        return
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_bool
    if not kernel32.CloseHandle(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def start_parent_watchdog(shutdown_event, *, parent=None, interval_sec=1.0):
    """Set the shared shutdown flag when a spawned worker loses its parent."""
    if shutdown_event is None:
        return None
    parent = mp.parent_process() if parent is None else parent
    if parent is None:
        return None
    interval_sec = max(0.01, float(interval_sec))

    def watch_parent():
        while not shutdown_event.wait(interval_sec):
            try:
                alive = parent.is_alive()
            except (AssertionError, OSError, ValueError):
                alive = False
            if not alive:
                shutdown_event.set()
                return

    thread = threading.Thread(
        target=watch_parent,
        name="parent-watchdog",
        daemon=True,
    )
    thread.start()
    return thread

# =====================================================================
# IP ADDRESS REPRESENTATION (v4 + v6)
# =====================================================================
# The whole pipeline keys an endpoint by its *packed* address bytes: 4 bytes for
# IPv4, 16 for IPv6 (the natural width of ``socket.inet_pton``). Bytes are
# hashable (so they slot straight into ``ip_to_idx``), pickle cleanly across the
# process queues, and carry their family implicitly in ``len()``. Text form
# (dotted v4 / colon v6) is reconstructed only at the display/DB/geo boundary.
# Keeping these helpers here — pure, no Scapy/Qt — means the conversion logic is
# unit-tested in isolation.


def ip_pack(text):
    """Pack a textual IP (v4 or v6) into address bytes, or ``None`` if it parses
    as neither. 4 bytes for IPv4, 16 for IPv6."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            return socket.inet_pton(family, text)
        except (OSError, ValueError):
            continue
    return None


def ip_str(packed):
    """Render packed address bytes back to text (v4 dotted / v6 colon). Tolerant:
    a non-bytes value is stringified, an odd length is hex-dumped — a display path
    must never raise."""
    if not isinstance(packed, bytes | bytearray):
        return str(packed)
    if len(packed) == 4:
        return socket.inet_ntop(socket.AF_INET, bytes(packed))
    if len(packed) == 16:
        return socket.inet_ntop(socket.AF_INET6, bytes(packed))
    return bytes(packed).hex()


def ip_family(packed):
    """4, 6, or 0 for a packed address by its byte length."""
    n = len(packed) if isinstance(packed, bytes | bytearray) else 0
    return 4 if n == 4 else 6 if n == 16 else 0


def is_global_ip(packed):
    """True only for a packed, globally routable unicast endpoint."""
    if ip_family(packed) == 0:
        return False
    return _is_global_packed(bytes(packed))


@functools.lru_cache(maxsize=65536)  # ipaddress parsing per packet endpoint dominated the intel check
def _is_global_packed(packed):
    address = ipaddress.ip_address(packed)
    return address.is_global and not address.is_multicast


# Community ID v1 ICMP request/reply counterparts (type -> paired type); others are one-way.
_ICMP_COUNTERPART = {1: {8: 0, 0: 8, 13: 14, 14: 13, 15: 16, 16: 15, 10: 9, 9: 10, 17: 18, 18: 17},
                     58: {128: 129, 129: 128, 133: 134, 134: 133, 135: 136, 136: 135,
                          130: 131, 131: 130, 139: 140, 140: 139, 144: 145, 145: 144}}


def community_id_v1(proto, src_ip, src_port, dst_ip, dst_port, seed=0):
    """Community ID v1 (corelight/community-id-spec), base64 SHA-1.

    TCP/UDP/SCTP use ports; ICMP/ICMPv6 pass type as ``src_port`` and code as
    ``dst_port``; other protocols ignore ports.
    """
    src, dst = ipaddress.ip_address(src_ip).packed, ipaddress.ip_address(dst_ip).packed
    one_way = False
    if proto in _ICMP_COUNTERPART:
        pairs = _ICMP_COUNTERPART[proto]
        one_way = src_port not in pairs
        dst_port = dst_port if one_way else pairs[src_port]
    has_ports = proto in (1, 6, 17, 58, 132)
    if not has_ports:
        src_port = dst_port = 0
    if not (one_way or (src, src_port) < (dst, dst_port)):
        src, dst, src_port, dst_port = dst, src, dst_port, src_port
    data = struct.pack("!H", seed) + src + dst + struct.pack("BB", proto, 0)
    if has_ports:
        data += struct.pack("!HH", src_port, dst_port)
    return "1:" + base64.b64encode(hashlib.sha1(data, usedforsecurity=False).digest()).decode()


def ttl_profile(ttl, low_threshold=64, mid_threshold=128):
    """Describe the observed TTL family without claiming a device OS."""
    try:
        value = int(ttl)
        low_limit = int(low_threshold)
        mid_limit = int(mid_threshold)
    except (TypeError, ValueError, OverflowError):
        return "UNKNOWN TTL"
    if not 1 <= value <= 255:
        return "UNKNOWN TTL"
    if value <= low_limit:
        return "LOW TTL"
    if value <= mid_limit:
        return "MID TTL"
    return "HIGH TTL"


def compile_networks(values, *, version=None, strict=False):
    """Canonical networks shared by config, detection and containment.

    Accept CIDRs, network objects and legacy dotted IPv4 prefixes. Strict mode
    rejects invalid input/family mismatches; tolerant callers skip them.
    """
    if isinstance(values, str | ipaddress.IPv4Network | ipaddress.IPv6Network):
        values = (values,)
    networks = []
    for value in values or ():
        try:
            if isinstance(value, ipaddress.IPv4Network | ipaddress.IPv6Network):
                network = value
            else:
                text = str(value).strip()
                if text.endswith("."):
                    parts = text[:-1].split(".")
                    if (not 1 <= len(parts) <= 3
                            or any(not p.isascii() or not p.isdecimal() or not 0 <= int(p) <= 255 for p in parts)):
                        raise ValueError(f"invalid IPv4 prefix {value!r}")
                    text = ".".join([*(str(int(p)) for p in parts), *(["0"] * (4 - len(parts)))])
                    text += f"/{len(parts) * 8}"
                network = ipaddress.ip_network(text, strict=False)
            if version is not None and network.version != version:
                raise ValueError(f"expected IPv{version} network: {value!r}")
            if network not in networks:
                networks.append(network)
        except (TypeError, ValueError):
            if strict:
                raise
    return tuple(networks)


def compile_v4_prefixes(prefixes):
    """Compile legacy dotted prefixes or CIDRs into fast IPv4 membership pairs."""
    return [(int(net.network_address), int(net.netmask)) for net in compile_networks(prefixes, version=4)]


def compile_v6_prefixes(prefixes):
    """Compile IPv6 CIDR strings (``"2600:1700:abcd:1200::/64"``) into ``(value,
    mask)`` 128-bit int pairs.

    This is what makes globally-routable LAN addresses count as *local*. Home
    ISPs delegate a real GUA prefix to the LAN, so ``2600:…`` on your own network
    is structurally indistinguishable from a remote address — without the
    delegated prefix configured here, every internal IPv6 flow is misclassified
    as external (breaking baselining, the scope filter, and — worst — making your
    own devices mitigation-eligible). Non-v6 / unparseable entries are skipped."""
    return [(int(net.network_address), int(net.netmask)) for net in compile_networks(prefixes, version=6)]


def is_local_ip(packed, v4_prefix_pairs, v6_prefix_pairs=()):
    """True if a packed address is on the local network / non-routable.

    IPv4 is matched against the compiled ``v4_prefix_pairs``. IPv6 is matched
    structurally first (loopback ``::1``, unspecified ``::``, link-local
    ``fe80::/10``, ULA ``fc00::/7``, multicast ``ff00::/8``) and then against
    ``v6_prefix_pairs`` — the host's own delegated global prefixes."""
    n = len(packed) if isinstance(packed, bytes | bytearray) else 0
    if n == 4:
        ip_int = int.from_bytes(packed, "big")
        # Structural locality is invariant even with a narrowly configured LAN.
        if (packed[0] in (0, 127, 255) or bytes(packed[:2]) == b"\xa9\xfe"
                or packed[0] & 0xF0 == 0xE0):
            return True
        for val, mask in v4_prefix_pairs:
            if (ip_int & mask) == val:
                return True
        return False
    if n == 16:
        b = bytes(packed)
        if b == b"\x00" * 15 + b"\x01" or b == b"\x00" * 16:  # ::1 / ::
            return True
        b0 = b[0]
        if b0 == 0xFF:                       # multicast ff00::/8
            return True
        if (b0 & 0xFE) == 0xFC:              # ULA fc00::/7
            return True
        if b0 == 0xFE and (b[1] & 0xC0) == 0x80:  # link-local fe80::/10
            return True
        if v6_prefix_pairs:
            ip_int = int.from_bytes(b, "big")
            for val, mask in v6_prefix_pairs:
                if (ip_int & mask) == val:
                    return True
        return False
    return False


def _shard_of(key, shards):
    return zlib.crc32(key.encode() if isinstance(key, str) else bytes(key)) % shards


def core_shard(event, shards, v4_prefix_pairs, v6_prefix_pairs=(), sender_macs=None):
    """The analytics shard that owns one packet event.

    Chosen by the LAN endpoint, so a flow's two directions and one device's per-source state (both
    address families included) land in one shard: when exactly one side is local, the MAC that local
    address last sent from (``sender_macs``, filled here; the web classifier keys local senders by
    that MAC), else the lower address of the pair. Inbound traffic follows the learned sender MAC,
    not its own destination MAC, so a host that receives on another MAC still keeps its flows whole."""
    src, dst = event["src_ip"], event["dst_ip"]
    src_local = is_local_ip(src, v4_prefix_pairs, v6_prefix_pairs)
    if src_local == is_local_ip(dst, v4_prefix_pairs, v6_prefix_pairs):
        return _shard_of(min(src, dst), shards)
    if src_local:
        mac = event.get("mac_src")
        if mac and sender_macs is not None:
            if len(sender_macs) >= 65536 and src not in sender_macs:
                sender_macs.clear()  # shortcut: forgets every sender at once; fine for a home-sized LAN
            sender_macs[src] = mac
        return _shard_of(mac or src, shards)
    return _shard_of((sender_macs or {}).get(dst) or event.get("mac_dst") or dst, shards)
    owner = _shard_of(min(src, dst), shards)
    if src_local and event.get("dns_qr") == 0:
        hint = _shard_of(event.get("mac_src") or src, shards)
        return owner, (None if hint == owner else hint)
    return owner, None


# =====================================================================
# SYSTEM CONSTRAINTS: IPC SCHEMA INVARIANTS
# =====================================================================
MESSAGE_PAYLOAD_KEYS = ("correlation_id", "source", "action", "target_id", "data", "error")
MESSAGE_PAYLOAD_KEYSET = set(MESSAGE_PAYLOAD_KEYS)


def make_message(source, action, target_id, data=None, error=None, correlation_id=None):
    """Build a payload that satisfies ``is_message_payload``. The only sanctioned
    way to construct a cross-process message."""
    if data is None:
        data = {}
    elif not isinstance(data, dict):
        data = {"value": data}
    return {
        "correlation_id": correlation_id or str(uuid.uuid4()),
        "source": str(source),
        "action": str(action),
        "target_id": target_id,
        "data": data,
        "error": None if error is None else str(error),
    }


def make_db_batch_message(rows, observations):
    """Build a DB batch with an immutable observation snapshot.

    ``multiprocessing.Queue`` serializes on a feeder thread, so callers may clear
    their retry list after an accepted put before the payload is pickled.
    """
    return make_message(
        "DOD_CORE", "DB_BATCH", "DB_WORKER",
        {"rows": rows, "observations": tuple(observations)},
    )


def is_message_payload(payload):
    """Validate a payload against the load-bearing IPC contract. Every receiver
    re-validates with this before unpacking; never assume schema."""
    return (
        isinstance(payload, dict)
        and payload.keys() == MESSAGE_PAYLOAD_KEYSET
        and isinstance(payload["correlation_id"], str)
        and isinstance(payload["source"], str)
        and isinstance(payload["action"], str)
        and isinstance(payload["data"], dict)
        and (payload["error"] is None or isinstance(payload["error"], str))
    )


def newest_render_data(payloads, event_limit=50, observation_limit=1000):
    """Flatten packet rows and priority web observations independently.

    Sparse session observations must not disappear when the packet tail is load
    shed.  New render batches carry them separately; rolling deployments derive
    them from annotated events when the separate field is absent.
    """
    width = max(0, int(event_limit))
    observation_width = max(0, int(observation_limit))
    newest_reversed = []
    observations_reversed = []
    total_ingested = 0
    for payload in reversed(payloads or ()):
        if not is_message_payload(payload):
            continue
        if payload["action"] == "RENDER_BATCH":
            events = payload["data"].get("events")
            if not isinstance(events, list):
                continue
            observations = payload["data"].get("observations")
            if not isinstance(observations, list):
                observations = [
                    event for event in events
                    if isinstance(event, dict) and isinstance(event.get("web_observation"), dict)
                ]
            reported = payload["data"].get("total_ingested", len(events))
            try:
                total_ingested += max(0, int(reported))
            except (TypeError, ValueError, OverflowError):
                total_ingested += len(events)
        elif payload["action"] == "RENDER_UPDATE":
            events = [payload["data"]]
            observations = (
                events if isinstance(payload["data"].get("web_observation"), dict) else []
            )
            total_ingested += 1
        else:
            continue
        remaining = width - len(newest_reversed)
        if remaining > 0:
            newest_reversed.extend(reversed(events[-remaining:]))
        observation_remaining = observation_width - len(observations_reversed)
        if observation_remaining > 0:
            observations_reversed.extend(reversed(observations[-observation_remaining:]))
    newest_reversed.reverse()
    observations_reversed.reverse()
    return newest_reversed, observations_reversed, total_ingested


def newest_render_events(payloads, limit=50):
    """Backward-compatible packet-tail view over :func:`newest_render_data`."""
    events, _observations, total_ingested = newest_render_data(
        payloads, event_limit=limit, observation_limit=0,
    )
    return events, total_ingested


MAX_GATE_KEYS = 4096  # keys come from the network; unbounded they grow until OOM


class AlertGate:
    """Per-detector/key cooldown so a sustained condition emits one incident."""

    def __init__(self, cooldown_sec=60):
        self.cooldown_sec = max(1.0, float(cooldown_sec))
        self.last_alert = {}

    def allow(self, detector, key, now):
        gate_key = (str(detector), key)
        now = float(now)
        previous = self.last_alert.get(gate_key)
        if previous is not None and now - previous < self.cooldown_sec:
            return False
        self.last_alert.pop(gate_key, None)  # re-insert at the end keeps the dict oldest-first
        if len(self.last_alert) >= MAX_GATE_KEYS:
            # O(1) under a flood; the oldest key is the likeliest to have expired, and an expired key changes nothing.
            self.last_alert.pop(next(iter(self.last_alert)))
        self.last_alert[gate_key] = now
        return True


def try_put_drop_oldest_with_eviction(ipc_queue, payload):
    """Nonblocking enqueue returning ``(accepted, evicted_payload)``."""
    if not is_message_payload(payload):
        return False, None
    try:
        ipc_queue.put_nowait(payload)
        return True, None
    except queue.Full:
        evicted = None
        try:
            evicted = ipc_queue.get_nowait()
        except queue.Empty:
            pass
        try:
            ipc_queue.put_nowait(payload)
            return True, evicted
        except queue.Full:
            return False, evicted


def try_put_drop_oldest(ipc_queue, payload):
    """Nonblocking enqueue for lossy paths where only acceptance matters."""
    accepted, _evicted = try_put_drop_oldest_with_eviction(ipc_queue, payload)
    return accepted


def try_put_no_drop(ipc_queue, payload, timeout=0.0):
    """Enqueue without evicting anything already queued. Returns ``True`` on
    success, ``False`` if the queue stayed full for ``timeout`` seconds.

    Used for durable evidence and security-control paths: silently discarding an
    accepted item loses persisted telemetry or an enforcement verdict. Refusing
    the new item loudly is the correct bounded failure mode."""
    if not is_message_payload(payload):
        return False
    try:
        if timeout > 0:
            ipc_queue.put(payload, timeout=timeout)
        else:
            ipc_queue.put_nowait(payload)
        return True
    except queue.Full:
        return False


# =====================================================================
# DETECTORS (per-entity heuristics over the memory arena)
# =====================================================================
# Each windowed detector keeps a small ring of time buckets instead of one slot
# per packet. A per-packet ring is exact but its size must scale with the
# threshold (a 10k-packets-in-2s detector needed a 16384-entry f8 ring = 128 KB
# *per tracked endpoint*, ~464 MiB across a 2048-slot arena). Bucketing gives the
# same rate/volume answer at window/DETECTOR_BUCKETS resolution for ~8.4 KB per
# endpoint, and the roll is O(1) amortised instead of a per-packet expiry walk.

DETECTOR_BUCKETS = 20
SWEEP_BITMAP_WORDS = 1024  # 65536 bits: one per possible destination port


def arena_dtype(buckets=DETECTOR_BUCKETS):
    """NumPy structured dtype for one arena slot.

    ``*_state[0]`` is the absolute index of the newest bucket, ``*_state[1]`` the
    running total across the ring (so a detector never re-sums its buckets)."""
    return [
        ('vol_buckets', 'f8', buckets), ('vol_state', 'f8', 2),
        ('udp_buckets', 'f8', buckets), ('udp_state', 'f8', 2),
        ('sweep_bitmap', 'u8', SWEEP_BITMAP_WORDS), ('sweep_state', 'f8', 2),
    ]


def _roll_window(buckets, state, current_time, window, nbuckets):
    """Advance a trailing-window bucket ring to ``current_time``.

    Zeroes (and deducts from the running total) every bucket skipped since the
    last observation, so ``state[1]`` is always the trailing-window sum. A clock
    jump in either direction clears the ring rather than corrupting it. Returns
    the ring slot that ``current_time`` falls in."""
    width = window / nbuckets
    b = current_time // width
    last = state[0]
    if b != last:
        gap = b - last
        if gap < 0 or gap >= nbuckets:
            buckets[:] = 0.0
            state[1] = 0.0
        else:
            k = last + 1.0
            while k <= b:
                i = int(k % nbuckets)
                state[1] -= buckets[i]
                buckets[i] = 0.0
                k += 1.0
        state[0] = b
    return int(b % nbuckets)


def analyze_udp_flood(arena_row, current_time, config, src):
    """Sliding-window UDP packet-rate detector. Returns an alert string when a
    single source exceeds ``UDP_FLOOD_THRESHOLD`` packets inside
    ``UDP_FLOOD_WINDOW_SEC``, else ``None``."""
    buckets, state = arena_row['udp_buckets'], arena_row['udp_state']
    idx = _roll_window(buckets, state, current_time, config["UDP_FLOOD_WINDOW_SEC"], len(buckets))
    buckets[idx] += 1.0
    state[1] += 1.0

    if state[1] > config["UDP_FLOOD_THRESHOLD"]:
        buckets[:] = 0.0
        state[1] = 0.0
        return f"UDP FLOOD ALERT: {src} blasted >{config['UDP_FLOOD_THRESHOLD']} pkts"
    return None


def analyze_port_sweep(arena_row, current_time, config, src, dport, sport=0, tcp_flags=None):
    """Distinct-destination-port sweep detector. A 65536-bit bitmap per row tracks
    which ports a source has touched inside ``SWEEP_WINDOW_SEC``; alerts once the
    distinct count exceeds ``SWEEP_THRESHOLD_PORTS``.

    A packet from a service port (<1024) to an ephemeral port is a server's reply
    (DNS, HTTPS) to a local client's random port, not a probe, and is not counted:
    otherwise every busy resolver or CDN reads as a scanner. For TCP (``tcp_flags`` given) only a
    bare SYN is a probe: SYN-ACK/RST replies from a scanned host (the gateway answering
    the dev host's sweep) and established-flow segments are not counted."""
    if 0 < sport < 1024 <= dport:
        return None
    if tcp_flags is not None and ("S" not in tcp_flags or "A" in tcp_flags):
        return None
    s_bitmap, s_state = arena_row['sweep_bitmap'], arena_row['sweep_state']
    if abs(current_time - s_state[0]) > config["SWEEP_WINDOW_SEC"]:
        s_bitmap.fill(0)
        s_state[0], s_state[1] = current_time, 0

    if not (s_bitmap[dport >> 6] & (1 << (dport & 63))):
        s_bitmap[dport >> 6] |= (1 << (dport & 63))
        s_state[1] += 1

    if s_state[1] > config["SWEEP_THRESHOLD_PORTS"]:
        s_bitmap.fill(0)
        s_state[1] = 0
        return f"PORT SCAN ALERT: {src} swept >{config['SWEEP_THRESHOLD_PORTS']} ports"
    return None


MAX_SWEEP_TARGETS = 8  # destinations named in a PORT SCAN detection
MAX_SWEEP_SOURCES = 4096


def track_sweep_target(targets, src, dst, new_window):
    """Remember (bounded, ordered) which destinations ``src`` touched in the current sweep window."""
    if new_window:
        targets.pop(src, None)
    seen = targets.setdefault(src, {})
    if len(seen) < MAX_SWEEP_TARGETS:
        seen[dst] = None
    if len(targets) > MAX_SWEEP_SOURCES:
        targets.pop(next(iter(targets)))


def analyze_volumetric_exfil(arena_row, current_time, config, dst, size):
    """Rolling-byte-volume detector. Maintains a windowed byte sum; alerts when it
    crosses ``EXFIL_THRESHOLD_BYTES`` inside ``EXFIL_WINDOW_SEC``.

    The caller is responsible for direction: this must be driven from the
    *sender's* arena row and only for local-source → external-destination flows.
    Accumulating on the destination row counts inbound bytes as egress, which
    turns any ordinary download into an exfiltration alert against your own
    host."""
    buckets, state = arena_row['vol_buckets'], arena_row['vol_state']
    idx = _roll_window(buckets, state, current_time, config["EXFIL_WINDOW_SEC"], len(buckets))
    buckets[idx] += size
    state[1] += size

    if state[1] > config["EXFIL_THRESHOLD_BYTES"]:
        current_vol = int(state[1])
        buckets[:] = 0.0
        state[1] = 0.0
        return f"EXFIL ALERT: {current_vol / 1e6:.2f}MB streamed to {dst}"
    return None


def write_json_atomic(path, payload):
    """Write payload as indented JSON through a .tmp sibling and rename it into place.

    Returns True on success, False on OSError: a transient write failure must never
    break the capture loop."""
    try:
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())  # else a power cut after the rename can leave an empty ledger
        for delay in (0.05, 0.1, 0.2, None):
            try:
                os.replace(tmp_path, path)
                return True
            except PermissionError:
                # Windows refuses the rename while a reader (CLI, backup, scanner) holds the target open.
                if delay is None:
                    raise
                time.sleep(delay)
    except OSError:
        return False


def ago(ts, now):
    """Compact age label ("5m ago") shared by the operator CLIs."""
    d = max(0, int(now - ts))
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"
