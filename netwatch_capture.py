"""High-throughput capture parsing, socket tuning, and loss accounting.

NetWatch owns the Npcap handle, enlarges its kernel buffer, and reads raw frames
with ``recv_raw()``. Building a full Scapy object graph for every packet pinned
the capture process to one CPU core at 14k packets/s and caused sustained driver
loss. The bounded parser below extracts only the Ethernet/ARP/IP/TCP/UDP/DNS/TLS
fields the analytics contract consumes; Scapy remains the socket wrapper and the
compatibility fallback, not the hot-path decoder.

Owning ``pcap_t`` also keeps ``ps_recv`` / ``ps_drop`` / ``ps_ifdrop`` visible.
If direct ownership or a tuning API is unavailable, capture degrades to Scapy's
normal listener and the platform's default buffering policy.
"""

import math
import struct
import sys
import threading
import time

_TCP_FLAG_NAMES = "FSRPAUECN"
_TCP_FLAG_TEXT = tuple(
    "".join(name for bit, name in enumerate(_TCP_FLAG_NAMES) if value & (1 << bit))
    for value in range(512)
)


class CaptureProgress:
    """Report read-loop progress separately from traffic arrival, using monotonic time."""

    def __init__(self, started_at=None):
        self.lock = threading.Lock()
        self.started_at = time.monotonic() if started_at is None else float(started_at)
        self.last_progress = self.last_packet = None
        self.error = None

    def packet_seen(self, now=None):
        with self.lock:
            self.last_packet = time.monotonic() if now is None else float(now)

    def read_complete(self, now=None):
        with self.lock:
            self.last_progress = time.monotonic() if now is None else float(now)
            self.error = None

    def read_failed(self, error):
        with self.lock:
            self.error = str(error)[:1000]

    def report(self, now=None, timeout=10, start_timeout=120):
        with self.lock:  # Read the clock under the lock so a read landing mid-report can't age negative.
            now = time.monotonic() if now is None else float(now)
            progress, packet, error = self.last_progress, self.last_packet, self.error
        loop_age = now - (self.started_at if progress is None else progress)
        packet_age = None if packet is None else now - packet
        limit = start_timeout if progress is None else timeout  # Opening capture is not a stalled loop.
        status = ("CAPTURE_UNAVAILABLE" if error else
                  "DEADLOCK_DETECTED" if not math.isfinite(loop_age) or loop_age < 0 or loop_age > limit else
                  "STARTING" if progress is None else
                  "IDLE" if packet_age is None or packet_age > timeout else "ALIVE")
        return {"status": status, "loop_age_sec": loop_age, "last_packet_age_sec": packet_age, "error": error}


def _mac_text(raw):
    return raw.hex(":")


def _dns_name(payload, start):
    """Decode one bounds-checked DNS name, including compression pointers."""
    labels = []
    offset = int(start)
    next_offset = None
    seen = set()
    for _ in range(64):
        if offset >= len(payload) or offset in seen:
            return None, None
        seen.add(offset)
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                return None, None
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer >= len(payload):
                return None, None
            if next_offset is None:
                next_offset = offset + 2
            offset = pointer
            continue
        if length & 0xC0 or length > 63:
            return None, None
        offset += 1
        if length == 0:
            return ".".join(labels), next_offset or offset
        end = offset + length
        if end > len(payload):
            return None, None
        labels.append(bytes(payload[offset:end]).decode("ascii", errors="replace"))
        offset = end
    return None, None


def _parse_dns(payload):
    if len(payload) < 12:
        return None
    flags, questions = struct.unpack_from("!HH", payload, 2)
    qr = (flags >> 15) & 1
    rcode = flags & 0x0F
    qtype = qname = None
    if questions:
        qname, offset = _dns_name(payload, 12)
        if offset is not None and offset + 4 <= len(payload):
            qtype = struct.unpack_from("!H", payload, offset)[0]
    return {"qr": qr, "rcode": rcode, "qtype": qtype, "qname": qname}


def _ipv6_transport(frame, offset, next_header, packet_end):
    """Walk the bounded IPv6 extension chain to the TCP/UDP header."""
    fragmented = False
    is_fragment = False
    for _ in range(8):
        if next_header in (0, 43, 60):  # hop-by-hop, routing, destination options
            if offset + 2 > packet_end:
                return None, None, fragmented, is_fragment
            following = frame[offset]
            length = (frame[offset + 1] + 1) * 8
        elif next_header == 44:  # fragment
            if offset + 8 > packet_end:
                return None, None, fragmented, is_fragment
            following = frame[offset]
            is_fragment = True
            frag_field = struct.unpack_from("!H", frame, offset + 2)[0]
            fragmented = ((frag_field >> 3) & 0x1FFF) != 0
            length = 8
        elif next_header == 51:  # authentication header
            if offset + 2 > packet_end:
                return None, None, fragmented, is_fragment
            following = frame[offset]
            length = (frame[offset + 1] + 2) * 4
        else:
            return next_header, offset, fragmented, is_fragment
        if length <= 0 or offset + length > packet_end:
            return None, None, fragmented, is_fragment
        next_header, offset = following, offset + length
    return None, None, fragmented, is_fragment


def parse_ethernet_frame(frame, timestamp=None, tls_fingerprint=None):
    """Parse the fields NetWatch consumes without constructing a Scapy graph.

    Returns ``("packet", data)``, ``("arp", data)``, ``("control", data)`` or ``None``. The parser is
    deliberately bounded: malformed lengths, extension loops, and truncated
    frames are rejected per-frame and never escape into the capture loop.
    """
    frame = memoryview(frame)
    if len(frame) < 14:
        return None
    mac_dst = _mac_text(frame[0:6])
    mac_src = _mac_text(frame[6:12])
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    vlan_ids = []
    for _ in range(2):  # 802.1Q / QinQ
        if ether_type not in (0x8100, 0x88A8, 0x9100):
            break
        if offset + 4 > len(frame):
            return None
        vlan_ids.append(struct.unpack_from("!H", frame, offset)[0] & 0x0FFF)
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    captured_at = float(timestamp) if timestamp is not None else time.time()
    if ether_type == 0x0806:  # ARP
        if offset + 28 > len(frame):
            return None
        htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", frame, offset)
        if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
            return None
        sender_mac = _mac_text(frame[offset + 8:offset + 14])
        sender_ip = ".".join(str(byte) for byte in frame[offset + 14:offset + 18])
        target_ip = ".".join(str(byte) for byte in frame[offset + 24:offset + 28])
        return "arp", {
            "timestamp": captured_at, "op": op, "sender_ip": sender_ip,
            "sender_mac": sender_mac, "target_ip": target_ip,
            "mac_src": mac_src, "mac_dst": mac_dst, "vlan_ids": vlan_ids,
        }

    if ether_type == 0x0800:  # IPv4
        if offset + 20 > len(frame) or frame[offset] >> 4 != 4:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or offset + ihl > len(frame):
            return None
        total_length = struct.unpack_from("!H", frame, offset + 2)[0]
        if total_length < ihl:
            return None
        packet_end = min(len(frame), offset + total_length) if total_length else len(frame)
        protocol = frame[offset + 9]
        ttl = frame[offset + 8]
        src_ip = bytes(frame[offset + 12:offset + 16])
        dst_ip = bytes(frame[offset + 16:offset + 20])
        frag_field = struct.unpack_from("!H", frame, offset + 6)[0]
        fragmented = (frag_field & 0x1FFF) != 0
        is_fragment = bool(frag_field & 0x3FFF)
        transport_offset = offset + ihl
    elif ether_type == 0x86DD:  # IPv6
        if offset + 40 > len(frame) or frame[offset] >> 4 != 6:
            return None
        payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
        packet_end = min(len(frame), offset + 40 + payload_length) if payload_length else len(frame)
        ttl = frame[offset + 7]
        src_ip = bytes(frame[offset + 8:offset + 24])
        dst_ip = bytes(frame[offset + 24:offset + 40])
        protocol, transport_offset, fragmented, is_fragment = _ipv6_transport(
            frame, offset + 40, frame[offset + 6], packet_end,
        )
    else:
        control_type = {0x88CC: "lldp", 0x888E: "eapol", 0x8809: "lacp"}.get(ether_type)
        if ether_type == 0x8809 and (offset >= len(frame) or frame[offset] != 1):
            control_type = "slow_protocol"
        if ether_type <= 1500 and bytes(frame[offset:offset + 3]) == b"\x42\x42\x03":
            control_type = "stp"
        if not control_type:
            return None
        return "control", {
            "timestamp": captured_at, "mac_src": mac_src, "mac_dst": mac_dst,
            "vlan_ids": vlan_ids, "ether_type": ether_type, "control_type": control_type,
            "size_bytes": len(frame), "control_payload": bytes(frame[offset:]),
        }

    protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(protocol, "IP")
    dport = 0
    tcp_flags = "---"
    payload = memoryview(b"")
    sport = 0
    icmp_type = icmp_code = None
    if not fragmented and protocol in (1, 58) and transport_offset is not None:
        if transport_offset + 4 > packet_end:
            return None
        icmp_type, icmp_code = frame[transport_offset], frame[transport_offset + 1]
    if not fragmented and protocol == 6 and transport_offset is not None:
        if transport_offset + 20 > packet_end:
            return None
        sport, dport = struct.unpack_from("!HH", frame, transport_offset)
        data_offset = (frame[transport_offset + 12] >> 4) * 4
        if data_offset < 20 or transport_offset + data_offset > packet_end:
            return None
        flag_bits = frame[transport_offset + 13] | ((frame[transport_offset + 12] & 1) << 8)
        tcp_flags = _TCP_FLAG_TEXT[flag_bits]
        payload = frame[transport_offset + data_offset:packet_end]
    elif not fragmented and protocol == 17 and transport_offset is not None:
        if transport_offset + 8 > packet_end:
            return None
        sport, dport, udp_length = struct.unpack_from("!HHH", frame, transport_offset)
        udp_end = min(packet_end, transport_offset + udp_length) if udp_length >= 8 else packet_end
        payload = frame[transport_offset + 8:udp_end]

    sni_domain = "encrypted-payload"
    dns_qr = dns_rcode = dns_qtype = dns_qname = None
    if payload and (sport in (53, 5353, 5355) or dport in (53, 5353, 5355)):
        dns_payload = payload
        if protocol == 6:
            dns_payload = memoryview(b"")
            if len(payload) >= 14:
                dns_length = struct.unpack_from("!H", payload, 0)[0]
                # A mid-stream continuation segment has no length prefix or header; accept only a
                # plausible message start (full header, known opcode, at most one question).
                if (dns_length >= 12 and (struct.unpack_from("!H", payload, 4)[0] >> 11) & 0xF <= 5
                        and struct.unpack_from("!H", payload, 6)[0] <= 1):
                    dns_payload = payload[2:min(len(payload), 2 + dns_length)]
        dns = _parse_dns(dns_payload)
        if dns:
            dns_qr, dns_rcode = dns["qr"], dns["rcode"]
            dns_qtype, dns_qname = dns["qtype"], dns["qname"]
            if dns_qr == 0 and dns_qname:
                sni_domain = dns_qname

    ja3 = ja3s = None
    ja4 = None
    # Almost every encrypted application-data segment has a payload, but only a
    # handshake record can yield JA3/JA4. Guard on the record and handshake type
    # before copying the payload out of its memoryview for the fingerprinter.
    if (len(payload) >= 6 and protocol == 6 and tls_fingerprint is not None
            and payload[0] == 0x16 and payload[5] in (0x01, 0x02)):
        fingerprint = tls_fingerprint(bytes(payload))
        if fingerprint:
            if fingerprint["kind"] == "ja3":
                ja3 = fingerprint["hash"]
                ja4 = fingerprint.get("ja4")
                if fingerprint.get("sni"):
                    sni_domain = fingerprint["sni"]
            else:
                ja3s = fingerprint["hash"]

    control_type = None
    control_payload = b""
    if not fragmented and protocol in (1, 58) and transport_offset is not None:
        control_type = ({133: "ipv6_rs", 134: "ipv6_ra", 135: "ipv6_ns",
                         136: "ipv6_na", 137: "ipv6_redirect"}.get(icmp_type, "icmpv6")
                        if protocol == 58 else "icmp")
        control_payload = bytes(frame[transport_offset:packet_end])
    elif not fragmented and protocol == 17:
        if {sport, dport} <= {67, 68} and sport and dport:
            control_type = "dhcp"
        elif {sport, dport} <= {546, 547} and sport and dport:
            control_type = "dhcpv6"
        if control_type:
            control_payload = bytes(payload)
    if not control_type and is_fragment and len(src_ip) == 16:
        control_type = "ipv6_fragment"

    return "packet", {
        "timestamp": captured_at, "mac_src": mac_src, "mac_dst": mac_dst,
        "src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol_name,
        "port": dport, "tcp_flags": tcp_flags, "ttl": ttl,
        "size_bytes": len(frame), "sni_domain": sni_domain,
        "dns_qr": dns_qr, "dns_rcode": dns_rcode, "dns_qtype": dns_qtype,
        "dns_qname": dns_qname, "ja3": ja3, "ja3s": ja3s, "ja4": ja4,
        "source_port": sport,
        "vlan_ids": vlan_ids, "ip_protocol": protocol,
        "fragmented": is_fragment, "non_initial_fragment": fragmented,
        "icmp_type": icmp_type, "icmp_code": icmp_code,
        "tls_enrichment": "single-segment; no reassembly",
        "control_type": control_type, "control_payload": control_payload,
    }


def open_capture_socket(interface, bpf_filter=None, buffer_bytes=0):
    """Open an L2 listen socket on ``interface`` with an optional BPF filter.
    Raises on failure — the caller decides whether to fall back."""
    # Importing Scapy's L2 module registers the platform capture backend in
    # ``conf.L2listen``. Importing ``scapy.config`` alone leaves it as ``None``.
    import scapy.layers.l2  # noqa: F401
    from scapy.config import conf
    # Linux defaults to Scapy's native socket, which has no pcap handle for the
    # nonblocking/batch-dispatch path; without libpcap this stays native.
    conf.use_pcap = True
    kwargs = {"iface": interface}
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    if int(buffer_bytes) <= 0 or sys.platform == "win32":
        return conf.L2listen(**kwargs)
    # libpcap sizes the Linux ring only between create and activate, and Scapy sets neither;
    # its 2 MB default holds ~128 of the mirror's coalesced frames, so any short stall dropped packets.
    from scapy.libs import winpcapy
    activate, sized = winpcapy.pcap_activate, []

    def sized_activate(handle):
        sized.append(winpcapy.pcap_set_buffer_size(handle, int(buffer_bytes)) == 0)
        return activate(handle)

    winpcapy.pcap_activate = sized_activate
    try:
        sock = conf.L2listen(**kwargs)
    finally:
        winpcapy.pcap_activate = activate
    sock.buffer_preset = sized == [True]
    return sock


def set_capture_buffer(sock, buffer_bytes):
    """Set Npcap's activated kernel buffer with its Windows-specific API.

    Returns ``True`` only when Npcap accepted the requested size. Other libpcap
    platforms simply return ``False`` and retain their native buffering policy.
    """
    if getattr(sock, "buffer_preset", False):  # Linux: sized before activation by open_capture_socket.
        return True
    handle = getattr(getattr(sock, "pcap_fd", None), "pcap", None)
    if handle is None or int(buffer_bytes) <= 0:
        return False
    try:
        from scapy.libs.winpcapy import pcap_setbuff
    except (ImportError, AttributeError):
        return False
    try:
        return pcap_setbuff(handle, int(buffer_bytes)) == 0
    except (OSError, ValueError, TypeError):
        return False


def make_capture_dispatcher(sock, on_frame):
    """Bind libpcap's batch dispatcher to a bounded raw-frame callback.

    Scapy's ``recv_raw()`` crosses Python/C once per packet and copies through a
    list, ``bytearray``, then ``bytes``.  ``pcap_dispatch`` drains a batch in C;
    its callback performs one direct bounded copy into the final ``bytes``.
    The returned closure retains the native callback for the handle lifetime.
    """
    from ctypes import string_at

    from scapy.libs.winpcapy import pcap_dispatch, pcap_handler

    handle = sock.pcap_fd.pcap

    @pcap_handler
    def receive(_user, header_pointer, data_pointer):
        header = header_pointer.contents
        timestamp = header.ts.tv_sec + float(header.ts.tv_usec) / 1e6
        on_frame(string_at(data_pointer, int(header.caplen)), timestamp)

    def dispatch(max_packets):
        result = pcap_dispatch(handle, max(1, int(max_packets)), receive, None)
        if result < 0:
            raise OSError(f"pcap_dispatch failed with status {result}")
        return result

    return dispatch


def pcap_stats(sock):
    """``{"recv", "drop", "ifdrop"}`` cumulative since capture start, or ``None``
    when the underlying handle or the libpcap symbol is unavailable."""
    try:
        import ctypes

        from scapy.libs.winpcapy import pcap_stat
        from scapy.libs.winpcapy import pcap_stats as _pcap_stats
    except Exception:
        return None

    handle = getattr(getattr(sock, "pcap_fd", None), "pcap", None)
    if handle is None:
        return None
    try:
        stat = pcap_stat()
        if _pcap_stats(handle, ctypes.byref(stat)) != 0:
            return None
        return {"recv": int(stat.ps_recv), "drop": int(stat.ps_drop), "ifdrop": int(stat.ps_ifdrop)}
    except Exception:
        return None


class DropTracker:
    """Turns cumulative pcap counters into per-interval deltas and a loss rate.

    Pure — no scapy — so the reporting logic is unit-testable without a NIC.
    Counters that go backwards (a re-opened handle) reset the baseline instead of
    reporting a nonsensical negative delta."""

    def __init__(self):
        self.last = None
        self.total_dropped = 0

    def update(self, stats):
        """Feed a ``pcap_stats()`` dict. Returns ``None`` only while establishing
        the first baseline; later samples include zero-loss intervals."""
        if not stats:
            return None
        prev, self.last = self.last, stats
        if prev is None:
            return None

        recv = stats["recv"] - prev["recv"]
        drop = stats["drop"] - prev["drop"]
        ifdrop = stats["ifdrop"] - prev["ifdrop"]
        if recv < 0 or drop < 0 or ifdrop < 0:
            return None  # counters reset; re-baseline on the next sample

        lost = drop + ifdrop
        self.total_dropped += max(0, lost)
        offered = max(recv, drop) + ifdrop  # Linux ps_recv already counts drops; ifdrop never reaches the socket.
        return {
            "received": recv,
            "offered": offered,
            "dropped": drop,
            "ifdropped": ifdrop,
            "loss_pct": (lost / offered * 100.0) if offered else 0.0,
            "total_dropped": self.total_dropped,
        }


class CaptureHealth:
    """Convert interval loss samples into state changes and sparse reminders."""

    def __init__(self, *, min_loss_pct=0.1, reminder_sec=60.0, recovery_samples=2):
        # Zero would make a perfectly clean 0.0% sample satisfy ``>= threshold``
        # and pin the state in degraded forever.
        self.min_loss_pct = max(1e-6, float(min_loss_pct))
        self.reminder_sec = max(1.0, float(reminder_sec))
        self.recovery_samples = max(1, int(recovery_samples))
        self.degraded = False
        self.clean_samples = 0
        self.last_alert = float("-inf")

    def observe(self, report, now=None):
        """Return ``"loss"``, ``"recovered"``, or ``None`` for one interval."""
        if report is None:
            return None
        now = time.time() if now is None else float(now)
        if float(report.get("loss_pct", 0.0)) >= self.min_loss_pct:
            self.clean_samples = 0
            should_alert = not self.degraded or now - self.last_alert >= self.reminder_sec
            self.degraded = True
            if should_alert:
                self.last_alert = now
                return "loss"
            return None
        if not self.degraded:
            return None
        self.clean_samples += 1
        if self.clean_samples < self.recovery_samples:
            return None
        self.degraded = False
        self.clean_samples = 0
        return "recovered"
