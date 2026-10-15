"""Unit tests for raw-frame parsing and kernel-drop accounting.

The reporting logic is pure so it can be exercised without a NIC: what matters is
that a monitor never claims a clean capture while the driver is discarding
packets, and never reports nonsense when the counters restart.
"""

import ipaddress
import struct

import pytest

from netwatch_capture import (
    CaptureHealth,
    DropTracker,
    make_capture_dispatcher,
    open_capture_socket,
    parse_ethernet_frame,
    set_capture_buffer,
)

DST_MAC = bytes.fromhex("aabbccddeeff")
SRC_MAC = bytes.fromhex("001122334455")


def ethernet(payload, ether_type=0x0800):
    return DST_MAC + SRC_MAC + struct.pack("!H", ether_type) + payload


def ipv4(payload, protocol, src="192.168.1.10", dst="1.1.1.1"):
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, protocol, 0,
        ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed,
    )
    return header + payload


def ipv6(payload, next_header, src="2601:db8::10", dst="2606:4700:4700::1111"):
    return struct.pack(
        "!IHBB16s16s", 6 << 28, len(payload), next_header, 64,
        ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed,
    ) + payload


def tcp(payload=b"", sport=50000, dport=443, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 0, 0, 0) + payload


def udp(payload=b"", sport=50000, dport=53):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name="example.com", qtype=1):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def stats(recv, drop, ifdrop=0):
    return {"recv": recv, "drop": drop, "ifdrop": ifdrop}


def test_first_sample_establishes_baseline_only():
    tracker = DropTracker()
    assert tracker.update(stats(1000, 5)) is None


def test_zero_loss_interval_is_reported_for_health_recovery():
    tracker = DropTracker()
    tracker.update(stats(1000, 0))
    report = tracker.update(stats(5000, 0))
    assert report["received"] == 4000
    assert report["loss_pct"] == 0.0


def test_reports_delta_not_cumulative():
    tracker = DropTracker()
    tracker.update(stats(1000, 10))
    report = tracker.update(stats(2000, 60))
    assert report["received"] == 1000
    assert report["dropped"] == 50
    assert report["total_dropped"] == 50


def test_loss_percentage_is_of_offered_packets():
    tracker = DropTracker()
    tracker.update(stats(0, 0))
    report = tracker.update(stats(1000, 250))
    # ps_recv already counts drops: 250 lost of 1000 offered
    assert report["loss_pct"] == 25.0


def test_drop_greater_than_recv_clamps_to_100_percent():
    tracker = DropTracker()
    tracker.update(stats(0, 0))
    assert tracker.update(stats(100, 400))["loss_pct"] == 100.0


def test_ifdrop_counts_toward_loss():
    tracker = DropTracker()
    tracker.update(stats(0, 0, 0))
    report = tracker.update(stats(90, 0, 10))
    assert report["ifdropped"] == 10
    assert report["loss_pct"] == 10.0


def test_total_accumulates_across_intervals():
    tracker = DropTracker()
    tracker.update(stats(0, 0))
    tracker.update(stats(100, 10))
    report = tracker.update(stats(200, 25))
    assert report["dropped"] == 15
    assert report["total_dropped"] == 25


def test_counter_reset_rebaselines_instead_of_reporting_negative():
    tracker = DropTracker()
    tracker.update(stats(9000, 900))
    assert tracker.update(stats(5, 1)) is None      # handle re-opened, counters restarted
    report = tracker.update(stats(105, 11))         # next sample measures from the new baseline
    assert report["received"] == 100
    assert report["dropped"] == 10


def test_missing_stats_is_ignored():
    tracker = DropTracker()
    assert tracker.update(None) is None
    assert tracker.update({}) is None


def test_capture_health_suppresses_repeated_loss_and_emits_recovery():
    health = CaptureHealth(min_loss_pct=0.1, reminder_sec=60, recovery_samples=2)
    loss = {"loss_pct": 12.0}
    clean = {"loss_pct": 0.0}
    assert health.observe(loss, now=100) == "loss"
    assert health.observe(loss, now=110) is None
    assert health.observe(loss, now=160) == "loss"
    assert health.observe(clean, now=170) is None
    assert health.observe(clean, now=180) == "recovered"
    assert health.degraded is False


def test_capture_health_zero_threshold_does_not_mark_clean_sample_as_loss():
    health = CaptureHealth(min_loss_pct=0)
    assert health.observe({"loss_pct": 0.0}, now=100) is None
    assert health.degraded is False


def test_parse_ipv4_tcp_without_scapy_packet_graph():
    tls = b"\x16\x03\x03\x00\x05\x01test"
    frame = ethernet(ipv4(tcp(tls), 6))

    def fingerprint(payload):
        assert payload == tls
        return {"kind": "ja3", "hash": "abc123", "sni": "tls.example"}

    kind, event = parse_ethernet_frame(frame, timestamp=123.5, tls_fingerprint=fingerprint)
    assert kind == "packet"
    assert event["timestamp"] == 123.5
    assert event["mac_src"] == "00:11:22:33:44:55"
    assert event["src_ip"] == ipaddress.ip_address("192.168.1.10").packed
    assert event["dst_ip"] == ipaddress.ip_address("1.1.1.1").packed
    assert event["protocol"] == "TCP"
    assert event["port"] == 443
    assert event["tcp_flags"] == "PA"
    assert event["sni_domain"] == "tls.example"
    assert event["ja3"] == "abc123"
    assert event["size_bytes"] == len(frame)


def test_non_handshake_tls_payload_skips_fingerprinter_copy():
    frame = ethernet(ipv4(tcp(b"\x17\x03\x03\x00\x04data"), 6))

    def fingerprint(_payload):
        raise AssertionError("application data must not reach the TLS fingerprinter")

    kind, event = parse_ethernet_frame(frame, tls_fingerprint=fingerprint)
    assert kind == "packet"
    assert event["ja3"] is None
    assert event["ja3s"] is None


def test_parse_dns_query_metadata():
    frame = ethernet(ipv4(udp(dns_query("sub.example.com", qtype=16)), 17))
    kind, event = parse_ethernet_frame(frame)
    assert kind == "packet"
    assert event["protocol"] == "UDP"
    assert event["port"] == 53
    assert event["dns_qr"] == 0
    assert event["dns_rcode"] == 0
    assert event["dns_qtype"] == 16
    assert event["dns_qname"] == "sub.example.com"
    assert event["sni_domain"] == "sub.example.com"


def test_parse_ipv6_extension_header_and_udp():
    udp_datagram = udp(b"payload", sport=1234, dport=9999)
    hop_by_hop = bytes([17, 0]) + (b"\x00" * 6)
    frame = ethernet(ipv6(hop_by_hop + udp_datagram, next_header=0), ether_type=0x86DD)
    kind, event = parse_ethernet_frame(frame)
    assert kind == "packet"
    assert event["src_ip"] == ipaddress.ip_address("2601:db8::10").packed
    assert event["protocol"] == "UDP"
    assert event["port"] == 9999
    assert event["ttl"] == 64


def test_parse_arp_claim():
    arp = struct.pack(
        "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
        SRC_MAC, ipaddress.ip_address("192.168.1.20").packed,
        DST_MAC, ipaddress.ip_address("192.168.1.1").packed,
    )
    kind, claim = parse_ethernet_frame(ethernet(arp, ether_type=0x0806), timestamp=42)
    assert kind == "arp"
    assert claim == {
        "timestamp": 42.0,
        "op": 2,
        "sender_ip": "192.168.1.20",
        "sender_mac": "00:11:22:33:44:55",
        "target_ip": "192.168.1.1",
        "mac_src": "00:11:22:33:44:55", "mac_dst": "aa:bb:cc:dd:ee:ff", "vlan_ids": [],
    }


def test_parse_vlan_and_reject_truncated_frames():
    inner = ipv4(udp(b"x", dport=9999), 17)
    tagged = DST_MAC + SRC_MAC + struct.pack("!HHH", 0x8100, 7, 0x0800) + inner
    assert parse_ethernet_frame(tagged)[1]["port"] == 9999
    assert parse_ethernet_frame(b"too short") is None


def test_capture_dispatcher_batches_with_direct_c_buffer_copy(monkeypatch):
    import sys
    from ctypes import POINTER, Structure, c_long, c_ubyte, c_uint, cast, pointer
    from types import ModuleType

    payload = b"captured-frame"
    backing = (c_ubyte * len(payload)).from_buffer_copy(payload)
    class Timeval(Structure):
        _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]

    class PcapHeader(Structure):
        _fields_ = [("ts", Timeval), ("caplen", c_uint), ("len", c_uint)]

    header = PcapHeader()
    header.ts.tv_sec = 123
    header.ts.tv_usec = 250000
    header.caplen = len(payload)
    header.len = len(payload)

    class PcapFd:
        pcap = None

    class Sock:
        pcap_fd = PcapFd()

    fake_winpcapy = ModuleType("scapy.libs.winpcapy")
    fake_winpcapy.pcap_handler = lambda callback: callback

    calls = []

    def pcap_dispatch(_handle, count, callback, _user):
        calls.append(count)
        callback(None, pointer(header), cast(backing, POINTER(c_ubyte)))
        return 1

    fake_winpcapy.pcap_dispatch = pcap_dispatch
    monkeypatch.setitem(sys.modules, "scapy.libs.winpcapy", fake_winpcapy)
    captured = []
    dispatch = make_capture_dispatcher(Sock(), lambda frame, timestamp: captured.append((frame, timestamp)))
    assert dispatch(256) == 1
    assert calls == [256]
    assert captured == [(payload, 123.25)]


def test_capture_watchdog_distinguishes_idle_reads_from_stalled_loops():
    from netwatch_capture import CaptureProgress

    progress = CaptureProgress(started_at=0)
    assert progress.report(now=1)["status"] == "STARTING"
    assert progress.report(now=60)["status"] == "STARTING"  # a slow start is not a stalled loop
    assert progress.report(now=121)["status"] == "DEADLOCK_DETECTED"
    for tick in (10, 20, 30):
        progress.read_complete(now=tick)
        assert progress.report(now=tick + 1)["status"] == "IDLE"
    progress.packet_seen(now=30)
    assert progress.report(now=31)["status"] == "ALIVE"
    progress.packet_seen(now=45)  # Callbacks alone do not prove the read loop completes.
    assert progress.report(now=45)["status"] == "DEADLOCK_DETECTED"
    progress.read_failed("driver read failed")
    assert progress.report(now=46)["status"] == "CAPTURE_UNAVAILABLE"
    progress.read_complete(now=46)
    assert progress.report(now=47)["status"] == "ALIVE"


def test_capture_socket_asks_for_libpcap(monkeypatch):
    # Linux's native Scapy socket has no pcap handle, so direct capture fell back every 30 s.
    import types

    import scapy.config
    import scapy.layers.l2  # noqa: F401  (import before swapping conf; it reads conf at load)

    fake = types.SimpleNamespace(use_pcap=False)
    fake.L2listen = lambda **kw: (fake.use_pcap, kw)
    monkeypatch.setattr(scapy.config, "conf", fake)
    assert open_capture_socket("eth9", "tcp") == (True, {"iface": "eth9", "filter": "tcp"})


def test_linux_capture_ring_is_sized_before_activation(monkeypatch):
    # libpcap ignores a buffer size set after activation; the 2 MB default dropped mirror bursts.
    import types

    import scapy.config
    import scapy.layers.l2  # noqa: F401
    try:
        from scapy.libs import winpcapy
    except OSError:  # Windows without Npcap: loading winpcapy needs wpcap.dll
        pytest.skip("Npcap (wpcap.dll) not installed")

    calls = []
    monkeypatch.setattr(winpcapy, "pcap_set_buffer_size", lambda h, n: calls.append(("size", n)) or 0)
    monkeypatch.setattr(winpcapy, "pcap_activate", lambda h: calls.append(("activate",)) or 0)
    monkeypatch.setattr("sys.platform", "linux")

    def listen(**kw):
        winpcapy.pcap_activate("handle")  # what Scapy's pcap wrapper does inside L2listen
        return types.SimpleNamespace()

    monkeypatch.setattr(scapy.config, "conf", types.SimpleNamespace(use_pcap=False, L2listen=listen))
    sock = open_capture_socket("eth9", None, 64 << 20)
    assert calls == [("size", 64 << 20), ("activate",)]
    assert set_capture_buffer(sock, 64 << 20) is True


def test_start_timeout_extends_the_starting_grace():
    from netwatch_capture import CaptureProgress

    assert CaptureProgress(started_at=0).report(now=200, start_timeout=300)["status"] == "STARTING"
