"""Independent libpcap filter execution plus control-plane parser fixtures."""

import ctypes
import ctypes.util
import struct

import pytest

from netwatch_capture import parse_ethernet_frame
from netwatch_config import CAPTURE_PROFILES, build_config
from tests.test_capture import ethernet, ipv4, ipv6, tcp, udp


def _passes_filter(expression, frame):
    if expression is None:
        return True  # Full profile installs no kernel filter.
    library = ctypes.util.find_library("pcap") or ctypes.util.find_library("wpcap")
    if not library:
        pytest.skip("libpcap unavailable; CI Linux installs it for filter execution")
    lib = ctypes.CDLL(library)

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_uint), ("instructions", ctypes.c_void_p)]

    class Header(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long),
                    ("captured", ctypes.c_uint), ("original", ctypes.c_uint)]

    lib.pcap_open_dead.argtypes = (ctypes.c_int, ctypes.c_int)
    lib.pcap_open_dead.restype = ctypes.c_void_p
    lib.pcap_compile.argtypes = (ctypes.c_void_p, ctypes.POINTER(Program), ctypes.c_char_p,
                                ctypes.c_int, ctypes.c_uint)
    lib.pcap_offline_filter.argtypes = (ctypes.POINTER(Program), ctypes.POINTER(Header), ctypes.c_void_p)
    lib.pcap_offline_filter.restype = ctypes.c_uint
    lib.pcap_freecode.argtypes = (ctypes.POINTER(Program),)
    lib.pcap_close.argtypes = (ctypes.c_void_p,)
    handle = lib.pcap_open_dead(1, 65535)
    assert handle
    program = Program()
    try:
        assert lib.pcap_compile(handle, ctypes.byref(program), expression.encode(), 1, 0xFFFFFFFF) == 0
        header = Header(0, 0, len(frame), len(frame))
        return bool(lib.pcap_offline_filter(ctypes.byref(program), ctypes.byref(header),
                                            ctypes.create_string_buffer(frame)))
    finally:
        lib.pcap_freecode(ctypes.byref(program))
        lib.pcap_close(handle)


def _control_frames():
    icmp = b"\x08\x00\x00\x00" + b"\x00" * 4
    ra = b"\x86\x00\x00\x00" + b"\x00" * 12
    frame4 = ipv4(icmp, 1)
    return [ethernet(frame4), ethernet(ipv6(ra, 58), 0x86DD),
            ethernet(ipv4(udp(b"dhcp", sport=67, dport=68), 17)),
            ethernet(struct.pack("!HH", 42, 0x0800) + frame4, 0x8100),
            ethernet(struct.pack("!HHHH", 100, 0x8100, 42, 0x0800) + frame4, 0x88A8),
            ethernet(b"\x02\x07chassis\x00\x00", 0x88CC),
            ethernet(b"\x01\x00\x00\x00", 0x888E),
            ethernet(b"\x42\x42\x03" + b"\x00" * 35, 38)]


@pytest.mark.parametrize("profile", CAPTURE_PROFILES)
def test_compiled_capture_profiles_preserve_control_and_tagged_frames(profile):
    for frame in _control_frames():
        assert _passes_filter(CAPTURE_PROFILES[profile], frame)


def test_balanced_excludes_only_small_bare_tcp_acks():
    ack = ethernet(ipv4(tcp(flags=0x10), 6))
    assert _passes_filter(CAPTURE_PROFILES["full"], ack)
    assert not _passes_filter(CAPTURE_PROFILES["balanced"], ack)
    assert _passes_filter(CAPTURE_PROFILES["balanced"], ethernet(ipv4(tcp(flags=0x02), 6)))


def test_vlan_icmp_and_qinq_metadata_survives():
    for frame, tags, protocol, icmp_type in [
        (_control_frames()[0], [], "ICMP", 8),
        (_control_frames()[1], [], "ICMPv6", 134),
        (_control_frames()[3], [42], "ICMP", 8),
        (_control_frames()[4], [100, 42], "ICMP", 8),
    ]:
        kind, event = parse_ethernet_frame(frame)
        assert kind == "packet"
        assert event["vlan_ids"] == tags
        assert event["protocol"] == protocol and event["icmp_type"] == icmp_type


def test_ipv6_fragment_after_extension_is_explicit():
    fragment = struct.pack("!BBHI", 6, 0, 8, 42) + b"fragment"
    hop = bytes([44, 0]) + b"\x00" * 6
    frame = ethernet(ipv6(hop + fragment, 0), 0x86DD)
    kind, event = parse_ethernet_frame(frame)
    assert kind == "packet"
    assert event["fragmented"] is True and event["non_initial_fragment"] is True
    assert event["source_port"] == 0 and event["ja3"] is None
    assert _passes_filter(CAPTURE_PROFILES["balanced"], frame)


def test_custom_capture_filter_is_preserved_and_invalid_profile_rejected(tmp_path):
    cfg, _ = build_config(tmp_path, extra={"BPF_FILTER": "udp port 53", "GATEWAY_IP": "10.0.0.1"})
    assert cfg["BPF_FILTER"] == "udp port 53"
    with pytest.raises(ValueError, match="CAPTURE_PROFILE"):
        build_config(tmp_path, extra={"CAPTURE_PROFILE": "typo"})
