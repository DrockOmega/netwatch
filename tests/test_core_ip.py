"""Unit tests for the v4/v6 packed-address helpers in netwatch_core."""

import socket

from netwatch_core import (
    compile_v4_prefixes,
    compile_v6_prefixes,
    ip_family,
    ip_pack,
    ip_str,
    is_local_ip,
    ttl_profile,
)

# --- pack / unpack ---------------------------------------------------------


def test_pack_unpack_v4_roundtrip():
    b = ip_pack("192.168.1.1")
    assert b == bytes([192, 168, 1, 1]) and len(b) == 4
    assert ip_str(b) == "192.168.1.1"
    assert ip_family(b) == 4


def test_pack_unpack_v6_roundtrip():
    b = ip_pack("2001:db8::1")
    assert len(b) == 16
    # ip_str normalises to the canonical compressed form
    assert ip_str(b) == "2001:db8::1"
    assert ip_family(b) == 6


def test_pack_rejects_garbage():
    assert ip_pack("not.an.ip") is None
    assert ip_pack("999.1.1.1") is None
    assert ip_pack("") is None
    assert ip_pack("12345::xyz") is None


def test_v4_and_v6_keys_never_collide():
    # ::ffff:1.2.3.4 (v6, 16 bytes) and 1.2.3.4 (v4, 4 bytes) are distinct keys.
    assert ip_pack("::ffff:1.2.3.4") != ip_pack("1.2.3.4")
    assert len(ip_pack("::ffff:1.2.3.4")) == 16
    assert len(ip_pack("1.2.3.4")) == 4


def test_ip_str_is_total():
    # never raises on bad input — a display path must degrade, not crash
    assert ip_str(b"\x01\x02\x03") == "010203"   # odd length -> hex
    assert ip_str(12345) == "12345"              # non-bytes -> str()


def test_ttl_profile_reports_evidence_without_claiming_an_os():
    assert ttl_profile(64) == "LOW TTL"
    assert ttl_profile(128) == "MID TTL"
    assert ttl_profile(255) == "HIGH TTL"
    assert ttl_profile(0) == "UNKNOWN TTL"
    assert ttl_profile("invalid") == "UNKNOWN TTL"


# --- locality --------------------------------------------------------------

LOCAL_V4 = compile_v4_prefixes((
    "10.", "192.168.", "172.16.", "172.31.", "224.", "239.", "255.", "0.",
))


def test_is_local_v4():
    for ip in ("10.0.0.5", "192.168.1.1", "172.16.0.1", "172.31.255.1", "224.0.0.1"):
        assert is_local_ip(ip_pack(ip), LOCAL_V4), ip
    for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.5", "172.32.0.1"):
        assert not is_local_ip(ip_pack(ip), LOCAL_V4), ip


def test_is_local_v6():
    for ip in ("::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1"):
        assert is_local_ip(ip_pack(ip), LOCAL_V4), ip
    for ip in ("2001:db8::1", "2606:4700:4700::1111"):
        assert not is_local_ip(ip_pack(ip), LOCAL_V4), ip


def test_compile_v4_prefixes_ignores_non_dotted():
    pairs = compile_v4_prefixes(("10.", "fe80::/10", "192.168."))
    assert len(pairs) == 2  # the v6 prefix is skipped


def test_compile_v4_prefix_mask():
    # "192.168." -> /16 mask, matches 192.168.x.x only
    pairs = compile_v4_prefixes(("192.168.",))
    assert is_local_ip(ip_pack("192.168.255.255"), pairs)
    assert not is_local_ip(ip_pack("192.169.0.0"), pairs)


# --- delegated IPv6 prefixes (globally-routable LAN) -----------------------


def test_delegated_v6_prefix_counts_as_local():
    # An ISP-delegated /64 is globally routable, so nothing structural marks it as
    # local: without the compiled prefix, your own LAN devices read as external.
    lan = compile_v6_prefixes(("2600:1700:abcd:1200::/64",))
    assert not is_local_ip(ip_pack("2600:1700:abcd:1200::42"), LOCAL_V4)
    assert is_local_ip(ip_pack("2600:1700:abcd:1200::42"), LOCAL_V4, lan)
    # a neighbouring /64 from the same delegation is NOT this LAN
    assert not is_local_ip(ip_pack("2600:1700:abcd:1300::42"), LOCAL_V4, lan)
    # and a genuinely remote address stays remote
    assert not is_local_ip(ip_pack("2606:4700:4700::1111"), LOCAL_V4, lan)


def test_v6_structural_locality_still_applies_without_prefixes():
    for ip in ("::1", "fe80::1", "fd00::1", "ff02::1"):
        assert is_local_ip(ip_pack(ip), LOCAL_V4, ()), ip


def test_compile_v6_prefixes_skips_v4_and_garbage():
    pairs = compile_v6_prefixes(("2001:db8::/32", "10.0.0.0/8", "not-a-cidr", ""))
    assert len(pairs) == 1
    assert is_local_ip(ip_pack("2001:db8:dead::1"), (), pairs)


def test_v6_prefixes_never_affect_v4_matching():
    pairs = compile_v6_prefixes(("::/0",))  # matches every v6 address
    assert is_local_ip(ip_pack("2606:4700:4700::1111"), (), pairs)
    assert not is_local_ip(ip_pack("8.8.8.8"), (), pairs)


def test_pack_v6_loopback_and_canonicalisation():
    # inet_ntop canonicalises, so a verbose form round-trips to the short form
    assert ip_str(ip_pack("2001:0db8:0000:0000:0000:0000:0000:0001")) == "2001:db8::1"
    assert socket.inet_pton(socket.AF_INET6, "::1") == ip_pack("::1")
