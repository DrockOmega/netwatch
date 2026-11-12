"""Unit tests for threat-intel feed parsing and matching. Sample feed snippets only
— no network."""

import ipaddress
import json

import pytest

from netwatch_core import compile_v4_prefixes, ip_pack, is_global_ip, is_local_ip
from netwatch_threatintel import (
    IndicatorBuilder,
    IndicatorSet,
    parse_domains,
    parse_ip_csv,
    parse_ipset,
    parse_ja3_csv,
)


def ipi(s):
    return int(ipaddress.ip_address(s))


def ipb(s):
    """Packed address bytes (4 for v4, 16 for v6) — how the monitor keys an IP."""
    return ipaddress.ip_address(s).packed


# --- parsers ---------------------------------------------------------------


def test_parse_ipset_firehol_and_spamhaus():
    text = """# FireHOL level1
1.2.3.0/24
8.8.8.8
; Spamhaus DROP
192.0.2.0/24 ; SBL123
not-an-ip
2001:db8::/32
"""
    ranges = parse_ipset(text)
    # 3 IPv4 + 1 IPv6 entry (garbage skipped); each range carries its version
    assert len(ranges) == 4
    assert (ipi("1.2.3.0"), ipi("1.2.3.255"), 4) in ranges
    assert (ipi("8.8.8.8"), ipi("8.8.8.8"), 4) in ranges
    assert (ipi("2001:db8::"), ipi("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), 6) in ranges


def test_parse_ip_csv_feodo():
    text = '# Feodo Tracker\n"2024-01-01","203.0.113.5","447","online","Dridex"\n'
    ranges = parse_ip_csv(text)
    assert ranges == [(ipi("203.0.113.5"), ipi("203.0.113.5"), 4)]


def test_parse_domains_hostfile_and_plain():
    text = "# comment\n127.0.0.1 bad-domain.example\n0.0.0.0 evil.test\nplain-bad.org\n"
    domains = parse_domains(text)
    assert domains == {"bad-domain.example", "evil.test", "plain-bad.org"}


def test_parse_ja3_csv():
    text = "# ja3_md5,first_seen,reason\ne7d705a3286e19ea42f587b344ee6865,2019-01-01,Malware\nbadline\n"
    assert parse_ja3_csv(text) == {"e7d705a3286e19ea42f587b344ee6865"}


# --- IndicatorSet matching -------------------------------------------------


def test_match_ip_in_and_out_of_range():
    s = IndicatorSet(ranges=[(ipi("1.2.3.0"), ipi("1.2.3.255"), "firehol")])
    assert s.match_ip(ipi("1.2.3.5")) == "firehol"
    assert s.match_ip(ipi("1.2.3.0")) == "firehol"     # network address
    assert s.match_ip(ipi("1.2.3.255")) == "firehol"   # broadcast
    assert s.match_ip(ipi("1.2.4.0")) is None
    assert s.match_ip(ipi("1.2.2.255")) is None


def test_match_ip_merges_overlapping_ranges():
    s = IndicatorSet(ranges=[
        (ipi("10.0.0.0"), ipi("10.0.0.255"), "a"),
        (ipi("10.0.0.128"), ipi("10.0.1.255"), "b"),  # overlaps the first
        (ipi("203.0.113.0"), ipi("203.0.113.255"), "c"),
    ])
    assert s.match_ip(ipi("10.0.1.100")) is not None   # covered by the merged range
    assert s.match_ip(ipi("203.0.113.9")) == "c"
    assert s.counts()["ip_ranges"] == 2                # two disjoint ranges after merge


def test_match_ip_accepts_packed_bytes():
    s = IndicatorSet(ranges=[(ipi("1.2.3.0"), ipi("1.2.3.255"), "firehol")])
    assert s.match_ip(ipb("1.2.3.5")) == "firehol"   # 4-byte key
    assert s.match_ip(ipb("1.2.4.0")) is None


def test_match_ip_v6():
    s = IndicatorSet(ranges6=[(ipi("2001:db8::"), ipi("2001:db8::ffff"), "feed6")])
    assert s.match_ip(ipb("2001:db8::5")) == "feed6"      # in range, 16-byte key
    assert s.match_ip(ipb("2001:db8::1:0")) is None       # out of range
    assert s.match_ip(ipb("2606:4700::1")) is None        # different /32


def test_v4_and_v6_spaces_do_not_collide():
    # v6 "::1" and v4 "0.0.0.1" both map to int 1, but live in separate spaces.
    s = IndicatorSet(ranges6=[(ipi("::1"), ipi("::1"), "v6feed")])
    assert s.match_ip(ipb("::1")) == "v6feed"   # v6 hit
    assert s.match_ip(ipb("0.0.0.1")) is None    # same int, v4 space is empty
    assert s.counts()["ip_ranges"] == 1 and s.counts()["ip_ranges6"] == 1


def test_builder_routes_v4_and_v6():
    s = (IndicatorBuilder()
         .add("mixed", "ipset", parse_ipset("1.2.3.0/24\n2001:db8::/48\n"))
         .finalize())
    assert s.match_ip(ipb("1.2.3.9")) == "mixed"
    assert s.match_ip(ipb("2001:db8::1")) == "mixed"
    assert s.counts()["ip_ranges"] == 2 and s.counts()["ip_ranges6"] == 1


def test_serialization_roundtrip_v6(tmp_path):
    s = IndicatorSet(ranges=[(ipi("1.2.3.0"), ipi("1.2.3.255"), "f4")],
                     ranges6=[(ipi("2001:db8::"), ipi("2001:db8::ff"), "f6")])
    path = str(tmp_path / "cache6.json")
    s.save(path)
    loaded = IndicatorSet.load(path)
    assert loaded.match_ip(ipb("1.2.3.50")) == "f4"
    assert loaded.match_ip(ipb("2001:db8::50")) == "f6"


def test_match_domain_parent():
    s = IndicatorSet(domains={"evil.com": "urlhaus"})
    assert s.match_domain("evil.com") == "urlhaus"
    assert s.match_domain("a.b.evil.com") == "urlhaus"  # subdomain matches parent
    assert s.match_domain("notevil.com") is None
    assert s.match_domain("evil.com.attacker.net") is None


def test_match_ja3():
    s = IndicatorSet(ja3={"abc123": "sslbl"})
    assert s.match_ja3("ABC123") == "sslbl"   # case-insensitive
    assert s.match_ja3("deadbeef") is None


# --- local-endpoint guard (capture-loop composition) -----------------------
#
# Feeds like firehol_level1 embed bogon/RFC1918 ranges, so a LAN endpoint matches
# the blocklist. The capture loop guards each IP match with `not is_local(...)`
# (main.py) so LAN traffic does not false-positive on every flow. These tests
# exercise that exact composed rule with the real locality helper.

_LOCAL = compile_v4_prefixes(("10.", "192.168.", "172.16.", "172.31."))


def _intel_ip_hit(intel, src, dst):
    """Mirror the capture loop's IP-match decision: only PUBLIC endpoints match."""
    if not is_local_ip(dst, _LOCAL) and is_global_ip(dst) and (h := intel.match_ip(dst)):
        return "egress", h
    if not is_local_ip(src, _LOCAL) and is_global_ip(src) and (h := intel.match_ip(src)):
        return "inbound", h
    return None


def test_local_endpoint_not_matched_against_bogon_feed():
    # A firehol-style feed that includes the 10/8 bogon range.
    intel = IndicatorSet(ranges=[(ipi("10.0.0.0"), ipi("10.255.255.255"), "firehol_level1")])
    # LAN-to-LAN flow from 10.0.0.172: both endpoints are local -> no alert,
    # even though both sit inside the blocklisted 10/8 range.
    assert _intel_ip_hit(intel, ip_pack("10.0.0.172"), ip_pack("10.0.0.1")) is None


def test_public_endpoint_still_matched():
    intel = IndicatorSet(ranges=[
        (ipi("10.0.0.0"), ipi("10.255.255.255"), "firehol_level1"),
        (ipi("8.8.8.0"), ipi("8.8.8.255"), "firehol_level1"),
    ])
    # Local host talking to a blocklisted public IP -> egress hit (the bad dst).
    assert _intel_ip_hit(intel, ip_pack("10.0.0.172"), ip_pack("8.8.8.9")) == ("egress", "firehol_level1")
    # Blocklisted public IP talking to a local host -> inbound hit (the bad src).
    assert _intel_ip_hit(intel, ip_pack("8.8.8.9"), ip_pack("10.0.0.172")) == ("inbound", "firehol_level1")


def test_link_local_endpoint_not_matched_against_bogon_feed():
    intel = IndicatorSet(ranges=[
        (ipi("169.254.0.0"), ipi("169.254.255.255"), "firehol_level1"),
    ])
    assert _intel_ip_hit(intel, ip_pack("169.254.181.126"), ip_pack("10.0.0.172")) is None


def test_multicast_endpoint_not_matched_against_bogon_feed():
    intel = IndicatorSet(ranges=[
        (ipi("224.0.0.0"), ipi("239.255.255.255"), "firehol_level1"),
    ])
    assert _intel_ip_hit(intel, ip_pack("10.0.0.172"), ip_pack("230.0.0.1")) is None


# --- builder + serialization ----------------------------------------------


def test_builder_and_counts():
    s = (IndicatorBuilder()
         .add("firehol", "ipset", parse_ipset("1.2.3.0/24\n8.8.8.8\n"))
         .add("urlhaus", "domains", parse_domains("evil.test\n"))
         .add("sslbl", "ja3_csv", parse_ja3_csv("e7d705a3286e19ea42f587b344ee6865,x,y\n"))
         .finalize())
    c = s.counts()
    assert c["ip_ranges"] == 2 and c["domains"] == 1 and c["ja3"] == 1
    assert s.match_ip(ipi("1.2.3.9")) == "firehol"


def test_serialization_roundtrip(tmp_path):
    s = IndicatorSet(ranges=[(ipi("1.2.3.0"), ipi("1.2.3.255"), "f")],
                     domains={"evil.com": "u"}, ja3={"abc": "s"}, meta={"f": 1})
    path = str(tmp_path / "cache.json")
    s.save(path, extra={"fetched_at": 123})
    loaded = IndicatorSet.load(path)
    assert loaded.match_ip(ipi("1.2.3.50")) == "f"
    assert loaded.match_domain("evil.com") == "u"
    assert loaded.match_ja3("abc") == "s"


def test_load_missing_is_empty():
    s = IndicatorSet.load("does-not-exist-zzz.json")
    assert s.counts()["ip_ranges"] == 0 and s.match_ip(ipi("8.8.8.8")) is None


def test_load_corrupt_raises(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text('{"ranges": [[1, 2, "f"]', encoding="utf-8")
    with pytest.raises(ValueError):
        IndicatorSet.load(str(path))


def test_save_failure_keeps_old_cache(tmp_path, monkeypatch):
    path = str(tmp_path / "cache.json")
    IndicatorSet(domains={"evil.com": "u"}).save(path)

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("netwatch_threatintel.json.dump", boom)
    with pytest.raises(OSError):
        IndicatorSet(domains={"other.com": "u"}).save(path)
    assert IndicatorSet.load(path).match_domain("evil.com") == "u"


def test_ja3_keys_normalised_and_bad_shape_loads_empty(tmp_path):
    s = IndicatorSet(ja3={" ABC123 ": "s"})
    assert s.match_ja3("abc123") == "s" and s.ja3_hashes() == {"abc123"}
    path = tmp_path / "cache.json"
    path.write_text('{"ja3": [1]}', encoding="utf-8")
    assert IndicatorSet.load(str(path)).counts()["ja3"] == 0


def test_feed_ja3_ignore_drops_only_the_listed_hash(tmp_path):
    bad = "40adfd923eb82b89d8836ba37a19bca1"
    s = IndicatorSet(ja3={bad.upper(): "sslbl_ja3", "a" * 32: "sslbl_ja3"})
    assert s.match_ja3(bad) is None and s.ja3_hashes() == {"a" * 32}
    path = tmp_path / "cache.json"
    path.write_text(json.dumps({"ja3": {bad: "sslbl_ja3", "b" * 32: "sslbl_ja3"}}), encoding="utf-8")
    assert IndicatorSet.load(str(path)).ja3_hashes() == {"b" * 32}
