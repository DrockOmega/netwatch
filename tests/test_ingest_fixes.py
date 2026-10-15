"""Regressions for the ingest/detection audit fixes (ING-04, 06, 07, 08, 13, 15, 16, 17, 18)."""

import json
import runpy
import struct
from argparse import Namespace
from pathlib import Path

import pytest

import netwatch_scan
import threatintel_update
from netwatch_arp import DurableArpAnalyzer
from netwatch_assets import DurableAssetAnalyzer, rank
from netwatch_capture import parse_ethernet_frame
from netwatch_control import ControlCollector
from netwatch_scan import ingest_nmap
from netwatch_security_store import DurableIncidentStore
from netwatch_threatintel import IndicatorSet
from tests.test_arp_replay import A, record
from tests.test_assets import CONFIG, MAC_A, arp, intervals, store  # noqa: F401 - fixture
from tests.test_capture import dns_query, ethernet, ipv4, tcp

FIX = Path(__file__).parent / "fixtures"


def test_a_failed_feed_keeps_its_previous_indicators(tmp_path, monkeypatch):
    cache = tmp_path / "intel.json"
    feeds = tmp_path / "feeds.json"
    feeds.write_text(json.dumps([{"name": n, "url": f"http://x.invalid/{n}", "type": "domains"} for n in "ab"]))
    served = {"a": "old-a.example\n", "b": "old-b.example\n"}
    monkeypatch.setattr(threatintel_update, "_fetch", lambda url, _timeout: served[url[-1]])
    args = Namespace(cache=str(cache), feeds_file=str(feeds), timeout=1)
    threatintel_update.cmd_update(args)
    served["a"] = "new-a.example\n"
    del served["b"]  # feed b is down: KeyError stands in for the network failure
    threatintel_update.cmd_update(args)
    domains = json.loads(cache.read_text())["domains"]
    assert domains == {"new-a.example": "a", "old-b.example": "b"}


def test_ping_only_rescan_does_not_resolve_exposure_findings(store):  # noqa: F811
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": ["10.0.0.0/24"]})
    ingest_nmap(analyzer, (FIX / "nmap_lan.xml").read_bytes(), ["10.0.0.0/24"])
    ping = (b'<?xml version="1.0"?><nmaprun><host endtime="2100"><status state="up"/>'
            b'<address addr="10.0.0.5" addrtype="ipv4"/></host></nmaprun>')
    assert ingest_nmap(analyzer, ping, ["10.0.0.0/24"])["drift"] == []


def test_scaninfo_range_lets_a_rescan_close_unlisted_ports(store):  # noqa: F811
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": ["10.0.0.0/24"]})
    ingest_nmap(analyzer, (FIX / "nmap_lan.xml").read_bytes(), ["10.0.0.0/24"])
    sweep = (b'<?xml version="1.0"?><nmaprun><scaninfo type="syn" protocol="tcp" services="1-100"/>'
             b'<host endtime="2100"><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
             b'<ports><extraports state="closed" count="100"/></ports></host></nmaprun>')
    out = ingest_nmap(analyzer, sweep, ["10.0.0.0/24"])
    assert sorted(out["drift"]) == [("closed", "10.0.0.5", "tcp", 22), ("closed", "10.0.0.5", "tcp", 23)]


def test_nmap_does_not_mask_external_exposure_score():
    assert rank("tcp", 443, {"sources": ["NMAP"], "external_peers": 3})[0] >= 50
    assert rank("tcp", 443, {"sources": ["NMAP"]})[0] == 10


def test_arp_fanout_finding_is_rate_limited_per_mac(tmp_path):
    db = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(db, {})
    for n in range(1, 7):
        record(collector, A, n, ip=f"10.0.0.{n}")
    notifications = []
    DurableArpAnalyzer(db, {"ARP_MAC_FANOUT_THRESHOLD": 2}, notifications.append).poll()
    assert len(notifications) == 1
    db.close()


def test_failed_oui_refresh_leaves_existing_db_untouched(tmp_path, monkeypatch):
    mod = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools" / "refresh_oui_db.py"))
    out = tmp_path / "oui_db.json"
    out.write_text('{"AABBCC": "Full Vendor"}')
    main = mod["main"]
    main.__globals__["OUT_PATH"] = str(out)

    def fail():
        raise OSError("offline")

    main.__globals__["build_from_ieee"] = fail
    assert main() == 1
    assert out.read_text() == '{"AABBCC": "Full Vendor"}'


def test_scan_cli_defaults_scopes_from_the_config_overlay(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(netwatch_scan, "build_config", lambda _base: ({"EXPOSURE_OWNED_SCOPES": ["192.0.2.0/24"]}, []))
    netwatch_scan.main(["x", str(FIX / "nmap_lan.xml"), str(tmp_path / "s.db")])
    assert "'10.0.0.5'" in capsys.readouterr().out  # in the compiled default scope, refused under the overlay


def test_transient_cache_read_error_is_not_an_empty_set(tmp_path):
    with pytest.raises(ValueError):
        IndicatorSet.load(str(tmp_path))  # a directory: OSError, not FileNotFoundError
    assert IndicatorSet.load(str(tmp_path / "absent.json")).counts()["domains"] == 0


def test_unchanged_inventory_is_not_re_observed(store):  # noqa: F811
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    device = {"mac": MAC_A, "vendor": "V", "first_seen": 10, "last_seen": 20}
    analyzer.observe_inventory([device])
    analyzer.observe_inventory([device])
    [row] = store._read("SELECT observations FROM security_asset_identities WHERE kind='mac'")
    assert row["observations"] == 2  # first/last on the first cycle only
    analyzer.observe_inventory([dict(device, last_seen=30)])
    assert intervals(store, "mac", MAC_A)[0][1:] == (10, 30)


def test_dns_over_tcp_continuation_segment_is_not_parsed():
    msg = dns_query("example.com")
    start = parse_ethernet_frame(ethernet(ipv4(tcp(struct.pack("!H", len(msg)) + msg, dport=53), 6)), 1.0)[1]
    assert start["dns_qname"] == "example.com"
    junk = bytes([0xFF, 0xFF, 0x12, 0x34]) + b"\xff" * 20  # mid-stream bytes
    mid = parse_ethernet_frame(ethernet(ipv4(tcp(junk, dport=53), 6)), 1.0)[1]
    assert mid["dns_qr"] is None
