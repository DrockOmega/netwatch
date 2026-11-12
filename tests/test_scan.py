from pathlib import Path

import pytest

from netwatch_assets import DurableAssetAnalyzer, exposure, list_assets
from netwatch_scan import ingest_nmap
from tests.test_assets import store  # noqa: F401 - fixture

XML = (Path(__file__).parent / "fixtures" / "nmap_lan.xml").read_bytes()
SCOPES = ["10.0.0.0/24"]


def test_ingest_records_in_scope_open_ports_and_refuses_out_of_scope(store):  # noqa: F811
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": SCOPES})
    assert ingest_nmap(analyzer, XML, SCOPES) == {"hosts": 1, "services": 2, "refused": ["203.0.113.9"], "drift": []}
    findings = {(f["body"]["port"], f["body"]["ip"]): f["body"] for f in exposure(store)}
    assert set(findings) == {(22, "10.0.0.5"), (23, "10.0.0.5")}
    telnet = findings[(23, "10.0.0.5")]
    assert telnet["sources"] == ["NMAP"] and "active nmap scan" in telnet["verification"]
    assert telnet["score"] == 40  # 10 active + 30 cleartext admin protocol
    assets = list_assets(store)
    assert len(assets) == 1
    assert assets[0]["current"] == {"hostname": "nas.lan", "ip": "10.0.0.5", "mac": "00:11:22:33:44:55"}
    ingest_nmap(analyzer, XML, SCOPES)  # idempotent: same findings, no duplicates
    assert len(exposure(store)) == 2 and len(list_assets(store)) == 1


@pytest.mark.parametrize("bad", [b"<nmaprun", b"<other/>", b'<!DOCTYPE nmaprun [<!ENTITY a "b">]><nmaprun/>'])
def test_ingest_rejects_untrusted_xml(store, bad):  # noqa: F811
    with pytest.raises(ValueError):
        ingest_nmap(DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": SCOPES}), bad, SCOPES)


def test_drift_new_service_new_host_and_closed_service_resolves_finding(store):  # noqa: F811
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": SCOPES})
    ingest_nmap(analyzer, XML, SCOPES)  # baseline: no drift
    assert store.snapshot() == []
    out = ingest_nmap(analyzer, (Path(__file__).parent / "fixtures" / "nmap_lan2.xml").read_bytes(), SCOPES)
    assert sorted(out["drift"]) == [("closed", "10.0.0.5", "tcp", 23), ("new_host", "10.0.0.9"),
                                    ("new_service", "10.0.0.5", "tcp", 443)]
    assert {row["action"] for row in store.snapshot()} == {
        "EXPOSURE_NEW_SERVICE", "EXPOSURE_NEW_HOST", "EXPOSURE_SERVICE_CLOSED"}
    status = {f["body"]["port"]: f["body"]["status"] for f in exposure(store) if f["body"]["ip"] == "10.0.0.5"}
    assert status == {22: "open", 23: "resolved", 443: "open"}


def test_host_not_covered_by_rescan_is_not_closed(store):  # noqa: F811
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": SCOPES})
    ingest_nmap(analyzer, XML, SCOPES)
    other = (b'<nmaprun><host starttime="2000" endtime="2100"><status state="up"/>'
             b'<address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>')
    assert ingest_nmap(analyzer, other, SCOPES)["drift"] == []
    assert {f["body"]["status"] for f in exposure(store)} == {"open"}
