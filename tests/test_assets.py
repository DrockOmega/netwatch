import ipaddress
import json
import struct
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest

from netwatch_api import ServiceAPI, load_secret
from netwatch_assets import (
    READ_LIMIT,
    AssetResolver,
    DurableAssetAnalyzer,
    asset_detail,
    exposure,
    list_assets,
    named_nodes,
)
from netwatch_capture import parse_ethernet_frame
from netwatch_client import ServiceClient
from netwatch_config import build_config
from netwatch_control import ControlCollector
from netwatch_security_store import DurableIncidentStore
from netwatch_zeek import ZeekCollector
from tests.test_capture import ethernet, ipv4, udp

CONFIG = {"LOCAL_PREFIXES": ["10.0.0.0/8"]}
MAC_A, MAC_B = "00:11:22:33:44:55", "00:66:77:88:99:aa"


def arp(store, mac, ip, t):
    sender = bytes.fromhex(mac.replace(":", ""))
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, sender, ipaddress.ip_address(ip).packed,
                       b"\xff" * 6, ipaddress.ip_address("10.0.0.1").packed)
    frame = b"\xff" * 6 + sender + struct.pack("!H", 0x0806) + body
    event_id = f"arp-{mac}-{ip}-{t}"
    store.accept_source_record("CONTROL:test", {"n": event_id}, {
        "event_id": event_id, "source": "CONTROL", "sensor_id": "sensor-a", "event_type": "arp",
        "event_time": t, "received_at": t}, {"frame": frame.hex()})


def suricata(store, event_id, t, event_type, src, dst, port, **meta):
    native = {"event_type": event_type, "src_ip": src, "dest_ip": dst, "dest_port": port, "proto": "TCP",
              "app_proto": event_type, event_type: meta}
    store.accept_source_record("SURICATA:test", {"n": event_id}, {
        "event_id": event_id, "source": "SURICATA", "sensor_id": "sensor-a", "event_type": event_type,
        "event_time": t, "received_at": t, "src_ip": src, "dst_ip": dst}, native)


def dhcp_ack(hostname, client_id=b"\x01\x00\x11\x22\x33\x44\x55"):
    body = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, 42, 0, 0, b"\0" * 4,
                       ipaddress.ip_address("10.0.0.22").packed, b"\0" * 4, b"\0" * 4,
                       bytes.fromhex("001122334455"), b"", b"")
    body += b"\x63\x82\x53\x63" + bytes([53, 1, 5, 12, len(hostname)]) + hostname
    body += bytes([61, len(client_id)]) + client_id + b"\xff"
    return ethernet(ipv4(udp(body, sport=67, dport=68), 17, "10.0.0.1", "255.255.255.255"))



def intervals(store, kind, value):
    return [(row["asset_id"], row["first_seen"], row["last_seen"]) for row in store._read(
        "SELECT * FROM security_asset_identities WHERE kind=? AND value=? ORDER BY first_seen", (kind, value))]


@pytest.fixture
def store(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    yield store
    store.close()


def test_ip_reuse_across_two_devices_opens_intervals_and_never_merges(tmp_path, store):
    arp(store, MAC_A, "10.0.0.50", 1000)
    for t in (5000, 5001, 5002):  # a rebind needs ARP_REBIND_CONFIRMATIONS claims over ARP_REBIND_MIN_SEC
        arp(store, MAC_B, "10.0.0.50", t)
    arp(store, MAC_A, "10.0.0.60", 6000)
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    assert analyzer.poll() == 5
    a = intervals(store, "mac", MAC_A)[0][0]
    b = intervals(store, "mac", MAC_B)[0][0]
    assert a != b and len(list_assets(store)) == 2
    assert intervals(store, "ip", "10.0.0.50") == [(a, 1000, 1000), (b, 5002, 5002)]
    # A service after the reuse belongs to B; a late record from before it still belongs to A.
    suricata(store, "late", 7000, "tls", "203.0.113.9", "10.0.0.50", 22)
    suricata(store, "early", 2000, "tls", "203.0.113.9", "10.0.0.50", 80)
    analyzer.poll()
    assert [s["port"] for s in asset_detail(store, b)["services"]] == [22]
    assert [s["port"] for s in asset_detail(store, a)["services"]] == [80]
    assert intervals(store, "ip", "10.0.0.50") == [(a, 1000, 2000), (b, 5002, 7000)]
    assert len(list_assets(store)) == 2
    assert analyzer.poll() == 0  # Durable cursors: nothing is replayed.


def test_one_forged_arp_claim_does_not_move_the_holder(store):
    arp(store, MAC_A, "10.0.0.50", 1000)
    arp(store, MAC_B, "10.0.0.50", 1001)  # one forged claim
    arp(store, MAC_A, "10.0.0.50", 1010)
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    analyzer.poll()
    a = intervals(store, "mac", MAC_A)[0][0]
    assert intervals(store, "ip", "10.0.0.50") == [(a, 1000, 1010)]
    for t in (1020, 1021, 1022):  # three consistent claims over 2 s do move it
        arp(store, MAC_B, "10.0.0.50", t)
    analyzer.poll()
    b = intervals(store, "mac", MAC_B)[0][0]
    assert intervals(store, "ip", "10.0.0.50") == [(a, 1000, 1010), (b, 1022, 1022)]


def ndp_na(store, mac, target, t):
    event_id = f"na-{mac}-{target}-{t}"
    layers = [{"layer": "Ether", "fields": {"src": mac}},
              {"layer": "ICMPv6ND_NA", "fields": {"tgt": target, "type": 136}}]
    store.accept_source_record("CONTROL:test", {"n": event_id}, {
        "event_id": event_id, "source": "CONTROL", "sensor_id": "sensor-a", "event_type": "ipv6_na",
        "event_time": t, "received_at": t, "mac_src": mac, "summary": {"layers": layers}}, {"frame": ""})


def test_ndp_advertisement_puts_a_temporary_ipv6_address_on_its_mac(store):
    v6 = "2601:db8:82:ba80:d409:413b:6501:eacd"
    arp(store, MAC_A, "10.0.0.12", 1000)
    ndp_na(store, MAC_A, v6, 1001)
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": ["10.0.0.0/8", "2601:db8:82:ba80::/64"]})
    analyzer.poll()
    a = intervals(store, "mac", MAC_A)[0][0]
    assert intervals(store, "ip", v6) == [(a, 1001, 1001)]
    assert store._read("SELECT count(*) AS n FROM security_assets")[0]["n"] == 1  # no address-only asset



def ndp_ns(store, mac, src, target, t):
    event_id = f"ns-{mac}-{src}-{target}-{t}"
    layers = [{"layer": "Ether", "fields": {"src": mac}},
              {"layer": "ICMPv6ND_NS", "fields": {"tgt": target, "type": 135}}]
    store.accept_source_record("CONTROL:test", {"n": event_id}, {
        "event_id": event_id, "source": "CONTROL", "sensor_id": "sensor-a", "event_type": "ipv6_ns",
        "event_time": t, "received_at": t, "mac_src": mac, "src_ip": src, "summary": {"layers": layers}},
        {"frame": ""})


def test_ndp_solicitations_put_temporary_ipv6_addresses_on_their_mac(store):
    dad, own = "2601:db8:82:ba80:4dc6:fcf:b6ff:9cdd", "2601:db8:82:ba80:2016:2fbe:99b6:9a6a"
    arp(store, MAC_A, "10.0.0.198", 1000)
    ndp_ns(store, MAC_A, "::", dad, 1001)  # duplicate-address probe names the new address
    ndp_ns(store, MAC_A, own, "fe80::1", 1002)  # an ordinary NS comes from the sender's own address
    analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": ["10.0.0.0/8", "2601:db8:82:ba80::/64"]})
    analyzer.poll()
    a = intervals(store, "mac", MAC_A)[0][0]
    assert intervals(store, "ip", dad) == [(a, 1001, 1001)]
    assert intervals(store, "ip", own) == [(a, 1002, 1002)]
    assert intervals(store, "ip", "fe80::1") == []
    assert store._read("SELECT count(*) AS n FROM security_assets")[0]["n"] == 1

def test_dhcp_hostname_change_keeps_one_asset_with_name_intervals(store):
    collector = ControlCollector(store, {"SENSOR_ID": "sensor-a", "NIC_INTERFACE": "mirror"})
    for t, name in ((100, b"laptop"), (200, b"laptop-renamed")):
        frame = dhcp_ack(name)
        collector.process(frame, parse_ethernet_frame(frame, timestamp=t)[1], received_at=t)
    arp(store, MAC_A, "10.0.0.22", 300)
    DurableAssetAnalyzer(store, CONFIG).poll()
    [asset] = list_assets(store)
    detail = asset_detail(store, asset["asset_id"])
    names = [(row["value"], row["first_seen"]) for row in detail["identities"] if row["kind"] == "hostname"]
    assert names == [("laptop", 100), ("laptop-renamed", 200)]
    assert asset["current"]["hostname"] == "laptop-renamed"
    kinds = {row["kind"]: row["value"] for row in detail["identities"]}
    assert kinds["dhcp_client_id"] == "01001122334455" and kinds["mac"] == MAC_A
    assert intervals(store, "ip", "10.0.0.22") == [(asset["asset_id"], 100, 300)]


def test_service_ranking_and_dedup(store):
    ext, lan, host = "203.0.113.9", "10.0.0.7", "10.0.0.5"
    suricata(store, "T1", 110, "http", ext, host, 23)
    suricata(store, "H1", 130, "http", lan, host, 8080)
    suricata(store, "S1", 120, "tls", ext, host, 443)
    suricata(store, "N1", 110 + 86400, "tls", ext, host, 2222)
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    analyzer.poll()
    ranked = [(f["body"]["port"], f["score"]) for f in exposure(store)]
    assert ranked == [(23, 80), (2222, 70), (443, 50), (8080, 40)]
    telnet = exposure(store)[0]["body"]
    assert [r["reason"] for r in telnet["reasons"]] == [
        "answered 1 inbound connection(s) from external peers",
        "cleartext protocol commonly used for administration: Telnet"]
    assert telnet["evidence"] and telnet["ip"] == host
    assert "new listening service" in exposure(store)[1]["body"]["reasons"][-1]["reason"]
    # The same exposure seen again is one finding with a higher count, not a second finding.
    suricata(store, "T2", 200, "http", ext, host, 23)
    analyzer.poll()
    findings = [f for f in exposure(store) if f["body"]["port"] == 23]
    assert len(findings) == 1 and findings[0]["observations"] == 2 and findings[0]["last_seen"] == 200
    assert findings[0]["body"]["reasons"][0]["reason"].startswith("answered 2 inbound")
    assert len(exposure(store)) == 4


def test_suricata_tls_http_and_inventory_feed(store):
    for event_id, native in (
            ("tls-1", {"event_type": "tls", "src_ip": "198.51.100.4", "dest_ip": "10.0.0.9", "dest_port": 443,
                       "proto": "TCP", "app_proto": "tls", "tls": {"version": "TLS 1.0", "sni": "nas.local"}}),
            ("http-1", {"event_type": "http", "src_ip": "10.0.0.8", "dest_ip": "10.0.0.9", "dest_port": 80,
                        "proto": "TCP", "app_proto": "http",
                        "http": {"http_user_agent": "curl/8.5.0", "server": "lighttpd/1.4.35"}})):
        store.accept_source_record("SURICATA:test", {"n": event_id}, {
            "event_id": event_id, "source": "SURICATA", "sensor_id": "sensor-a",
            "event_type": native["event_type"], "event_time": 500, "received_at": 500}, native)
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    analyzer.poll()
    analyzer.observe_inventory([{"mac": MAC_A, "vendor": "Fixture Vendor", "first_seen": 10, "last_seen": 20,
                                 "ips": ["10.0.0.9"], "count": 4}])
    assets = {tuple(sorted(a["current"].items())): a for a in list_assets(store)}
    assert len(assets) == 3  # server, client, and the inventory MAC (inventory IPs carry no times)
    server = next(a for a in assets.values() if a["current"].get("ip") == "10.0.0.9")
    detail = asset_detail(store, server["asset_id"])
    assert {(s["protocol"], s["port"]) for s in detail["services"]} == {("tcp", 80), ("tcp", 443)}
    assert {(s["name"], s["version"]) for s in detail["software"]} == {("TLS", "TLS 1.0"), ("lighttpd/1.4.35", "")}
    client = next(a for a in assets.values() if a["current"].get("ip") == "10.0.0.8")
    assert asset_detail(store, client["asset_id"])["software"][0]["name"] == "curl/8.5.0"
    inventory = next(a for a in assets.values() if a["current"].get("mac") == MAC_A)
    assert inventory["body"]["vendor"] == "Fixture Vendor" and intervals(store, "mac", MAC_A)[0][1:] == (10, 20)


def test_owned_scopes_are_validated_but_unused(tmp_path):
    base = {"GATEWAY_IP": "10.0.0.1", "LOCAL_PREFIXES6_AUTO": False}
    assert build_config(tmp_path, extra=base)[0]["EXPOSURE_OWNED_SCOPES"] == ("10.0.0.0/24",)
    config, _ = build_config(tmp_path, extra={**base, "EXPOSURE_OWNED_SCOPES": ["203.0.113.7/32", "2001:db8::/48"]})
    assert config["EXPOSURE_OWNED_SCOPES"] == ("203.0.113.7/32", "2001:db8::/48")
    for bad in ("203.0.113.0/24", ["not-a-cidr"], ["0.0.0.0/0"]):
        with pytest.raises(ValueError, match="EXPOSURE_OWNED_SCOPES"):
            build_config(tmp_path, extra={**base, "EXPOSURE_OWNED_SCOPES": bad})


def test_asset_and_exposure_api_requires_auth_and_is_bounded(tmp_path, store):
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    with store._transaction():
        for index in range(READ_LIMIT + 20):
            analyzer.observe(float(index), "TEST", None, mac=f"00:00:00:00:{index // 256:02x}:{index % 256:02x}")
        asset_id = analyzer.observe(1.0, "TEST", None, mac="00:00:00:00:00:01")
        analyzer._service("10.0.0.3", 5.0, "TEST", "ref", "tcp", 23)
    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence")}
    secret = load_secret(tmp_path / "api.secret", create=True)
    api = ServiceAPI(SimpleNamespace(store=store, runtime=SimpleNamespace(config=config)), secret, port=0).start()
    try:
        client = ServiceClient(f"http://127.0.0.1:{api.server.server_port}", secret, timeout=2)
        for endpoint in ("assets", "assets/" + asset_id, "exposure"):
            with pytest.raises(HTTPError) as rejected:
                build_opener(ProxyHandler({})).open(Request(client.url + "/v1/" + endpoint))
            assert rejected.value.code == 401
        assert len(client.request("assets")["data"]) == 200
        assert len(client.request("assets", limit=100000)["data"]) == READ_LIMIT
        assert len(client.request("assets", limit=3)["data"]) == 3
        assert client.request("assets/" + asset_id)["data"]["identities"][0]["value"] == "00:00:00:00:00:01"
        assert client.request("assets/" + "0" * 32)["data"] is None
        assert client.request("exposure", limit=1)["data"][0]["body"]["port"] == 23
        for bad in ("assets/not-an-id", "assets?limit=x", "exposure?limit=1e9"):
            with pytest.raises(HTTPError) as rejected:
                client.request(bad)
            assert rejected.value.code == 400
    finally:
        api.close()


def source_record(store, event_id, t, src, dst):
    store.accept_source_record("SURICATA:test", {"n": event_id}, {
        "event_id": event_id, "source": "SURICATA", "sensor_id": "sensor-a", "event_type": "alert",
        "event_time": t, "received_at": t, "src_ip": src, "dst_ip": dst, "asset_ids": []}, {})


def test_records_resolve_to_the_asset_holding_the_address_at_their_time(tmp_path, store):
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    with store._transaction():
        sensor1 = analyzer.observe(100.0, "T", None, mac=MAC_A, ip="10.0.0.12")  # MAC-backed identity
        first = analyzer.observe(100.0, "T", None, mac=MAC_A, ip="10.0.0.50")
        second = analyzer.observe(5000.0, "T", None, mac=MAC_B, ip="10.0.0.50")  # address reassigned
    assert sensor1 == first != second
    source_record(store, "net-old", 300.0, "10.0.0.50", "93.184.216.34")
    source_record(store, "net-new", 6000.0, "93.184.216.34", "10.0.0.50")
    source_record(store, "remote", 6000.0, "93.184.216.34", "8.8.8.8")
    source_record(store, "both", 6000.0, "10.0.0.12", "10.0.0.50")
    ids = {row["event_id"]: row["normalized"]["asset_ids"]
           for row in AssetResolver(store, CONFIG).annotate(store.source_events(limit=50))}
    assert ids["net-old"] == [first]
    assert ids["net-new"] == [second]
    assert ids["remote"] == []  # non-local addresses never resolve
    assert ids["both"] == [sensor1, second]


def test_wazuh_records_pivot_by_agent_address(tmp_path, store):
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    with store._transaction():
        sensor = analyzer.observe(100.0, "T", None, mac=MAC_A, ip="10.0.0.12")
    for event_id, agent in (("w1", "10.0.0.12"), ("remote", "8.8.4.4")):
        store.accept_source_record("WAZUH:test", {"n": event_id}, {
            "event_id": event_id, "source": "WAZUH", "sensor_id": "sensor-a", "event_type": "alert",
            "event_time": 200.0, "received_at": 200.0, "src_ip": None, "dst_ip": None,
            "agent": {"address": agent}, "asset_ids": []}, {})
    ids = {row["event_id"]: row["normalized"]["asset_ids"]
           for row in AssetResolver(store, CONFIG).annotate(store.source_events(limit=50))}
    assert ids == {"w1": [sensor], "remote": []}


def test_asset_records_endpoint_pivots_and_is_bounded(tmp_path, store):
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    with store._transaction():
        asset = analyzer.observe(100.0, "T", None, mac=MAC_A, ip="10.0.0.12")
    for index in range(5):
        source_record(store, f"w{index}", 200.0 + index, "10.0.0.12", "93.184.216.34")
    source_record(store, "other", 300.0, "10.0.0.99", "93.184.216.34")
    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence"), **CONFIG}
    secret = load_secret(tmp_path / "api.secret", create=True)
    api = ServiceAPI(SimpleNamespace(store=store, runtime=SimpleNamespace(config=config)), secret, port=0).start()
    try:
        client = ServiceClient(f"http://127.0.0.1:{api.server.server_port}", secret, timeout=2)
        records = client.request(f"assets/{asset}/records")["data"]["records"]
        assert sorted(row["event_id"] for row in records) == [f"w{index}" for index in range(5)]
        assert all(row["normalized"]["asset_ids"] == [asset] for row in records)
        sources = client.request("sources")["data"]
        assert {row["event_id"]: row["normalized"]["asset_ids"] for row in sources}["other"] == []
        assert client.request("assets/" + "0" * 32 + "/records")["data"] is None
    finally:
        api.close()


def test_asset_poll_takes_the_writer_lock_once_and_only_with_work(store):
    """Nine per-stream lock waits every 2 s kept the core loop from turning for 30 s on the sensor VM."""
    arp(store, MAC_A, "10.0.0.50", 1000)
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    begins = []
    store.conn.set_trace_callback(lambda sql: sql == "BEGIN IMMEDIATE" and begins.append(sql))
    assert analyzer.poll() == 1 and len(begins) == 1
    assert analyzer.poll() == 0 and len(begins) == 1  # nothing new: no writer lock at all


def test_assets_carry_the_configured_secure_node_name(store):
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    with store._transaction():
        analyzer.observe(1.0, "T", None, mac=MAC_A.upper(), ip="10.0.0.5")
        analyzer.observe(1.0, "T", None, mac=MAC_B, ip="10.0.0.6")
    nodes = {"phone": {"macs": [MAC_A], "ips": []}, "Other": {"macs": [], "ips": ["10.0.0.6"]}}
    names = {a["current"]["mac"]: a["node_name"] for a in list_assets(store, nodes=nodes)}
    assert names == {MAC_A: "phone", MAC_B: None}  # an IP match applies only when the asset has no MAC
    [asset] = [a for a in list_assets(store, nodes=nodes) if a["node_name"]]
    assert asset_detail(store, asset["asset_id"], nodes)["node_name"] == "phone"
    assert all(a["node_name"] is None for a in list_assets(store))


def test_device_names_label_assets_and_secure_nodes_win(store):
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    with store._transaction():
        analyzer.observe(1.0, "T", None, mac=MAC_A, ip="10.0.0.5")
        analyzer.observe(1.0, "T", None, mac=MAC_B, ip="10.0.0.6")
    config = {"SECURE_NODES": {"Phone": {"macs": [MAC_A]}}, "DEVICE_NAMES": {MAC_A: "Not Phone", MAC_B: "Xbox"}}
    names = {a["current"]["mac"]: a["node_name"] for a in list_assets(store, nodes=named_nodes(config))}
    assert names == {MAC_A: "Phone", MAC_B: "Xbox"}


def zeek(tmp_path, store, log_type, *records):
    with (tmp_path / f"{log_type}.log").open("ab") as handle:
        for record in records:
            handle.write(json.dumps(record).encode() + b"\n")
    collector = ZeekCollector(store, {"ZEEK_LOG_PATHS": [str(tmp_path / "*.log")], **CONFIG})
    collector.poll(now=1)
    collector.close()


def conn(orig, resp, port, ts, history="ShADadFf", uid="C1"):
    return {"ts": ts, "uid": uid, "id.orig_h": orig, "id.orig_p": 40000, "id.resp_h": resp,
            "id.resp_p": port, "proto": "tcp", "history": history}


def test_zeek_services_software_ranking_and_dedup(tmp_path, store):
    ext, lan, host = "203.0.113.9", "10.0.0.7", "10.0.0.5"
    zeek(tmp_path, store, "known_hosts", {"ts": 100, "host": host})
    zeek(tmp_path, store, "conn", conn(ext, host, 23, 110, uid="T1"), conn(ext, host, 443, 120, uid="S1"),
         conn(lan, host, 8080, 130, uid="H1"), conn(ext, host, 3389, 140, history="S", uid="R1"))
    zeek(tmp_path, store, "known_services",
         {"ts": 150, "host": host, "port_num": 22, "port_proto": "tcp", "service": ["SSH"]},
         {"ts": 100 + 86400 + 1, "host": host, "port_num": 2222, "port_proto": "tcp", "service": ["SSH"]})
    zeek(tmp_path, store, "software",
         {"ts": 160, "host": host, "host_p": 22, "software_type": "SSH::SERVER", "name": "OpenSSH",
          "version.major": 7, "version.minor": 4, "unparsed_version": "OpenSSH_7.4"},
         {"ts": 160, "host": "8.8.8.8", "host_p": 53, "software_type": "DNS", "name": "remote"})
    analyzer = DurableAssetAnalyzer(store, CONFIG)
    analyzer.poll()
    ranked = [(f["body"]["port"], f["score"]) for f in exposure(store)]
    assert ranked == [(23, 80), (443, 50), (8080, 40), (2222, 25), (22, 5)]
    telnet = exposure(store)[0]["body"]
    assert [r["reason"] for r in telnet["reasons"]] == [
        "answered 1 inbound connection(s) from external peers",
        "cleartext protocol commonly used for administration: Telnet"]
    assert telnet["evidence"] and telnet["ip"] == host
    assert "new listening service" in exposure(store)[3]["body"]["reasons"][-1]["reason"]
    [asset] = list_assets(store)
    [software] = asset_detail(store, asset["asset_id"])["software"]
    assert (software["name"], software["version"]) == ("OpenSSH", "OpenSSH_7.4")
    assert software["body"]["assertion"] == "hypothesis" and "not proof" in software["body"]["note"]
    # The same exposure seen again is one finding with a higher count, not a second finding.
    zeek(tmp_path, store, "conn", conn(ext, host, 23, 200, uid="T2"))
    analyzer.poll()
    findings = [f for f in exposure(store) if f["body"]["port"] == 23]
    assert len(findings) == 1 and findings[0]["observations"] == 2 and findings[0]["last_seen"] == 200
    assert findings[0]["body"]["reasons"][0]["reason"].startswith("answered 2 inbound")
    assert len(exposure(store)) == 5


V6_LAN, V6_ROUTED = "2601:db8:82:ba80::/64", "2601:db8:82:ba81::/64"
B231 = {"LOCAL_PREFIXES": ["10.0.0.0/8", V6_LAN, V6_ROUTED]}


def test_zeek_conn_puts_a_temporary_ipv6_address_on_its_mac(tmp_path, store):
    """A phone's rotating IPv6 joins its device by Zeek's orig_l2_addr, and the address-only asset
    minted for it first is absorbed with its service finding (b231)."""
    v6, ext = "2601:db8:82:ba80:e9b1:fa85:7651:acf2", "2607:f8b0:4005:80b::200e"
    arp(store, MAC_A, "10.0.0.12", 1)
    zeek(tmp_path, store, "known_hosts", {"ts": 1, "host": v6})
    zeek(tmp_path, store, "known_services", {"ts": 1, "host": v6, "port_num": 22, "port_proto": "tcp", "service": ["SSH"]})
    record = conn(v6, ext, 443, 2)
    record.update(orig_l2_addr=MAC_A, resp_l2_addr=MAC_B)  # the remote end shows the gateway's MAC
    zeek(tmp_path, store, "conn", record)
    DurableAssetAnalyzer(store, B231).poll()
    a = intervals(store, "mac", MAC_A)[0][0]
    assert [row[0] for row in intervals(store, "ip", v6)] == [a]
    assert intervals(store, "ip", ext) == []  # the gateway's MAC never takes a remote address
    assert store._read("SELECT count(*) AS n FROM security_assets")[0]["n"] == 1  # the orphan is gone
    assert [r["asset_id"] for r in store._read("SELECT asset_id FROM security_exposure_findings")] == [a]
    audit = store._read("SELECT body FROM security_native_audit WHERE operation='asset_absorbed'")
    assert len(audit) == 1 and json.loads(audit[0]["body"])["into"] == a


def test_zeek_conn_across_routed_local_networks_never_binds_the_router(tmp_path, store):
    """Across two local /64s Zeek sees the router's MAC on the far end: it must not take that address (b231)."""
    phone, routed = "2601:db8:82:ba80::12", "2601:db8:82:ba81::50"
    arp(store, MAC_A, "10.0.0.12", 1)
    arp(store, MAC_B, "10.0.0.1", 1)  # the router; GATEWAY_MAC is not configured
    for n in range(3):
        record = conn(phone, routed, 443, 2 + n, uid=f"R{n}")
        record.update(orig_l2_addr=MAC_A, resp_l2_addr=MAC_B)
        zeek(tmp_path, store, "conn", record)
    DurableAssetAnalyzer(store, B231).poll()
    router = intervals(store, "mac", MAC_B)[0][0]
    assert router not in [row[0] for row in intervals(store, "ip", routed)]


def test_address_only_asset_with_a_hostname_is_not_absorbed(tmp_path, store):
    """Only an asset whose sole identity is the address folds into its MAC's asset (b231)."""
    v6, ext = "2601:db8:82:ba80::77", "2607:f8b0:4005:80b::200e"
    arp(store, MAC_A, "10.0.0.12", 1)
    analyzer = DurableAssetAnalyzer(store, B231)
    named = analyzer.observe(1, "ZEEK", "r1", ip=v6, hostname="printer")
    record = conn(v6, ext, 443, 2)
    record.update(orig_l2_addr=MAC_A)
    zeek(tmp_path, store, "conn", record)
    analyzer.poll()
    assert store._read("SELECT count(*) AS n FROM security_assets WHERE asset_id=?", (named,))[0]["n"] == 1


def test_a_host_whose_prefix_rotated_long_ago_still_binds(tmp_path, store):
    """Only recently held networks make a MAC a router: an old ISP prefix must not stop binding (b231)."""
    old, new, ext = "2601:db8:82:ba81::12", "2601:db8:82:ba80:e9b1::12", "2607:f8b0:4005:80b::200e"
    arp(store, MAC_A, "10.0.0.12", 1)
    ndp_na(store, MAC_A, old, 2)
    zeek(tmp_path, store, "known_hosts", {"ts": 2 + 2 * 86400, "host": new})
    record = conn(new, ext, 443, 2 + 2 * 86400)
    record.update(orig_l2_addr=MAC_A)
    zeek(tmp_path, store, "conn", record)
    DurableAssetAnalyzer(store, B231).poll()
    assert [row[0] for row in intervals(store, "ip", new)] == [intervals(store, "mac", MAC_A)[0][0]]
