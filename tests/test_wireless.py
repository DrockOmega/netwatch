import pytest

from netwatch_assets import DurableAssetAnalyzer, asset_detail, list_assets
from netwatch_capture import parse_ethernet_frame
from netwatch_control import ControlCollector
from netwatch_security_store import DurableIncidentStore
from netwatch_wireless import COVERAGE, WirelessWatch, wireless_labels
from tests.test_assets import CONFIG, MAC_A, MAC_B, arp, dhcp_ack
from tests.test_capture import SRC_MAC

NOW = 10_000_000
DAY = 86400
PRIVATE = "02:11:22:33:44:55"
AP_MAC = "84:d8:1b:00:00:06"


@pytest.fixture
def store(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    yield store
    store.close()


def watch(store, **config):
    seen = []
    return WirelessWatch(store, config, notify=seen.append), seen, DurableAssetAnalyzer(store, CONFIG)


def test_baseline_does_not_flood_and_new_device_fires_once(store):
    for i, mac in enumerate((MAC_A, MAC_B, PRIVATE)):
        arp(store, mac, f"10.0.0.{50 + i}", 1000 + i)  # long-silent history
    ww, seen, assets = watch(store)
    assets.poll()
    assert ww.poll(now=NOW) == 0 and seen == []  # first run: all existing assets are baseline
    assert ww.poll(now=NOW + 60) == 0  # quiet-at-baseline devices are not reported later either
    arp(store, "00:aa:bb:cc:dd:ee", "10.0.0.70", NOW + 10)
    assets.poll()
    assert ww.poll(now=NOW + 120) == 1
    [new] = seen
    assert new["action"] == "WIRELESS_DEVICE_NEW" and new["data"]["offender_mac"] == "00:aa:bb:cc:dd:ee"
    assert ww.poll(now=NOW + 180) == 0


def test_history_replay_into_fresh_store_is_baseline_not_new(store):
    ww, seen, assets = watch(store)
    assert ww.poll(now=NOW) == 0  # the watch starts before any asset exists
    arp(store, MAC_A, "10.0.0.50", NOW - 5000)  # replayed old record creates a new asset row
    assets.poll()
    assert ww.poll(now=NOW + 60) == 0 and seen == []


def test_ap_mac_is_not_a_new_device(store):
    ww, seen, assets = watch(store, WIRELESS_AP_MACS=[AP_MAC])
    ww.poll(now=NOW)
    arp(store, AP_MAC, "10.0.0.99", NOW + 5)
    assets.poll()
    assert ww.poll(now=NOW + 60) == 0


def test_quiet_reported_once_and_private_macs_suppressed(store):
    arp(store, MAC_A, "10.0.0.50", NOW - 10)
    arp(store, PRIVATE, "10.0.0.51", NOW - 10)
    ww, seen, assets = watch(store, WIRELESS_QUIET_SEC=DAY)
    assets.poll()
    ww.poll(now=NOW)
    assert ww.poll(now=NOW + DAY - 100) == 0  # inside the window
    assert ww.poll(now=NOW + DAY + 100) == 1
    [quiet] = seen
    assert quiet["action"] == "WIRELESS_DEVICE_QUIET" and quiet["data"]["offender_mac"] == MAC_A
    assert quiet["data"]["severity"] == "info"
    assert ww.poll(now=NOW + 5 * DAY) == 0  # one report per quiet spell; the private MAC never reports
    arp(store, MAC_A, "10.0.0.50", NOW + 6 * DAY)  # it came back, then goes quiet again
    assets.poll()
    ww.poll(now=NOW + 6 * DAY + 10)
    assert ww.poll(now=NOW + 8 * DAY) == 1


def test_labels_are_marked_inference(store):
    private = wireless_labels(PRIVATE)
    assert private["private_mac"]["value"] and private["private_mac"]["basis"].startswith("observed")
    assert private["likely_wireless"]["basis"].startswith("inference")
    assert wireless_labels(MAC_A, "Espressif Inc.")["likely_wireless"]["value"]
    assert wireless_labels(MAC_A, "Cisco", "Johns-iPhone")["likely_wireless"]["value"]
    plain = wireless_labels(MAC_A, "Cisco", "switch1")
    assert plain["private_mac"]["value"] is False and plain["likely_wireless"]["value"] is False
    arp(store, PRIVATE, "10.0.0.51", 100)
    DurableAssetAnalyzer(store, CONFIG).poll()
    [asset] = list_assets(store)
    assert asset["labels"]["private_mac"]["value"] and asset["labels"]["likely_wireless"]["value"]
    assert asset_detail(store, asset["asset_id"])["labels"] == asset["labels"]


def test_ap_guard_second_ip(store):
    ww, seen, _ = watch(store, WIRELESS_AP_ADDRESSES=["10.0.0.99"], WIRELESS_AP_MACS=[AP_MAC])
    one = {"mac": AP_MAC, "ips": ["10.0.0.99"], "last_seen": NOW}
    assert ww.poll(now=NOW, devices=[one]) == 0 and ww.poll(now=NOW + 1, devices=[one]) == 0  # AP mode: quiet
    nat = {**one, "ips": ["10.0.0.99", "192.168.0.1"]}
    assert ww.poll(now=NOW + 2, devices=[nat]) == 1 and ww.poll(now=NOW + 3, devices=[nat]) == 0
    assert seen[0]["action"] == "WIRELESS_AP_MODE" and seen[0]["data"]["severity"] == "alert"


def test_ap_guard_dhcp_server(tmp_path, store):
    # The shared test frame is a DHCP ACK from 10.0.0.1 with the shared source MAC.
    frame = dhcp_ack(b"x")
    ControlCollector(store, {"SENSOR_ID": "sensor-a", "NIC_INTERFACE": "mirror"}).process(
        frame, parse_ethernet_frame(frame, timestamp=NOW)[1], received_at=NOW)
    bridge, quiet_seen, _ = watch(store, WIRELESS_AP_ADDRESSES=["10.0.0.99"], WIRELESS_AP_MACS=[AP_MAC])
    assert bridge.poll(now=NOW + 1) == 0 and quiet_seen == []  # the xFi answering DHCP is normal
    for n, key in enumerate(({"WIRELESS_AP_ADDRESSES": ["10.0.0.1"]}, {"WIRELESS_AP_MACS": [SRC_MAC.hex(":")]})):
        other = DurableIncidentStore(tmp_path / f"other{n}.db", sensor_id="sensor-a")
        try:
            ControlCollector(other, {"SENSOR_ID": "sensor-a", "NIC_INTERFACE": "mirror"}).process(
                frame, parse_ethernet_frame(frame, timestamp=NOW)[1], received_at=NOW)
            ww, seen, _ = watch(other, **key)
            assert ww.poll(now=NOW + 1) == 1
            assert seen[0]["action"] == "WIRELESS_AP_MODE" and "DHCP" in seen[0]["data"]["message"]
        finally:
            other.close()


def test_coverage_is_declared_unsupported(store):
    ww, _, _ = watch(store)
    coverage = ww.health()["coverage"]
    assert coverage is COVERAGE and any("deauthentication" in item for item in coverage["unsupported"])
    assert any("uplink mirror" in item for item in coverage["blind_spots"])


def test_notify_failure_is_counted(store):
    def boom(payload):
        raise RuntimeError("queue closed")

    ww = WirelessWatch(store, {}, notify=boom)
    assets = DurableAssetAnalyzer(store, CONFIG)
    ww.poll(now=NOW)
    arp(store, MAC_A, "10.0.0.50", NOW - 5000 + 100)
    assets.poll()
    arp(store, "00:aa:bb:cc:dd:ee", "10.0.0.70", NOW + 10)
    assets.poll()
    assert ww.poll(now=NOW + 120) == 1
    assert store.open_count() == 1  # the detection is committed despite the failed notify
    assert ww.health()["notify_failures"] == 1
