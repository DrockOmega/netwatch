"""Unit tests for the passive device inventory: MAC normalization, OUI vendor
lookup, new-device detection, and JSON ledger persistence. Pure logic only — no
scapy/Qt, no real network."""

import json

from netwatch_inventory import (
    DeviceInventory,
    is_locally_administered,
    is_usable_mac,
    load_oui_db,
    normalize_mac,
    oui_of,
    vendor_for,
)

OUI_DB = {"6C1FF7": "Ugreen Group Limited", "B827EB": "Raspberry Pi Foundation"}


# --- MAC normalization -----------------------------------------------------


def test_normalize_accepts_common_separators():
    want = "6c:1f:f7:00:00:04"
    assert normalize_mac("6C-1F-F7-00-00-04") == want
    assert normalize_mac("6c:1f:f7:00:00:04") == want
    assert normalize_mac("6c1f.f700.0004") == want
    assert normalize_mac("  6C1FF7000004  ") == want


def test_normalize_rejects_garbage():
    for bad in ["", "not-a-mac", "6c:1f:f7:00:00", "6c:1f:f7:00:00:zz", None, 12345]:
        assert normalize_mac(bad) is None


# --- usability / address-bit classification --------------------------------


def test_broadcast_and_zero_not_usable():
    assert not is_usable_mac("ff:ff:ff:ff:ff:ff")
    assert not is_usable_mac("00:00:00:00:00:00")


def test_multicast_not_usable():
    # I/G bit = low bit of first octet. 01:... and 33:33:.. (IPv6 mcast) are groups.
    assert not is_usable_mac("01:00:5e:00:00:fb")
    assert not is_usable_mac("33:33:00:00:00:01")
    assert is_usable_mac("6c:1f:f7:00:00:04")


def test_locally_administered_bit():
    assert is_locally_administered("02:11:22:33:44:55")   # U/L set
    assert not is_locally_administered("6c:1f:f7:00:00:04")  # globally unique


# --- OUI + vendor ----------------------------------------------------------


def test_oui_of():
    assert oui_of("6c:1f:f7:00:00:04") == "6C1FF7"
    assert oui_of("garbage") is None


def test_vendor_hit_miss_and_random():
    assert vendor_for("6c:1f:f7:00:00:04", OUI_DB) == "Ugreen Group Limited"
    assert vendor_for("3c:5a:b4:dd:ee:ff", OUI_DB) == "Unknown"  # global, not in db
    # locally-administered with no OUI hit is labelled, not "Unknown"
    assert vendor_for("02:11:22:33:44:55", OUI_DB) == "Locally-administered"


def test_load_oui_db_roundtrip_and_missing(tmp_path):
    p = tmp_path / "oui.json"
    p.write_text(json.dumps({"6c-1f-f7": "Ugreen", "b827eb": "RPi"}))
    db = load_oui_db(str(p))
    assert db["6C1FF7"] == "Ugreen" and db["B827EB"] == "RPi"
    assert load_oui_db(str(tmp_path / "nope.json")) == {}  # missing → empty, no crash


# --- inventory behavior ----------------------------------------------------


def test_observe_new_then_known():
    inv = DeviceInventory(oui_db=OUI_DB)
    r1 = inv.observe("6c:1f:f7:00:00:04", "10.0.0.11", now=100.0)
    assert r1["new_device"] is True
    assert r1["vendor"] == "Ugreen Group Limited"
    r2 = inv.observe("6c:1f:f7:00:00:04", "10.0.0.11", now=101.0)
    assert r2["new_device"] is False


def test_observe_ignores_non_devices():
    inv = DeviceInventory(oui_db=OUI_DB)
    assert inv.observe("ff:ff:ff:ff:ff:ff", "10.0.0.1") is None
    assert inv.observe("01:00:5e:00:00:fb", "224.0.0.251") is None
    assert inv.observe("garbage") is None
    assert inv.snapshot() == []


def test_observe_tracks_ips_and_count():
    inv = DeviceInventory(oui_db=OUI_DB)
    inv.observe("b8:27:eb:11:22:33", "10.0.0.5", now=1.0)
    inv.observe("b8:27:eb:11:22:33", "10.0.0.5", now=2.0)   # dup IP
    inv.observe("b8:27:eb:11:22:33", "10.0.0.9", now=3.0)   # new IP
    inv.observe("b8:27:eb:11:22:33", None, now=4.0)         # no IP
    snap = inv.snapshot()
    assert len(snap) == 1
    dev = snap[0]
    assert dev["count"] == 4
    assert dev["ips"] == ["10.0.0.5", "10.0.0.9"]
    assert dev["first_seen"] == 1.0 and dev["last_seen"] == 4.0


def test_unspecified_and_broadcast_ips_not_attributed():
    inv = DeviceInventory(oui_db=OUI_DB)
    inv.observe("90:f1:57:00:00:03", "0.0.0.0", now=1.0)          # DHCP-discover src
    inv.observe("90:f1:57:00:00:03", "255.255.255.255", now=2.0)  # limited broadcast
    inv.observe("90:f1:57:00:00:03", "10.0.0.50", now=3.0)        # real lease
    dev = inv.snapshot()[0]
    assert dev["ips"] == ["10.0.0.50"]  # only the real IP attached
    assert dev["count"] == 3            # but all three sightings counted


def test_alert_on_new_disabled():
    inv = DeviceInventory(oui_db=OUI_DB, alert_on_new=False)
    r = inv.observe("6c:1f:f7:00:00:04", "10.0.0.11")
    assert r["new_device"] is False  # still recorded, just no alert signal
    assert len(inv.snapshot()) == 1


def test_ip_list_is_bounded():
    inv = DeviceInventory(oui_db=OUI_DB)
    for i in range(60):
        inv.observe("b8:27:eb:11:22:33", f"10.0.0.{i}", now=float(i))
    assert len(inv.snapshot()[0]["ips"]) == DeviceInventory.MAX_IPS_PER_DEVICE


# --- persistence -----------------------------------------------------------


def test_ledger_persists_known_set(tmp_path):
    ledger = str(tmp_path / "devices.json")
    inv1 = DeviceInventory(oui_db=OUI_DB, ledger_path=ledger)
    assert inv1.observe("6c:1f:f7:00:00:04", "10.0.0.11", now=1.0)["new_device"] is True
    inv1.save()
    # A fresh instance loading the same ledger must treat the device as KNOWN.
    inv2 = DeviceInventory(oui_db=OUI_DB, ledger_path=ledger)
    assert inv2.observe("6c:1f:f7:00:00:04", "10.0.0.11", now=2.0)["new_device"] is False
    on_disk = json.loads((tmp_path / "devices.json").read_text())
    assert "6c:1f:f7:00:00:04" in on_disk["devices"]


def test_corrupt_ledger_degrades(tmp_path):
    ledger = tmp_path / "devices.json"
    ledger.write_text("{ not valid json")
    inv = DeviceInventory(oui_db=OUI_DB, ledger_path=str(ledger))
    assert inv.snapshot() == []  # corrupt file → empty inventory, no crash


def test_new_device_not_written_until_save(tmp_path):
    path = tmp_path / "devs.json"
    inv = DeviceInventory(OUI_DB, str(path))
    inv.observe("6c:1f:f7:00:00:04")
    assert not path.exists()
    inv.save()
    assert "6c:1f:f7:00:00:04" in json.loads(path.read_text())["devices"]


def test_inventory_refuses_past_max_devices():
    inv = DeviceInventory(OUI_DB)
    inv.MAX_DEVICES = 3
    for i in range(3):
        assert inv.observe(f"02:00:00:00:00:{i:02x}")
    assert inv.observe("02:00:00:00:00:ff") is None
    assert inv.refused == 1
    assert inv.observe("02:00:00:00:00:00")["new_device"] is False
    assert inv.devices["02:00:00:00:00:00"]["count"] == 2


def test_new_mac_flood_is_linear(tmp_path):
    import time

    inv = DeviceInventory(OUI_DB, str(tmp_path / "devs.json"))
    t0 = time.perf_counter()
    for i in range(4000):
        inv.observe(f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}")
    assert time.perf_counter() - t0 < 0.5


def test_mistyped_ledger_entry_is_dropped(tmp_path):
    path = tmp_path / "inv.json"
    good = {"vendor": "v", "first_seen": 1, "last_seen": 2, "ips": ["10.0.0.9"], "count": 1}
    bad = {**good, "ips": "10.0.0.5"}
    path.write_text(json.dumps({"devices": {"aa:bb:cc:00:00:01": bad, "aa:bb:cc:00:00:02": good}}))
    inv = DeviceInventory(ledger_path=str(path), oui_db=OUI_DB)
    assert list(inv.devices) == ["aa:bb:cc:00:00:02"]
    inv.observe("aa:bb:cc:00:00:01", "10.0.0.5", now=3)
