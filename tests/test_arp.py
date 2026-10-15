"""Unit tests for ARP-spoof / MITM detection: binding rebinds, gateway escalation,
MAC fan-out (subnet poisoning), input filtering."""

from netwatch_arp import NEW, REBIND, REBIND_CANDIDATE, STABLE, ArpWatch

GW = "10.0.0.1"
MAC_A = "02:00:00:00:01:01"   # legit gateway
MAC_B = "de:ad:be:ef:00:01"   # attacker (globally-unique form for is_usable_mac)
SINK = "02:00:00:00:de:ad"


def confirm_rebind(watch, ip, mac, start=2.0):
    results = [watch.observe(ip, mac, now=start + offset) for offset in (0.0, 1.0, 2.0)]
    return results[-1]


# --- basic binding lifecycle ----------------------------------------------


def test_new_then_stable():
    w = ArpWatch()
    r1 = w.observe("10.0.0.5", MAC_A, now=1.0)
    assert r1["event"] == NEW and r1["suspicious"] is False
    r2 = w.observe("10.0.0.5", MAC_A, now=2.0)
    assert r2["event"] == STABLE and r2["suspicious"] is False


def test_transient_rebind_is_only_a_candidate():
    w = ArpWatch()
    w.observe("10.0.0.5", MAC_A, now=1.0)
    r = w.observe("10.0.0.5", MAC_B, now=2.0)
    assert r["event"] == REBIND_CANDIDATE
    assert r["suspicious"] is False
    assert r["candidate_count"] == 1
    assert w.bindings["10.0.0.5"]["mac"] == MAC_A


def test_time_separated_rebind_confirmation_is_suspicious():
    w = ArpWatch()
    w.observe("10.0.0.5", MAC_A, now=1.0)
    r = confirm_rebind(w, "10.0.0.5", MAC_B)
    assert r["event"] == REBIND
    assert r["prev_mac"] == "02:00:00:00:01:01"
    assert r["suspicious"] is True
    assert r["severity"] == "alert"
    assert r["flaps"] == 1


def test_gateway_rebind_is_critical():
    w = ArpWatch(gateway_ip=GW)
    w.observe(GW, MAC_A, now=1.0)
    r = confirm_rebind(w, GW, MAC_B)
    assert r["event"] == REBIND and r["is_gateway"] is True
    assert r["severity"] == "critical"


def test_flaps_accumulate():
    w = ArpWatch()
    w.observe("10.0.0.5", MAC_A, now=1.0)
    confirm_rebind(w, "10.0.0.5", MAC_B, start=2.0)
    confirm_rebind(w, "10.0.0.5", MAC_A, start=5.0)
    r = confirm_rebind(w, "10.0.0.5", MAC_B, start=8.0)
    assert r["flaps"] == 3


def test_same_timestamp_burst_cannot_confirm_rebind():
    w = ArpWatch()
    w.observe("10.0.0.5", MAC_A, now=1.0)
    results = [w.observe("10.0.0.5", MAC_B, now=2.0) for _ in range(4)]
    assert all(row["event"] == REBIND_CANDIDATE for row in results)
    assert w.bindings["10.0.0.5"]["mac"] == MAC_A


def test_binding_eviction_removes_its_pending_rebind_candidate():
    w = ArpWatch(max_bindings=1)
    w.observe("10.0.0.5", MAC_A, now=1.0)
    w.observe("10.0.0.5", MAC_B, now=2.0)
    assert "10.0.0.5" in w.pending_rebinds
    w.observe("10.0.0.6", MAC_A, now=3.0)
    assert "10.0.0.5" not in w.bindings
    assert "10.0.0.5" not in w.pending_rebinds


def test_persistent_rebind_confirms_when_stable_claims_are_interleaved():
    w = ArpWatch()
    w.observe("10.0.0.5", MAC_A, now=1.0)
    w.observe("10.0.0.5", MAC_B, now=2.0)
    w.observe("10.0.0.5", MAC_A, now=2.5)
    w.observe("10.0.0.5", MAC_B, now=3.0)
    w.observe("10.0.0.5", MAC_A, now=3.5)
    assert w.observe("10.0.0.5", MAC_B, now=4.0)["event"] == REBIND


# --- MAC fan-out (subnet poisoning) ---------------------------------------


def test_mac_fanout_flags_subnet_poisoning():
    w = ArpWatch(mac_fanout_threshold=4)
    # one attacker MAC claims many IPs
    results = [w.observe(f"10.0.0.{i}", MAC_B, now=float(i)) for i in range(1, 7)]
    assert results[-1]["fanout"] == 6
    assert results[-1]["suspicious"] is True   # 6 > 4
    assert results[0]["suspicious"] is False   # fan-out of 1 is fine


def test_rebind_detaches_from_old_mac():
    w = ArpWatch(mac_fanout_threshold=100)  # isolate the fan-out bookkeeping
    w.observe("10.0.0.5", MAC_A, now=1.0)
    w.observe("10.0.0.6", MAC_A, now=1.0)
    assert w.observe("10.0.0.7", MAC_A, now=1.0)["fanout"] == 3
    # 10.0.0.5 moves to MAC_B -> MAC_A should now only claim .6 and .7
    confirm_rebind(w, "10.0.0.5", MAC_B, start=2.0)
    assert len(w.mac_ips[MAC_A]) == 2
    assert w.mac_ips[MAC_B] == {"10.0.0.5"}


# --- input filtering -------------------------------------------------------


def test_filters_unusable_inputs():
    w = ArpWatch()
    assert w.observe("0.0.0.0", MAC_A) is None              # ARP probe source
    assert w.observe("255.255.255.255", MAC_A) is None      # broadcast IP
    assert w.observe("10.0.0.5", "ff:ff:ff:ff:ff:ff") is None  # broadcast MAC
    assert w.observe("999.1.1.1", MAC_A) is None            # invalid IP
    assert w.snapshot() == []


def test_ignores_quarantine_sink_claims():
    w = ArpWatch(ignored_macs=(SINK,))
    assert w.observe(GW, SINK, now=3.0) is None
    assert w.observe(GW, MAC_A, now=4.0)["event"] == NEW


def test_live_dual_reply_flux_and_local_sink_frames_do_not_replace_trusted_bindings():
    phone_ip = "10.0.0.4"
    ap_ip = "10.0.0.174"
    phone_mac = "02:00:00:00:01:02"
    ap_mac = "02:00:00:00:01:03"
    w = ArpWatch(gateway_ip=GW, ignored_macs=(SINK,))
    w.observe(GW, MAC_A, now=1.0)
    w.observe(phone_ip, phone_mac, now=1.0)
    w.observe(ap_ip, ap_mac, now=1.0)

    flux = [
        w.observe(phone_ip, phone_mac, now=2.0),
        w.observe(ap_ip, phone_mac, now=2.0),
        w.observe(phone_ip, ap_mac, now=2.0),
        w.observe(ap_ip, ap_mac, now=2.0),
    ]
    sink_frames = [
        w.observe(GW, SINK, now=2.1),
        w.observe(phone_ip, SINK, now=2.1),
        w.observe(ap_ip, SINK, now=2.1),
    ]

    assert all(row is None or row["suspicious"] is False for row in flux)
    assert sink_frames == [None, None, None]
    assert w.bindings[GW]["mac"] == MAC_A
    assert w.bindings[phone_ip]["mac"] == phone_mac
    assert w.bindings[ap_ip]["mac"] == ap_mac


def test_eviction_bounds_bindings():
    w = ArpWatch(max_bindings=3)
    for i in range(10):
        w.observe(f"10.0.0.{i}", MAC_A, now=float(i))
    assert len(w.bindings) <= 3
    assert "10.0.0.9" in w.bindings
    assert "10.0.0.0" not in w.bindings


def test_snapshot_sorted_numerically():
    w = ArpWatch()
    for octet in (10, 2, 100, 1):
        w.observe(f"10.0.0.{octet}", MAC_A, now=1.0)
    ips = [r["ip"] for r in w.snapshot()]
    assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.100"]


def test_invalid_and_late_claims_cannot_confirm_rebinding():
    w = ArpWatch()
    for ip in ("224.0.0.1", "010.0.0.1"):
        assert w.observe(ip, MAC_A, now=1) is None
    assert w.observe(GW, MAC_A, now=float("nan")) is None
    w.observe(GW, MAC_A, now=10)
    assert w.observe(GW, MAC_B, now=9) is None
    assert not w.pending_rebinds and w.bindings[GW]["mac"] == MAC_A
