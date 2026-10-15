"""Unit tests for the LAN quarantine engine.

A recording effector stands in for scapy, so these never resolve a real MAC or
put a frame on the wire. What matters: the protected set is inverted from the
firewall allowlist (an ordinary LAN device IS a valid target, the gateway and this
host are NOT), poison is re-asserted, release heals, and TTL expiry lifts.
"""

import json
from types import SimpleNamespace

import pytest

from netwatch_quarantine import (
    ALREADY_QUARANTINED,
    AT_CAPACITY,
    INVALID,
    PENDING_APPROVAL,
    PROTECTED,
    QUARANTINE,
    Quarantine,
    RecordingQuarantineEffector,
    is_protected,
)

GW = "10.0.0.1"
SELF = "10.0.0.15"
VICTIM = "10.0.0.34"
MACS = {GW: "02:00:00:00:03:01", VICTIM: "1c:53:f9:00:00:07"}


def engine(**kw):
    kw.setdefault("gateway_ip", GW)
    kw.setdefault("own_ip", SELF)
    eff = kw.pop("effector", None) or RecordingQuarantineEffector(mac_table=MACS)
    return Quarantine(eff, **kw), eff


def auto_engine(**kw):
    kw.setdefault("auto", True)
    return engine(**kw)


# --- protected set ---------------------------------------------------------


def test_ordinary_lan_device_is_a_valid_target():
    # the inverse of the firewall allowlist: a private LAN IP IS quarantinable
    assert not is_protected(VICTIM, gateway_ip=GW, own_ip=SELF, allowlist_ips=set())


def test_gateway_and_self_are_protected():
    assert is_protected(GW, gateway_ip=GW, own_ip=SELF, allowlist_ips=set())
    assert is_protected(SELF, gateway_ip=GW, own_ip=SELF, allowlist_ips=set())


def test_structural_addresses_are_protected():
    for ip in ("127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255"):
        assert is_protected(ip, gateway_ip=GW, own_ip=SELF, allowlist_ips=set()), ip


def test_explicit_allowlist_is_protected():
    assert is_protected("10.0.0.50", gateway_ip=GW, own_ip=SELF, allowlist_ips={"10.0.0.50"})


# --- decision --------------------------------------------------------------


def test_manual_mode_queues_for_approval():
    eng, eff = engine(auto=False)
    assert eng.request(VICTIM, "suspicious") == PENDING_APPROVAL
    assert VICTIM in eng.pending
    assert eff.poisoned == []  # nothing on the wire until approved


def test_auto_mode_quarantines_immediately():
    eng, eff = auto_engine()
    assert eng.request(VICTIM, "auto") == QUARANTINE
    assert VICTIM in eng.active
    assert eff.poisoned and eff.poisoned[0][0] == VICTIM


def test_explicit_policy_enforcement_overrides_interactive_mode_only():
    eng, eff = engine(auto=False)
    assert eng.enforce(VICTIM, "policy") is True
    assert VICTIM in eng.active
    assert eff.poisoned
    assert eng.enforce(GW, "must remain protected") is False


def test_gateway_target_is_protected_decision():
    eng, _ = auto_engine()
    assert eng.evaluate(GW, now=0) == PROTECTED
    assert eng.evaluate(SELF, now=0) == PROTECTED


def test_invalid_or_unknown_gateway():
    eng, _ = auto_engine()
    assert eng.evaluate("not-an-ip", now=0) == INVALID
    eng2, _ = auto_engine(gateway_ip="")
    assert eng2.evaluate(VICTIM, now=0) == INVALID  # no gateway to poison a route to


def test_dedup_and_capacity():
    eng, _ = auto_engine(max_active=1)
    assert eng.request(VICTIM, "x") == QUARANTINE
    assert eng.evaluate(VICTIM, now=0) == ALREADY_QUARANTINED
    assert eng.evaluate("10.0.0.99", now=0) == AT_CAPACITY


# --- approve / release / reassert / expiry ---------------------------------


def test_approve_applies_pending():
    eng, eff = engine(auto=False)
    eng.request(VICTIM, "x")
    assert eng.approve(VICTIM)
    assert VICTIM in eng.active
    assert VICTIM not in eng.pending
    assert eff.poisoned


def test_release_heals_and_removes():
    eng, eff = auto_engine()
    eng.request(VICTIM, "x")
    assert eng.release(VICTIM)
    assert VICTIM not in eng.active
    assert eff.healed and eff.healed[0][0] == VICTIM
    assert not eng.release(VICTIM)  # idempotent


def test_failed_heal_is_retried_by_reconcile():
    eng, eff = auto_engine()
    eng.request(VICTIM, "x")
    results = iter([False, True])
    eff.heal = lambda ip, gw: next(results)
    assert eng.release(VICTIM) and VICTIM in eng._unhealed
    eng.reconcile()
    assert VICTIM not in eng._unhealed
    eng.reconcile()  # healed once; nothing left to retry
    assert next(results, None) is None


def test_release_during_reassert_sends_no_poison_for_released_ip():
    eng, eff = auto_engine()
    eng.request(VICTIM, "x")
    eng.request("10.0.0.35", "y")
    eff.poisoned.clear()
    sent = []

    def quarantine(ip, gw, *, bidirectional=True):
        sent.append(ip)
        eng.release("10.0.0.35")  # released after the snapshot, before its send
        return True

    eff.quarantine = quarantine
    eng.reassert()
    assert sent == [VICTIM]


def test_reassert_reposts_active_poison():
    eng, eff = auto_engine()
    eng.request(VICTIM, "x")
    before = len(eff.poisoned)
    eng.reassert()
    assert len(eff.poisoned) > before


def test_apply_aborts_and_heals_if_local_gateway_resolves_to_sink():
    eng, eff = auto_engine()
    eff.gateway_poisoned = True
    assert eng.request(VICTIM, "x") == "QUARANTINE_FAILED"
    assert VICTIM not in eng.active
    assert eff.poisoned == []
    assert eff.healed == [(VICTIM, GW)]


def test_reassert_releases_everything_if_local_gateway_resolves_to_sink():
    eng, eff = auto_engine()
    assert eng.request(VICTIM, "x") == QUARANTINE
    eff.gateway_poisoned = True
    eng.reassert()
    assert eng.active == {}
    assert eff.healed == [(VICTIM, GW)]


def test_reconcile_lifts_expired_only():
    eng, eff = auto_engine(ttl_sec=10)
    eng.request(VICTIM, "x", now=1000)
    eng.request("10.0.0.35", "y", now=1000)
    released = eng.reconcile(now=1005)
    assert released == []                 # nothing expired yet
    released = eng.reconcile(now=1011)
    assert set(released) == {VICTIM, "10.0.0.35"}
    assert eng.active == {}


def test_reassert_skips_expired():
    eng, eff = auto_engine(ttl_sec=10)
    eng.request(VICTIM, "x", now=1000)
    eff.poisoned.clear()
    eng.reassert(now=1050)                # past TTL: reconciled out, not re-poisoned
    assert eff.poisoned == []
    assert VICTIM not in eng.active


def test_bidirectional_flag_flows_to_effector():
    eng, eff = auto_engine(bidirectional=False)
    eng.request(VICTIM, "x")
    assert eff.poisoned[-1][2] is False


def test_stop_interrupts_reassert_loop_without_another_emission():
    eng, eff = auto_engine(reassert_sec=5)
    eng.request(VICTIM, "x")
    eng.start()
    before = len(eff.poisoned)
    assert eng.stop(timeout=1)
    assert len(eff.poisoned) == before


# --- persistence -----------------------------------------------------------


def test_ledger_roundtrip(tmp_path):
    path = str(tmp_path / "q.json")
    eng, _ = auto_engine(ledger_path=path)
    eng.request(VICTIM, "persisted", now=1000)
    data = json.loads((tmp_path / "q.json").read_text())
    assert VICTIM in data["active"]

    eng2, _ = auto_engine(ledger_path=path)
    assert VICTIM in eng2.active           # restored on construction


def test_ledger_rejects_schema_drift(tmp_path):
    path = tmp_path / "q.json"
    path.write_text(json.dumps({"active": {VICTIM: {"garbage": 1}, "10.0.0.7": {
        "reason": "ok", "created_ts": 1, "expires_ts": 2}}}))
    eng, _ = auto_engine(ledger_path=str(path))
    assert VICTIM not in eng.active        # missing required keys dropped
    assert "10.0.0.7" in eng.active


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_a_dry_run_hold_is_not_reasserted_by_a_live_engine(tmp_path):
    path = str(tmp_path / "q.json")
    preview, _ = auto_engine(ledger_path=path)  # the recording effector is dry-run
    preview.request(VICTIM, "preview", now=1000)
    live_effector = RecordingQuarantineEffector(mac_table=MACS)
    live_effector.dry_run = False
    live, _ = auto_engine(ledger_path=path, effector=live_effector)
    assert VICTIM not in live.active


def test_release_mid_send_heals_after_the_late_poison():
    eng, eff = auto_engine()
    eng.request(VICTIM, "x")
    events = []
    eff.heal = lambda ip, gw: events.append(("heal", ip)) or True

    def quarantine(ip, gw, *, bidirectional=True):
        eng.release(ip)  # lands while this poison is in flight: its heal goes out first
        events.append(("poison", ip))
        return True

    eff.quarantine = quarantine
    eng.reassert()
    assert events[-1] == ("heal", VICTIM)


def test_cli_release_is_not_undone_by_a_running_engine(tmp_path):
    ledger = str(tmp_path / "q.json")
    desktop, eff = auto_engine(ledger_path=ledger)
    desktop.request(VICTIM, "x")
    cli, _ = auto_engine(ledger_path=ledger)
    assert cli.release(VICTIM)
    eff.poisoned.clear()
    desktop.reassert()
    desktop.request("10.0.0.35", "y")  # its save must not write the released device back
    assert VICTIM not in [ip for ip, *_ in eff.poisoned]
    with open(ledger, encoding="utf-8") as f:
        assert set(json.load(f)["active"]) == {"10.0.0.35"}


def test_cli_hold_keeps_reasserting_until_expiry(tmp_path, monkeypatch):
    import quarantine

    eff = RecordingQuarantineEffector(mac_table=MACS)
    eff.dry_run = False
    eng = Quarantine(eff, gateway_ip=GW, own_ip=SELF, auto=True, ttl_sec=1.2, reassert_sec=0.5,
                     ledger_path=str(tmp_path / "q.json"))
    monkeypatch.setattr(quarantine, "_engine", lambda args: eng)
    quarantine.main(["hold", VICTIM, "--apply"])
    assert len(eff.poisoned) >= 2  # one poison alone lasts only until the victim re-ARPs
    assert eff.healed and VICTIM not in eng.active


# --- real effector: frames (dry run, _send stubbed) and OS-output parsers ------------------

ARP_A_WINDOWS = """
Interface: 192.168.1.20 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.50          AA-BB-CC-DD-EE-50     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
ROUTE_PRINT_WINDOWS = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.20     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
"""


def _effector(monkeypatch, cache):
    pytest.importorskip("scapy")
    import netwatch_quarantine as nq

    monkeypatch.setattr(nq, "_parse_arp_cache", lambda: cache)
    eff = nq.ArpQuarantineEffector("lo", sink_mac="02:00:00:00:de:ad", dry_run=True)
    sent = []
    monkeypatch.setattr(eff, "_send", lambda frames, label: sent.append(frames) or True)
    return eff, sent


def test_arp_effector_poison_frames_point_the_gateway_at_the_sink(monkeypatch):
    eff, sent = _effector(monkeypatch, {"10.0.0.5": "aa:bb:cc:00:00:05", "10.0.0.1": "aa:bb:cc:00:00:01"})
    assert eff.quarantine("10.0.0.5", "10.0.0.1")
    to_victim, to_gateway = sent[0]
    assert (to_victim.dst, to_victim.op, to_victim.psrc, to_victim.hwsrc, to_victim.pdst, to_victim.hwdst) == (
        "aa:bb:cc:00:00:05", 2, "10.0.0.1", "02:00:00:00:de:ad", "10.0.0.5", "aa:bb:cc:00:00:05")
    assert (to_gateway.dst, to_gateway.psrc, to_gateway.hwsrc, to_gateway.pdst) == (
        "aa:bb:cc:00:00:01", "10.0.0.5", "02:00:00:00:de:ad", "10.0.0.1")
    sent.clear()
    assert eff.quarantine("10.0.0.5", "10.0.0.1", bidirectional=False) and len(sent[0]) == 1


def test_arp_effector_heal_restores_true_bindings_and_unresolved_victim_aborts(monkeypatch):
    eff, sent = _effector(monkeypatch, {"10.0.0.5": "aa:bb:cc:00:00:05", "10.0.0.1": "aa:bb:cc:00:00:01"})
    assert eff.heal("10.0.0.5", "10.0.0.1")
    to_victim, to_gateway = sent[0]
    assert (to_victim.psrc, to_victim.hwsrc) == ("10.0.0.1", "aa:bb:cc:00:00:01")
    assert (to_gateway.psrc, to_gateway.hwsrc) == ("10.0.0.5", "aa:bb:cc:00:00:05")


def test_arp_effector_aborts_without_a_victim_mac(monkeypatch):
    import scapy.sendrecv

    eff, sent = _effector(monkeypatch, {"10.0.0.1": "aa:bb:cc:00:00:01"})
    monkeypatch.setattr(scapy.sendrecv, "srp", lambda *_a, **_k: ([], []))  # no live ARP request
    assert not eff.quarantine("10.0.0.99", "10.0.0.1") and sent == []


def test_gateway_poisoned_failsafe_reads_the_real_arp_cache(monkeypatch):
    eff, _ = _effector(monkeypatch, {"10.0.0.1": "02:00:00:00:de:ad"})
    assert eff.is_gateway_poisoned("10.0.0.1") and not eff.is_gateway_poisoned("10.0.0.2")


def test_parse_arp_cache_reads_windows_arp_a(monkeypatch):
    import netwatch_quarantine as nq

    monkeypatch.setattr(nq.subprocess, "run", lambda *_a, **_k: SimpleNamespace(stdout=ARP_A_WINDOWS))
    assert nq._parse_arp_cache() == {"192.168.1.1": "aa:bb:cc:dd:ee:01", "192.168.1.50": "aa:bb:cc:dd:ee:50",
                                     "192.168.1.255": "ff:ff:ff:ff:ff:ff"}

    def missing(*_a, **_k):
        raise FileNotFoundError("arp")

    monkeypatch.setattr(nq.subprocess, "run", missing)
    assert nq._parse_arp_cache() == {}


def test_detect_default_gateway_parses_windows_route_print(monkeypatch):
    import netwatch_config as nc

    monkeypatch.setattr(nc.os, "name", "nt")
    monkeypatch.setattr(nc.subprocess, "run", lambda *_a, **_k: SimpleNamespace(stdout=ROUTE_PRINT_WINDOWS))
    assert nc.detect_default_gateway() == "192.168.1.1"
    monkeypatch.setattr(nc.subprocess, "run", lambda *_a, **_k: SimpleNamespace(stdout="no routes"))
    assert nc.detect_default_gateway() == ""


def test_detect_default_gateway_reads_proc_net_route_lowest_metric(monkeypatch, tmp_path):
    import netwatch_config as nc

    table = tmp_path / "route"
    table.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"   # 192.168.1.1, metric 600
        "wlan0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"  # 10.0.0.1, metric 100
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n")
    monkeypatch.setattr(nc.os, "name", "posix")
    monkeypatch.setattr(nc, "PROC_NET_ROUTE", str(table))
    assert nc.detect_default_gateway() == "10.0.0.1"
    monkeypatch.setattr(nc, "PROC_NET_ROUTE", str(tmp_path / "missing"))
    assert nc.detect_default_gateway() == ""


def test_failed_route_and_arp_commands_are_not_parsed(monkeypatch):
    import subprocess

    import netwatch_config as nc
    import netwatch_quarantine as nq

    def failing(stdout):
        def run(args, **kwargs):  # exits non-zero yet printed something: only check=True notices
            if kwargs.get("check"):
                raise subprocess.CalledProcessError(1, args, output=stdout)
            return SimpleNamespace(stdout=stdout, returncode=1)
        return run

    monkeypatch.setattr(nc.os, "name", "nt")
    monkeypatch.setattr(nc.subprocess, "run", failing(ROUTE_PRINT_WINDOWS))
    assert nc.detect_default_gateway() == ""
    monkeypatch.setattr(nq.subprocess, "run", failing(ARP_A_WINDOWS))
    assert nq._parse_arp_cache() == {}


def test_pending_queue_is_capped():
    from netwatch_quarantine import AT_CAPACITY, PENDING_APPROVAL

    q, _ = engine(max_active=2)
    assert [q.request(ip, "r") for ip in ("10.0.0.40", "10.0.0.41")] == [PENDING_APPROVAL] * 2
    assert q.request("10.0.0.42", "r") == AT_CAPACITY
    assert q.request("10.0.0.40", "again") == PENDING_APPROVAL  # an entry already waiting is refreshed, not refused
    assert set(q.pending) == {"10.0.0.40", "10.0.0.41"}
