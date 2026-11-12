"""Unit tests for the mitigation engine. A recording fake stands in for netsh,
so these never touch the real firewall."""

import json

import pytest

from netwatch_mitigation import (
    ALLOWLISTED,
    ALREADY_BLOCKED,
    ALREADY_PENDING,
    AT_CAPACITY,
    BLOCK,
    INVALID,
    PENDING_APPROVAL,
    Mitigator,
    WindowsFirewall,
    is_allowlisted,
    rule_name_for,
)


class FakeFirewall:
    """Records block/unblock calls instead of shelling out to netsh."""

    def __init__(self):
        self.blocked = []    # (ip, rule_name)
        self.unblocked = []  # rule_name

    def block(self, ip, rule_name):
        self.blocked.append((ip, rule_name))

    def unblock(self, rule_name):
        self.unblocked.append(rule_name)


def auto_mit(**kw):
    return Mitigator(effector=FakeFirewall(), auto=True, **kw)


# --- allowlist / validation ------------------------------------------------


def test_is_allowlisted_prefix_and_explicit():
    assert is_allowlisted("192.168.1.5", ("192.168.",), set())
    assert is_allowlisted("8.8.8.8", ("192.168.",), {"8.8.8.8"})
    assert not is_allowlisted("8.8.8.8", ("192.168.",), set())


def test_evaluate_rejects_invalid_ip():
    m = auto_mit()
    assert m.evaluate("not.an.ip", now=0) == INVALID
    assert m.evaluate("999.1.1.1", now=0) == INVALID


def test_evaluate_protects_local_ranges():
    m = auto_mit()
    for ip in ("192.168.0.1", "10.0.0.5", "127.0.0.1", "224.0.0.1", "172.16.0.1"):
        assert m.evaluate(ip, now=0) == ALLOWLISTED


def test_is_allowlisted_structural_v4_and_v6():
    # No explicit prefix/IP — the structural (private/loopback/...) check carries it.
    assert is_allowlisted("10.0.0.1", (), set())          # private v4
    assert is_allowlisted("::1", (), set())               # v6 loopback
    assert is_allowlisted("fe80::1", (), set())           # v6 link-local
    assert is_allowlisted("fc00::1", (), set())           # v6 ULA
    assert is_allowlisted("ff02::1", (), set())           # v6 multicast
    assert not is_allowlisted("2606:4700:4700::1111", (), set())  # public v6


def test_evaluate_v6_public_is_blockable_and_local_protected():
    m = auto_mit()
    assert m.evaluate("2606:4700:4700::1111", now=0) == BLOCK
    assert m.evaluate("fe80::1", now=0) == ALLOWLISTED
    assert m.evaluate("::1", now=0) == ALLOWLISTED


def test_evaluate_rejects_invalid_v6():
    m = auto_mit()
    assert m.evaluate("2001:db8::xyz", now=0) == INVALID
    assert m.evaluate("gg::1", now=0) == INVALID


def test_auto_block_v6_applies_rule():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True)
    ipv6 = "2606:4700:4700::1111"
    assert m.request(ipv6, "THREAT INTEL", now=100) == BLOCK
    assert ipv6 in m.active
    assert fw.blocked == [(ipv6, rule_name_for(ipv6))]


# --- auto mode -------------------------------------------------------------


def test_auto_block_applies_firewall_rule():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True)
    assert m.request("8.8.8.8", "EXFIL", now=100) == BLOCK
    assert "8.8.8.8" in m.active
    assert fw.blocked == [("8.8.8.8", rule_name_for("8.8.8.8"))]


def test_duplicate_request_is_idempotent():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True)
    m.request("8.8.8.8", "EXFIL", now=100)
    assert m.request("8.8.8.8", "EXFIL", now=101) == ALREADY_BLOCKED
    assert len(fw.blocked) == 1  # no second rule created


def test_capacity_cap_refuses_new_blocks():
    m = auto_mit(max_active=1)
    assert m.request("8.8.8.8", "r", now=0) == BLOCK
    assert m.request("9.9.9.9", "r", now=0) == AT_CAPACITY
    assert "9.9.9.9" not in m.active


# --- manual approval -------------------------------------------------------


def test_manual_mode_queues_for_approval():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False)
    assert m.request("8.8.8.8", "PORT SCAN", now=0) == PENDING_APPROVAL
    assert "8.8.8.8" in m.pending
    assert fw.blocked == []  # nothing blocked without approval


def test_repeated_manual_request_preserves_original_pending_action():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False)
    assert m.request("8.8.8.8", "first", now=1) == PENDING_APPROVAL
    assert m.request("8.8.8.8", "repeat", now=2) == ALREADY_PENDING
    assert m.pending["8.8.8.8"] == {"reason": "first", "requested_ts": 1}
    assert fw.blocked == []


def test_autonomous_request_promotes_existing_pending_action():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False)
    m.request("8.8.8.8", "manual", now=1)
    assert m.request("8.8.8.8", "autonomous", now=2, auto=True) == BLOCK
    assert "8.8.8.8" not in m.pending
    assert "8.8.8.8" in m.active


def test_approve_applies_block():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False)
    m.request("8.8.8.8", "PORT SCAN", now=0)
    assert m.approve("8.8.8.8", now=1) is True
    assert "8.8.8.8" in m.active
    assert "8.8.8.8" not in m.pending
    assert len(fw.blocked) == 1


def test_capacity_rejection_preserves_pending_action_for_retry():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False, max_active=1)
    m.request("8.8.8.8", "pending", now=1)
    assert m.enforce("9.9.9.9", "active", now=2) is True
    assert m.approve("8.8.8.8", now=3) is False
    assert "8.8.8.8" in m.pending
    assert m.unblock("9.9.9.9") is True
    assert m.approve("8.8.8.8", now=4) is True


def test_explicit_policy_enforcement_preserves_manual_engine_guardrails():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False)
    assert m.enforce("8.8.8.8", "ordered policy", now=1) is True
    assert "8.8.8.8" in m.active
    assert fw.blocked == [("8.8.8.8", rule_name_for("8.8.8.8"))]
    assert m.enforce("192.168.1.5", "bad target", now=2) is False


def test_explicit_manual_policy_override_queues_even_when_global_auto_is_on():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True)
    assert m.request("8.8.8.8", "manual policy", now=1, auto=False) == PENDING_APPROVAL
    assert "8.8.8.8" in m.pending
    assert fw.blocked == []


def test_deny_drops_without_blocking():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False)
    m.request("8.8.8.8", "PORT SCAN", now=0)
    assert m.deny("8.8.8.8") is True
    assert not m.pending
    assert fw.blocked == []


def test_approve_unknown_ip_is_noop():
    m = Mitigator(effector=FakeFirewall(), auto=False)
    assert m.approve("8.8.8.8", now=0) is False


def test_approve_refuses_if_now_allowlisted():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=False, allowlist_ips=set())
    m.request("8.8.8.8", "r", now=0)
    m.allowlist_ips.add("8.8.8.8")  # operator allowlists it before approving
    assert m.approve("8.8.8.8", now=1) is False
    assert fw.blocked == []


# --- TTL / expiry ----------------------------------------------------------


def test_reconcile_lifts_expired_blocks():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True, block_ttl_sec=60)
    m.request("8.8.8.8", "r", now=1000)
    assert m.reconcile(now=1050) == []        # not yet expired
    assert m.reconcile(now=1061) == ["8.8.8.8"]  # past TTL
    assert "8.8.8.8" not in m.active
    assert fw.unblocked == [rule_name_for("8.8.8.8")]


def test_manual_unblock():
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True)
    m.request("8.8.8.8", "r", now=0)
    assert m.unblock("8.8.8.8") is True
    assert "8.8.8.8" not in m.active
    assert fw.unblocked == [rule_name_for("8.8.8.8")]
    assert m.unblock("8.8.8.8") is False  # already gone


# --- persistence -----------------------------------------------------------


def test_ledger_persists_and_reloads(tmp_path):
    ledger = tmp_path / "blocks.json"
    fw = FakeFirewall()
    m = Mitigator(effector=fw, auto=True, ledger_path=str(ledger))
    m.request("8.8.8.8", "EXFIL", now=1000)
    # a fresh instance pointed at the same ledger sees the active block.
    m2 = Mitigator(effector=FakeFirewall(), auto=True, ledger_path=str(ledger))
    assert "8.8.8.8" in m2.active
    assert m2.evaluate("8.8.8.8", now=1001) == ALREADY_BLOCKED


def test_ledger_expiry_honored_after_reload(tmp_path):
    ledger = tmp_path / "blocks.json"
    m = Mitigator(effector=FakeFirewall(), auto=True, block_ttl_sec=60, ledger_path=str(ledger))
    m.request("8.8.8.8", "r", now=1000)
    fw2 = FakeFirewall()
    m2 = Mitigator(effector=fw2, auto=True, ledger_path=str(ledger))
    # on the next boot, reconcile cleans up the stale block.
    assert m2.reconcile(now=2000) == ["8.8.8.8"]
    assert fw2.unblocked == [rule_name_for("8.8.8.8")]


def test_corrupt_ledger_degrades_gracefully(tmp_path):
    ledger = tmp_path / "blocks.json"
    ledger.write_text("{ not valid json")
    m = Mitigator(effector=FakeFirewall(), auto=True, ledger_path=str(ledger))
    assert m.active == {}


def test_dry_run_effector_records_commands_without_running():
    # default effector is dry-run; assert it builds netsh commands but the
    # subprocess is never invoked (no exception, commands captured).
    m = Mitigator(auto=True)
    m.request("8.8.8.8", "r", now=0)
    cmds = m.effector.commands
    assert any("add" in c and "dir=in" in " ".join(c) for c in cmds)
    assert any("dir=out" in " ".join(c) for c in cmds)
    assert m.effector.dry_run is True


def test_persisted_ledger_is_valid_json(tmp_path):
    ledger = tmp_path / "blocks.json"
    m = Mitigator(effector=FakeFirewall(), auto=True, ledger_path=str(ledger))
    m.request("8.8.8.8", "r", now=0)
    data = json.loads(ledger.read_text())
    assert "8.8.8.8" in data["active"]


class FailingFirewall:
    def __init__(self, fail_all=False):
        self.fail_all = fail_all

    def block(self, ip, rule_name):
        if self.fail_all:
            from netwatch_mitigation import FirewallError
            raise FirewallError("block failed")

    def unblock(self, rule_name):
        from netwatch_mitigation import FirewallError
        raise FirewallError("unblock failed")


class FailingWindowsFirewall(WindowsFirewall):
    def __init__(self, fail_on_second=False):
        super().__init__(dry_run=False)
        self.fail_on_second = fail_on_second
        self.run_count = 0

    def _run(self, args):
        self.commands.append(args)
        self.run_count += 1
        if self.fail_on_second and self.run_count == 2:
            from netwatch_mitigation import FirewallError
            raise FirewallError("mock outbound block failed")


def test_effector_failures():
    from netwatch_mitigation import FirewallError
    # Test 1: request returns MITIGATION_FAILED if block fails
    fw_fail = FailingFirewall(fail_all=True)
    m1 = Mitigator(effector=fw_fail, auto=True)
    assert m1.request("8.8.8.8", "test", now=0) == "MITIGATION_FAILED"
    assert "8.8.8.8" not in m1.active

    # Test 2: block rollback on partial failure in WindowsFirewall
    fw_partial = FailingWindowsFirewall(fail_on_second=True)
    with pytest.raises(FirewallError):
        fw_partial.block("8.8.8.8", "NetWatch Block 8.8.8.8")
    # Verify it ran the first block, then second block, then unblocked
    cmds = fw_partial.commands
    assert len(cmds) == 3
    assert "add" in cmds[0] and "dir=in" in " ".join(cmds[0])
    assert "add" in cmds[1] and "dir=out" in " ".join(cmds[1])
    assert "delete" in cmds[2]

    # Test 3: unblock preserves active entry if effector raises FirewallError
    fw_unblock_fail = FailingFirewall(fail_all=True)
    m3 = Mitigator(effector=fw_unblock_fail, auto=True)
    # inject active block directly to bypass failing block()
    m3.active["8.8.8.8"] = {"rule_name": "NetWatch Block 8.8.8.8", "reason": "test", "created_ts": 0, "expires_ts": 100}
    with pytest.raises(FirewallError):
        m3.unblock("8.8.8.8")
    assert "8.8.8.8" in m3.active

    # Test 4: reconcile continues on failure and doesn't pop failed entry
    m4 = Mitigator(effector=fw_unblock_fail, auto=True)
    m4.active["8.8.8.8"] = {"rule_name": "NetWatch Block 8.8.8.8", "reason": "test", "created_ts": 0, "expires_ts": 10}
    m4.active["9.9.9.9"] = {"rule_name": "NetWatch Block 9.9.9.9", "reason": "test", "created_ts": 0, "expires_ts": 10}
    assert m4.reconcile(now=20) == []
    assert "8.8.8.8" in m4.active
    assert "9.9.9.9" in m4.active


# --- IPv6 LAN protection ---------------------------------------------------
# A home ISP delegates a globally-routable prefix, so ipaddress.is_private is
# False for your own devices. Without the LAN prefix in allowlist_networks, a
# threat-intel or detector hit on a LAN v6 host is block-eligible and NetWatch
# firewalls its own network.

LAN_V6 = "2600:1700:abcd:1200::/64"


def test_global_v6_is_blockable_without_network_allowlist():
    m = auto_mit()
    assert m.evaluate("2600:1700:abcd:1200::42", now=0) == BLOCK


def test_delegated_v6_lan_is_allowlisted():
    m = auto_mit(allowlist_networks=[LAN_V6])
    assert m.evaluate("2600:1700:abcd:1200::42", now=0) == ALLOWLISTED
    assert m.request("2600:1700:abcd:1200::42", "threat intel") == ALLOWLISTED
    assert m.effector.blocked == []


def test_network_allowlist_does_not_overblock_remote_v6():
    m = auto_mit(allowlist_networks=[LAN_V6])
    assert m.evaluate("2606:4700:4700::1111", now=0) == BLOCK


def test_network_allowlist_is_family_safe():
    # a v6 network must never swallow a v4 address (or vice versa)
    m = auto_mit(allowlist_networks=[LAN_V6, "203.0.113.0/24"])
    assert m.evaluate("8.8.8.8", now=0) == BLOCK
    assert m.evaluate("203.0.113.9", now=0) == ALLOWLISTED
    assert is_allowlisted("2600:1700:abcd:1200::1", (), set(), m.allowlist_networks)


def test_network_allowlist_ignores_unparseable_entries():
    m = auto_mit(allowlist_networks=[LAN_V6, "garbage", None, ""])
    assert len(m.allowlist_networks) == 1
    assert m.evaluate("2600:1700:abcd:1200::7", now=0) == ALLOWLISTED


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_a_dry_run_block_never_binds_a_live_engine(tmp_path):
    ledger = str(tmp_path / "blocks.json")
    preview = Mitigator(auto=True, ledger_path=ledger)  # default effector is dry-run
    assert preview.request("8.8.8.8", "preview", now=0) == BLOCK
    assert "8.8.8.8" in Mitigator(auto=True, ledger_path=ledger).active  # another preview still sees it
    live = Mitigator(effector=FakeFirewall(), auto=True, ledger_path=ledger)
    assert live.active == {} and live.request("8.8.8.8", "real", now=1) == BLOCK
    assert live.effector.blocked == [("8.8.8.8", rule_name_for("8.8.8.8"))]


def test_explicit_allowlist_ips_are_never_blocked():
    m = Mitigator(effector=FakeFirewall(), auto=True, allowlist_ips={"8.8.8.8"})
    assert m.request("8.8.8.8", "r", now=0) == ALLOWLISTED and m.effector.blocked == []


def test_ledger_write_survives_a_target_held_open_on_windows(tmp_path, monkeypatch):
    import os

    import netwatch_core

    real_replace, calls = os.replace, []

    def held_once(src, dst):
        calls.append(dst)
        if len(calls) == 1:
            raise PermissionError(13, "The process cannot access the file")
        real_replace(src, dst)

    monkeypatch.setattr(netwatch_core.os, "replace", held_once)
    ledger = tmp_path / "telemetry_blocks.json"
    assert netwatch_core.write_json_atomic(str(ledger), {"active": {"1.2.3.4": {}}})
    assert json.loads(ledger.read_text()) == {"active": {"1.2.3.4": {}}}


def test_expiry_drops_a_block_whose_rule_is_already_gone(monkeypatch):
    import subprocess

    def netsh(args, **kwargs):
        if "delete" in args:  # netsh exits 1 when no rule has the name
            raise subprocess.CalledProcessError(1, args, output="\nNo rules match the specified criteria.\n")

    monkeypatch.setattr(subprocess, "run", netsh)
    m = Mitigator(effector=WindowsFirewall(dry_run=False), auto=True, block_ttl_sec=10)
    assert m.request("8.8.8.8", "x", now=0) == BLOCK
    assert m.reconcile(now=100) == ["8.8.8.8"] and not m.active


def test_non_canonical_allowlist_entry_and_zoned_target_still_match():
    assert is_allowlisted("2606:4700:4700::1111", (), {"2606:4700:4700:0:0:0:0:1111"})
    assert is_allowlisted("2606:4700:4700::1111%1", (), {"2606:4700:4700::1111"})


def test_cli_unblock_is_not_written_back_by_a_running_engine(tmp_path):
    ledger = str(tmp_path / "blocks.json")
    desktop = Mitigator(effector=FakeFirewall(), auto=True, ledger_path=ledger)
    desktop.request("8.8.8.8", "x", now=0)
    cli = Mitigator(effector=FakeFirewall(), auto=True, ledger_path=ledger)
    assert cli.unblock("8.8.8.8")
    desktop.request("9.9.9.9", "y", now=1)  # its save must not write the lifted block back
    with open(ledger) as f:
        assert set(json.load(f)["active"]) == {"9.9.9.9"}
    assert "8.8.8.8" not in desktop.active


# --- F4: failed unblocks are logged, not swallowed --------------------------------------


def _ui_warnings():
    import logging

    messages = []
    handler = logging.Handler(logging.WARNING)
    handler.emit = lambda record: messages.append(record.getMessage())  # the real loggers do not propagate
    logger = logging.getLogger("netwatch.ui")
    logger.addHandler(handler)
    return messages, lambda: logger.removeHandler(handler)


def test_failed_rollback_unblock_is_logged():
    from netwatch_mitigation import FirewallError

    class Fw(WindowsFirewall):
        def _run(self, args):
            if "dir=out" in args or "delete" in args:
                raise FirewallError("netsh failed")

    messages, stop = _ui_warnings()
    try:
        with pytest.raises(FirewallError):
            Fw(dry_run=False).block("203.0.113.5", "r")
    finally:
        stop()
    assert len(messages) == 1 and "rollback" in messages[0]


def test_failing_reconcile_logs_once_per_ip_and_keeps_the_entry():
    from netwatch_mitigation import FirewallError

    class Stuck(FakeFirewall):
        fail = True

        def unblock(self, rule_name):
            if self.fail:
                raise FirewallError("netsh failed")
            super().unblock(rule_name)

    fw = Stuck()
    mit = Mitigator(effector=fw, auto=True)
    mit.request("93.184.216.34", "t", now=1000)
    messages, stop = _ui_warnings()
    try:
        for _ in range(3):
            assert mit.reconcile(now=10**9) == []
        assert "93.184.216.34" in mit.active and len(messages) == 1
        fw.fail = False
        assert mit.reconcile(now=10**9) == ["93.184.216.34"]
    finally:
        stop()


def test_command_trail_bounded():
    from netwatch_mitigation import WindowsFirewall

    fw = WindowsFirewall()
    for index in range(1000):
        fw.block(f"93.184.{index // 250}.{index % 250}", f"rule-{index}")
    assert len(fw.commands) <= 256 and "name=rule-999" in " ".join(fw.commands[-1])


def test_pending_queue_is_capped():
    from netwatch_mitigation import AT_CAPACITY, BLOCK, PENDING_APPROVAL, Mitigator

    m = Mitigator(auto=False, max_active=2)
    assert [m.request(ip, "r") for ip in ("93.184.216.1", "93.184.216.2")] == [PENDING_APPROVAL] * 2
    assert m.request("93.184.216.3", "r") == AT_CAPACITY
    assert set(m.pending) == {"93.184.216.1", "93.184.216.2"}  # nothing already waiting is dropped
    assert m.request("93.184.216.4", "r", auto=True) == BLOCK
