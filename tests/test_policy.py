import ipaddress
import json

import pytest

from netwatch_policy import DecisionLedger, PolicyConfigError, PolicyEngine


def context(**overrides):
    base = {
        "flow_id": "flow-1", "direction": "egress", "protocol": "TCP",
        "src_ip": ipaddress.ip_address("10.0.0.2").packed,
        "dst_ip": ipaddress.ip_address("8.8.8.8").packed,
        "destination_port": 23, "source_mac": "00:11:22:33:44:55",
        "domain": "host.vendor.example",
    }
    return {**base, **overrides}


def test_ordered_policy_first_match_and_monitor_staging():
    engine = PolicyEngine({
        "version": 3, "default_action": "allow",
        "rules": [
            {"id": "exception", "action": "allow", "destination_cidrs": ["8.8.8.8/32"]},
            {"id": "deny-telnet", "action": "block", "destination_ports": [23]},
        ],
    }, mode="monitor")
    assert engine.evaluate(context())["rule_id"] == "exception"
    decision = PolicyEngine({
        "rules": [{"id": "deny-telnet", "action": "block", "destination_ports": [23]}],
    }, mode="monitor").evaluate(context())
    assert decision["configured_action"] == "block"
    assert decision["effective_action"] == "alert"


def test_device_domain_and_expiring_exception_selectors():
    engine = PolicyEngine({"rules": [{
        "id": "device-alert", "action": "alert", "direction": "egress",
        "source_macs": ["00:11:22:33:44:55"],
        "domain_suffixes": ["vendor.example"], "expires_at": 100,
    }], "default_action": "block"}, mode="enforce")
    assert engine.evaluate(context(), now=99)["rule_id"] == "device-alert"
    assert engine.evaluate(context(), now=101)["rule_id"] == "default"


def test_invalid_policy_is_rejected():
    with pytest.raises(PolicyConfigError):
        PolicyEngine({"rules": [{"action": "destroy"}]})
    with pytest.raises(PolicyConfigError):
        PolicyEngine({"rules": [{"action": "block", "destination_cidrs": ["not-cidr"]}]})
    with pytest.raises(PolicyConfigError):
        PolicyEngine({"rules": [{"id": "same"}, {"id": "same"}]})
    with pytest.raises(PolicyConfigError, match="cannot authorize allow"):
        PolicyEngine({"rules": [{"action": "allow", "source_macs": ["00:11:22:33:44:55"]}]})


def test_policy_load_digest_and_decision_ledger(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 2, "rules": []}), encoding="utf-8")
    engine = PolicyEngine.load(str(policy), mode="manual")
    assert engine.version == 2 and len(engine.digest) == 64
    ledger_path = tmp_path / "decisions.jsonl"
    ledger = DecisionLedger(str(ledger_path))
    assert ledger.append(engine.evaluate(context())) is True
    assert ledger.flush() is True
    row = json.loads(ledger_path.read_text())
    assert row["src_ip"] == "10.0.0.2"


def test_source_macs_in_any_notation_match_and_bad_ones_are_refused():
    engine = PolicyEngine({"rules": [{"id": "device", "action": "alert", "source_macs": ["00-11-22-33-44-55"]}],
                           "default_action": "block"}, mode="enforce")
    assert engine.evaluate(context())["rule_id"] == "device"
    with pytest.raises(PolicyConfigError, match="source_macs"):
        PolicyEngine({"rules": [{"action": "block", "source_macs": ["not-a-mac"]}]})
