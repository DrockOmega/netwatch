"""Locality must agree across capture, external IDS events, and response."""

import ipaddress

import pytest

from netwatch_config import build_config
from netwatch_core import compile_v4_prefixes, compile_v6_prefixes, ip_pack, is_local_ip
from netwatch_mitigation import Mitigator
from netwatch_suricata import normalize_eve_event


@pytest.mark.parametrize("local,remote", [
    ("10.0.0.87", "8.8.8.8"),
    ("172.31.255.254", "172.32.0.1"),
    ("192.168.2.1", "1.1.1.1"),
    ("169.254.1.2", "8.8.8.8"),
    ("fe80::123", "2606:4700:4700::1111"),
    ("2601:281:da82:ba80::123", "2601:281:da82:ba81::123"),
])
def test_default_locality_agrees_across_sources(tmp_path, local, remote):
    cfg, _ = build_config(tmp_path, extra={
        "LOCAL_PREFIXES6_AUTO": False,
        "LOCAL_PREFIXES6": ["2601:281:da82:ba80::/64"], "GATEWAY_IP": "10.0.0.1",
    })
    v4 = compile_v4_prefixes(cfg["LOCAL_PREFIXES"])
    v6 = compile_v6_prefixes(cfg["LOCAL_PREFIXES6"])
    assert is_local_ip(ip_pack(local), v4, v6)
    assert not is_local_ip(ip_pack(remote), v4, v6)
    for src, dst, direction in [(local, remote, "egress"), (remote, local, "ingress"),
                                (local, local, "lateral")]:
        event = normalize_eve_event({"event_type": "alert", "src_ip": src, "dest_ip": dst},
                                    (*cfg["LOCAL_PREFIXES"], *cfg["LOCAL_PREFIXES6"]))
        assert event["data"]["direction"] == direction
        assert event["data"]["containment_eligible"] is True


def test_config_canonicalizes_legacy_prefixes_and_cidr_host_bits(tmp_path):
    cfg, _ = build_config(tmp_path, extra={
        "LOCAL_PREFIXES": ["10.", "192.168.", "10.0.0.7/8", "8.8.8.99/24"],
        "LOCAL_PREFIXES6": ["2601:281:da82:ba80::123/64"],
        "LOCAL_PREFIXES6_AUTO": False, "GATEWAY_IP": "10.0.0.1",
    })
    assert cfg["LOCAL_PREFIXES"] == ("10.0.0.0/8", "192.168.0.0/16", "8.8.8.0/24")
    assert cfg["LOCAL_PREFIXES6"] == ("2601:281:da82:ba80::/64",)
    mit = Mitigator(allowlist_prefixes=cfg["LOCAL_PREFIXES"])
    assert mit.evaluate("8.8.8.8", "protect configured LAN") == "ALLOWLISTED"
    assert is_local_ip(ip_pack("8.8.8.8"), compile_v4_prefixes(cfg["LOCAL_PREFIXES"]))


@pytest.mark.parametrize("key,value", [("LOCAL_PREFIXES", "999."),
                                      ("LOCAL_PREFIXES", "fe80::/10"),
                                      ("LOCAL_PREFIXES6", "10.0.0.0/8")])
def test_invalid_locality_cannot_silently_start(tmp_path, key, value):
    with pytest.raises(ValueError, match=key):
        build_config(tmp_path, extra={key: [value], "LOCAL_PREFIXES6_AUTO": False})


def test_eve_standalone_accepts_legacy_prefixes():
    event = normalize_eve_event({"event_type": "alert", "src_ip": "10.0.0.87", "dest_ip": "8.8.8.8"},
                                ["10."])
    assert event["target_id"] == ipaddress.ip_address("8.8.8.8").packed
    assert event["data"]["direction"] == "egress"
