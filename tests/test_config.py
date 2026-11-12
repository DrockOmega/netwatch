"""Unit tests for the config layering.

The overlay chain is what lets two hosts share one checkout, so its failure modes
matter: a malformed overlay must not take startup down, an unknown key must not
silently pretend to configure something, and relative paths must land next to the
app rather than in the process's working directory.
"""

import json
import os

from netwatch_config import DEFAULTS, PATH_KEYS, build_config, load_overlay


def _write(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)


def test_defaults_only(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    assert cfg["MAX_ENTITIES"] == DEFAULTS["MAX_ENTITIES"]
    assert cfg["RESPONSE_MODE"] == "ids_only"
    assert cfg["POLICY_MODE"] == "manual"
    assert cfg["MITIGATION_ENABLED"] is True
    assert cfg["MITIGATION_DRY_RUN"] is False
    assert cfg["QUARANTINE_ENABLED"] is True
    assert cfg["QUARANTINE_DRY_RUN"] is False
    assert cfg["BPF_FILTER"] is None
    assert cfg["CAPTURE_PROFILE"] == "full"
    assert cfg["SENSOR_ID"] == "nohost"
    assert cfg["DB_WAL_MAX_BYTES"] == 67_108_864
    assert cfg["SECURE_NODES"] == {}
    assert cfg["UI_LOG_BLOCKS"] == 10_000
    assert cfg["UI_ACTIVITY_RELOAD_SEC"] == 5
    assert cfg["UI_TRAFFIC_LOOKBACK_SEC"] == 86_400
    assert cfg["UI_OBSERVATION_LOG_BLOCKS"] == 10_000
    assert cfg["WEB_OBSERVATION_BUFFER_MAX"] == 10_000
    assert cfg["CAPTURE_TOPOLOGY"] == "endpoint"
    assert cfg["CAPTURE_COVERAGE_ASSERTION"] == "unverified"


def test_relative_paths_resolve_against_base_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    for key in PATH_KEYS:
        value = cfg.get(key)
        if isinstance(value, str) and value:
            assert os.path.isabs(value), key
            assert value.startswith(str(tmp_path)), key


def test_missing_read_only_default_uses_frozen_resource_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    install = tmp_path / "install"
    bundle = tmp_path / "bundle"
    install.mkdir()
    bundle.mkdir()
    (bundle / "policy_rules.json").write_text('{"version":1,"rules":[]}', encoding="utf-8")
    cfg, _ = build_config(str(install), hostname="nohost", resource_dir=str(bundle))
    assert cfg["POLICY_FILE"] == str(bundle / "policy_rules.json")


def test_absolute_path_in_overlay_is_honoured(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    elsewhere = str(tmp_path / "elsewhere" / "ledger.db")
    _write(tmp_path / "netwatch.config.json", {"DB_NAME": elsewhere})
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    assert cfg["DB_NAME"] == elsewhere


def test_host_overlay_wins_over_shared_overlay(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    _write(tmp_path / "netwatch.config.json", {"NIC_INTERFACE": "shared", "MAX_ENTITIES": 64})
    _write(tmp_path / "netwatch.sensor1.json", {"NIC_INTERFACE": "sensor1-nic"})
    cfg, _ = build_config(str(tmp_path), hostname="sensor1")
    assert cfg["NIC_INTERFACE"] == "sensor1-nic"
    assert cfg["MAX_ENTITIES"] == 64  # untouched keys still come from the shared layer


def test_env_overlay_has_final_say(tmp_path, monkeypatch):
    _write(tmp_path / "netwatch.config.json", {"NIC_INTERFACE": "shared"})
    env_file = tmp_path / "override.json"
    _write(env_file, {"NIC_INTERFACE": "env-nic"})
    monkeypatch.setenv("NETWATCH_CONFIG", str(env_file))
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    assert cfg["NIC_INTERFACE"] == "env-nic"


def test_bom_overlay_is_read(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    (tmp_path / "netwatch.config.json").write_text('{"NIC_INTERFACE": "bom-nic"}', encoding="utf-8-sig")
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    assert cfg["NIC_INTERFACE"] == "bom-nic"


def test_malformed_overlay_is_skipped_not_fatal(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    (tmp_path / "netwatch.config.json").write_text("{not json", encoding="utf-8")
    cfg, notes = build_config(str(tmp_path), hostname="nohost")
    assert cfg["MAX_ENTITIES"] == DEFAULTS["MAX_ENTITIES"]
    assert any("SKIPPED" in n for n in notes)


def test_non_object_overlay_is_skipped(tmp_path):
    path = tmp_path / "list.json"
    _write(path, [1, 2, 3])
    data, error = load_overlay(str(path))
    assert data == {}
    assert "JSON object" in error


def test_unknown_keys_are_reported_and_dropped(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    _write(tmp_path / "netwatch.config.json", {"MAX_ENTIIES": 4})  # typo
    cfg, notes = build_config(str(tmp_path), hostname="nohost")
    assert "MAX_ENTIIES" not in cfg
    assert cfg["MAX_ENTITIES"] == DEFAULTS["MAX_ENTITIES"]
    assert any("MAX_ENTIIES" in n for n in notes)


def test_underscore_annotations_are_not_reported_as_typos(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    _write(tmp_path / "netwatch.config.json", {"_comment": "why", "MAX_ENTITIES": 8})
    cfg, notes = build_config(str(tmp_path), hostname="nohost")
    assert cfg["MAX_ENTITIES"] == 8
    assert not any("unknown keys" in n for n in notes)


def test_shipped_example_overlay_is_valid(monkeypatch):
    # The example is the documentation of the config surface; a stale key in it is
    # a doc bug that this catches at test time.
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    example = os.path.join(here, "netwatch.config.example.json")
    data, error = load_overlay(example)
    assert error is None
    stale = [k for k in data if not k.startswith("_") and k not in DEFAULTS]
    assert stale == [], f"example names keys that no longer exist: {stale}"


def test_explicit_v6_prefixes_survive_autodetection(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    _write(tmp_path / "netwatch.config.json",
           {"LOCAL_PREFIXES6": ["2600:1700:abcd:1200::/64"], "LOCAL_PREFIXES6_AUTO": False})
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    assert cfg["LOCAL_PREFIXES6"] == ("2600:1700:abcd:1200::/64",)


def test_explicit_gateway_disables_detection(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    _write(tmp_path / "netwatch.config.json", {"GATEWAY_IP": "10.9.9.1"})
    cfg, notes = build_config(str(tmp_path), hostname="nohost")
    assert cfg["GATEWAY_IP"] == "10.9.9.1"
    assert not any("gateway auto-detected" in n for n in notes)


def test_local_prefixes_are_a_tuple(tmp_path, monkeypatch):
    # compile_v4_prefixes iterates it; JSON hands back a list, which must not leak
    # a mutable shared default into the child processes.
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    cfg, _ = build_config(str(tmp_path), hostname="nohost")
    assert isinstance(cfg["LOCAL_PREFIXES"], tuple)
    assert isinstance(cfg["LOCAL_PREFIXES6"], tuple)


def test_configured_gateway_is_pinned_and_unset_is_refreshed(tmp_path, monkeypatch):
    import logging
    from types import SimpleNamespace

    import netwatch_config
    import netwatch_workers
    monkeypatch.setattr(netwatch_config, "detect_default_gateway", lambda: "10.0.0.1")
    monkeypatch.setattr(netwatch_workers, "detect_default_gateway", lambda: "10.9.9.9")
    log = logging.getLogger("t")
    for extra, expected in (({"GATEWAY_IP": "10.1.1.1"}, "10.1.1.1"), ({}, "10.9.9.9")):
        cfg, _ = build_config(str(tmp_path), hostname="nohost", extra=extra)
        analyzer = SimpleNamespace(gateway_ip=cfg["GATEWAY_IP"])
        netwatch_workers.refresh_gateway(cfg, analyzer, log)
        assert analyzer.gateway_ip == expected


def test_refresh_keeps_the_gateway_and_says_so_when_no_route_is_found(monkeypatch, caplog):
    import logging
    from types import SimpleNamespace

    import netwatch_workers
    monkeypatch.setattr(netwatch_workers, "detect_default_gateway", lambda: "")
    analyzer = SimpleNamespace(gateway_ip="10.0.0.1")
    with caplog.at_level(logging.INFO, logger="t"):
        netwatch_workers.refresh_gateway({}, analyzer, logging.getLogger("t"))
    assert analyzer.gateway_ip == "10.0.0.1" and "found no default route" in caplog.text


def test_protected_pins_survive_an_overlay(tmp_path, monkeypatch):
    from netwatch_actions import protection_from_config

    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    _write(tmp_path / "netwatch.config.json", {"OWN_IP": "10.0.0.9", "OWN_MAC": "02:00:00:00:00:09",
                                               "GATEWAY_MAC": "02:00:00:00:00:01"})
    cfg, notes = build_config(str(tmp_path), hostname="nohost")
    assert not any("unknown keys" in n for n in notes)
    protection = protection_from_config(cfg)
    assert (protection.own_ip, protection.own_mac, protection.gateway_mac) == (
        "10.0.0.9", "02:00:00:00:00:09", "02:00:00:00:00:01")


def test_missing_env_overlay_and_broken_overlay_are_warned(tmp_path, monkeypatch):
    (tmp_path / "netwatch.config.json").write_text('{"MAX_ENTITIES": 8,}', encoding="utf-8")  # trailing comma
    monkeypatch.setenv("NETWATCH_CONFIG", str(tmp_path / "typo.json"))
    _, notes = build_config(str(tmp_path), hostname="nohost")
    warned = [n for n in notes if n.startswith("WARNING") and "ignored" in n]
    assert len(warned) == 2 and any("typo.json" in n for n in warned)


def test_linux_gateway_comes_from_the_kernel_route_table(tmp_path, monkeypatch):
    import netwatch_config

    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n", encoding="ascii")
    monkeypatch.setattr(netwatch_config.os, "name", "posix")
    monkeypatch.setattr(netwatch_config, "PROC_NET_ROUTE", str(route), raising=False)
    assert netwatch_config.detect_default_gateway() == "10.0.0.1"  # lowest metric wins


def test_core_shards_are_capped_at_the_cpu_count(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_CONFIG", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    _write(tmp_path / "netwatch.config.json", {"CORE_SHARDS": 32})
    cfg, notes = build_config(str(tmp_path), hostname="nohost")
    assert cfg["CORE_SHARDS"] == 8 and any("CORE_SHARDS 32 exceeds 8 CPUs" in n for n in notes)
    _write(tmp_path / "netwatch.config.json", {"CORE_SHARDS": 0})
    try:
        build_config(str(tmp_path), hostname="nohost")
    except ValueError as exc:
        assert "CORE_SHARDS" in str(exc)
    else:
        raise AssertionError("CORE_SHARDS 0 was accepted")


def test_unparseable_beacon_ignore_destinations_are_named_at_boot(tmp_path):
    cfg, notes = build_config(str(tmp_path), hostname="nohost",
                              extra={"BEACON_IGNORE_DESTINATIONS": ["1.2.3.4", "not-an-ip"]})
    assert any("not-an-ip" in note and "1.2.3.4" not in note for note in notes)
