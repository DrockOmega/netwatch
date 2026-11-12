import json
from pathlib import Path

import pytest

LINUX = Path(__file__).resolve().parent.parent / "packaging" / "linux"


def test_suricata_yaml_matches_what_netwatch_reads():
    yaml = pytest.importorskip("yaml")
    conf = yaml.safe_load((LINUX / "suricata.yaml").read_text())
    eve = next(o["eve-log"] for o in conf["outputs"] if "eve-log" in o)
    assert eve["filename"] == "eve.json.%Y-%m-%d" and eve["rotate-interval"] == "1d"
    types = {next(iter(t)) if isinstance(t, dict) else t for t in eve["types"]}
    assert {"alert", "dns", "tls", "http", "stats"} <= types and "flow" not in types  # Zeek conn carries sessions
    assert conf["af-packet"][0]["cluster-type"] == "cluster_flow" and conf["af-packet"][0]["tpacket-v3"]
    assert conf["threshold-file"] == "/etc/netwatch/suricata/threshold.config"


def test_overlay_template_points_at_suricata_data_dir():
    overlay = json.loads((LINUX / "netwatch.HOST.json.template").read_text())
    assert overlay["SURICATA_EVE_PATH"].startswith("/var/lib/suricata/eve.json")
    assert overlay["NIC_INTERFACE"] == "REPLACE_WITH_IFACE"
