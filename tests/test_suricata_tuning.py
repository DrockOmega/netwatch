"""The shipped Suricata threshold example must only contain narrow suppressions."""
import ipaddress
from pathlib import Path

THRESHOLD = Path(__file__).resolve().parent.parent / "packaging" / "suricata" / "threshold.config"
# Signature-only entries allowed sensor-wide: STUN binding request/response (service identification).
SIGNATURE_ONLY = {"2016149", "2016150"}


def _suppressions():
    for line in THRESHOLD.read_text().splitlines():
        if line.startswith("suppress"):
            yield dict(part.strip().split(" ", 1) for part in line[len("suppress"):].split(","))


def test_every_suppression_names_one_signature_and_an_exact_endpoint():
    rows = list(_suppressions())
    assert rows
    for row in rows:
        assert row["gen_id"] == "1" and row["sig_id"].isdigit()
        if "track" not in row:
            assert set(row) == {"gen_id", "sig_id"} and row["sig_id"] in SIGNATURE_ONLY
            continue
        assert set(row) == {"gen_id", "sig_id", "track", "ip"}
        assert row["track"] in {"by_src", "by_dst"}
        if row["ip"] == "$TAILSCALE_DERP":  # an address variable, defined from the relay list
            continue
        network = ipaddress.ip_network(row["ip"], strict=True)
        assert network.prefixlen >= (16 if network.version == 4 else 32), row


def test_signature_only_entries_are_exactly_the_allowed_set():
    assert {row["sig_id"] for row in _suppressions() if "track" not in row} == SIGNATURE_ONLY


def test_derp_handshake_suppression_is_scoped_to_the_relay_list():
    rows = [row for row in _suppressions() if row["sig_id"] == "2210055"]
    assert rows == [{"gen_id": "1", "sig_id": "2210055", "track": "by_src", "ip": "$TAILSCALE_DERP"}]
    assert "include: /var/lib/suricata/tailscale-derp.yaml" in (THRESHOLD.parent.parent / "linux" / "suricata.yaml").read_text()
    seed = (THRESHOLD.parent / "tailscale-derp.yaml").read_text()
    relays = seed.split('TAILSCALE_DERP: "[', 1)[1].split(']"', 1)[0].split(",")
    assert len(relays) > 50 and all("/" not in r and r not in {"any", "0.0.0.0", "::"} for r in relays)
