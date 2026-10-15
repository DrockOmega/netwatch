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
        network = ipaddress.ip_network(row["ip"], strict=True)
        assert network.prefixlen >= (16 if network.version == 4 else 32), row


def test_signature_only_entries_are_exactly_the_allowed_set():
    assert {row["sig_id"] for row in _suppressions() if "track" not in row} == SIGNATURE_ONLY
