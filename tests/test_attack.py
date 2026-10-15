"""ATT&CK tagging: committed map, Suricata metadata pass-through, cases API field."""

import json
from pathlib import Path

from netwatch_core import make_message
from netwatch_incidents import load_attack_map, map_attack
from netwatch_security_store import DurableIncidentStore
from netwatch_suricata import normalize_eve_event
from tests.test_service_api import service  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent
PACK = load_attack_map(str(ROOT / "attack_map.json"))


def test_map_loads_and_nothing_is_demonstrated():
    assert len(PACK["kinds"]) >= 18 and PACK["none"]
    assert all(k["demonstrated"] is False for k in PACK["kinds"])  # flip only with a lab fixture
    assert all(t in PACK["techniques"] for k in PACK["kinds"] for t in k["techniques"])
    assert not {k["action"] for k in PACK["kinds"] if k["techniques"]} & set(PACK["none"])


def test_map_resolves_by_action_and_message_prefix():
    ids = lambda action, msg="": [t["technique_id"] for t in map_attack(action, msg, pack=PACK)]  # noqa: E731
    assert ids("ALERT", "PORT SCAN ALERT: x swept") == ["T1046"]
    assert ids("DNS_ANOMALY", "DNS TUNNEL: x") == ["T1071.004", "T1572"]
    assert ids("DNS_ANOMALY", "DNS DGA: x") == ["T1568.002"]
    assert ids("ARP_ANOMALY") == ["T1557.002"]
    assert ids("ALERT", "something else") == []
    assert ids("CAPTURE_LOSS") == [] and ids("RUNTIME_COLLECTION_GAP") == []
    assert map_attack("ARP_ANOMALY", pack=PACK)[0]["source"] == "map"


def _eve(metadata):
    return {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.9",
            "alert": {"signature": "ET MALWARE x", "signature_id": 1, "severity": 2, "action": "allowed",
                      "metadata": metadata}}


def test_suricata_metadata_passes_into_case():
    payload = normalize_eve_event(_eve({
        "mitre_technique_id": ["T1071"], "mitre_technique_name": ["Application_Layer_Protocol"],
        "mitre_tactic_id": ["TA0011"], "mitre_tactic_name": ["Command_and_Control"]}))
    assert payload["data"]["attack"] == [{"technique_id": "T1071", "technique_name": "Application Layer Protocol",
                                          "tactic": "Command and Control"}]
    store = DurableIncidentStore(":memory:")
    case = store.add(payload)
    assert case["attack"] == [{"technique_id": "T1071", "technique_name": "Application Layer Protocol",
                               "tactic": "Command and Control", "source": "suricata", "demonstrated": False}]
    junk = normalize_eve_event(_eve({"mitre_technique_id": ["not-an-id"], "other": "x"}))
    assert "not-an-id" not in json.dumps(store.add(junk))
    assert normalize_eve_event(_eve({}))["data"]["attack"] == []
    store.close()


def test_cases_api_exposes_attack(service):  # noqa: F811
    api, client, _, _ = service
    api.store.add(make_message("DOD_CORE", "DNS_ANOMALY", "UI_SHELL",
                               {"message": "DNS DGA: 10.0.0.2 queried x.test", "severity": "anomaly"}))
    api.store.add(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {"message": "gap"}))
    cases = {c["action"]: c for c in client.request("cases")["data"]}
    assert [t["technique_id"] for t in cases["DNS_ANOMALY"]["attack"]] == ["T1568.002"]
    assert cases["DNS_ANOMALY"]["attack"][0]["demonstrated"] is False
    assert cases["RUNTIME_COLLECTION_GAP"]["attack"] == []
    json.dumps(cases)
