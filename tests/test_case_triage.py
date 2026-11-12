from tools.case_triage import families, select


def case(action, detail, last_seen=0, severity="alert"):
    return {"incident_id": detail, "action": action, "detail": detail, "last_seen": last_seen, "severity": severity}


def test_families_fold_addresses_and_select_matches_one_reviewed_family():
    cases = [case("BEACON_ANOMALY", "BEACONING: 10.0.0.5 -> 1.2.3.4:443 every 30.1s"),
             case("BEACON_ANOMALY", "BEACONING: 2601:db8::1 -> 2606:4700::1:443 every 60.0s"),
             case("ALERT", "GEO-THREAT: Egress to CN from 10.0.0.9", last_seen=86400)]
    rows = families(cases, now=86400 * 2)
    assert rows[0][0] == 2 and rows[0][1][0] == "BEACON_ANOMALY"
    assert [c["detail"] for c in select(cases, "BEACON_ANOMALY", r"2606:4700")] == [cases[1]["detail"]]
    assert select(cases, "ALERT", "Egress to RU") == []
