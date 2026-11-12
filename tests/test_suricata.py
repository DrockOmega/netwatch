import ipaddress

from netwatch_suricata import normalize_eve_event


def test_normalize_suricata_alert():
    payload = normalize_eve_event({
        "event_type": "alert", "src_ip": "10.0.0.2", "src_port": 50000,
        "dest_ip": "8.8.8.8", "dest_port": 443, "app_proto": "tls",
        "alert": {"signature": "Known malware TLS", "signature_id": 42,
                  "severity": 1, "action": "blocked"},
    }, ["10.0.0.0/8"])
    assert payload["action"] == "SURICATA_ALERT"
    assert payload["target_id"] == ipaddress.ip_address("8.8.8.8").packed
    assert payload["data"]["severity"] == "critical"
    assert payload["data"]["signature_id"] == 42
    assert payload["data"]["direction"] == "egress"


def test_inbound_suricata_alert_targets_remote_source():
    payload = normalize_eve_event({
        "event_type": "alert", "src_ip": "198.51.100.8", "dest_ip": "10.0.0.2",
        "alert": {"signature": "Inbound exploit"},
    }, ["10.0.0.0/8"])
    assert payload["target_id"] == ipaddress.ip_address("198.51.100.8").packed
    assert payload["data"]["offender_ip"] == "198.51.100.8"


def test_ambiguous_suricata_alert_is_not_containment_eligible():
    payload = normalize_eve_event({
        "event_type": "alert", "src_ip": "198.51.100.8", "dest_ip": "203.0.113.9",
        "alert": {"signature": "Unknown direction"},
    }, ["10.0.0.0/8"])
    assert payload["target_id"] == "SYSTEM"
    assert payload["data"]["containment_eligible"] is False


def test_non_detection_eve_record_is_ignored():
    assert normalize_eve_event({"event_type": "flow"}) is None


def test_informational_priority_one_rule_is_not_critical():
    def sev(signature, category=""):
        return normalize_eve_event({
            "event_type": "alert", "src_ip": "10.0.0.2", "dest_ip": "8.8.8.8",
            "alert": {"signature": signature, "severity": 1, "category": category, "action": "allowed"},
        }, ["10.0.0.0/8"])["data"]["severity"]

    assert sev("ET USER_AGENTS Steam HTTP Client User-Agent") == "alert"
    assert sev("ET USER_AGENTS Steam HTTP Client User-Agent", "Potential Corporate Privacy Violation") == "info"
    assert sev("ET INFO Possible Kali Linux hostname in DHCP Request Packet") == "alert"
    assert sev("Custom rule", "Potential Corporate Privacy Violation") == "info"
    assert sev("ET DOS Possible SSDP Amplification Scan in Progress") == "critical"
