import json
import socket

from netwatch_core import make_message
from netwatch_security_store import DurableIncidentStore
from netwatch_ui_state import (
    IncidentStore,
    filter_incident_rows,
    filter_traffic_events,
    incident_title,
    load_inventory_snapshot,
    load_recent_traffic_events,
    load_response_mode,
    load_web_observation_events,
    normalize_response_mode,
    response_dispatch,
    save_response_mode,
    severity_for,
)


def test_response_mode_normalization_and_dispatch():
    assert normalize_response_mode("AUTONOMOUS") == "autonomous"
    assert normalize_response_mode("invalid") == "ids_only"
    assert normalize_response_mode("invalid", default="ids_only") == "ids_only"
    assert response_dispatch("ids_only") == "ignore"
    assert response_dispatch("invalid") == "ignore"
    assert normalize_response_mode("invalid", default="invalid") == "ids_only"
    assert response_dispatch("ready") == "queue"
    assert response_dispatch("autonomous") == "enforce"


def test_response_mode_state_round_trip_and_malformed_fallback(tmp_path):
    path = tmp_path / "response-mode.json"
    assert load_response_mode(path) == "ids_only"
    assert save_response_mode(path, "autonomous") == "autonomous"
    assert load_response_mode(path) == "autonomous"
    save_response_mode(path, "ready")
    assert load_response_mode(path) == "ready"

    path.write_text("{not json", encoding="utf-8")
    assert load_response_mode(path, default="ids_only") == "ids_only"


def test_severity_honors_explicit_known_value():
    assert severity_for("DNS_ANOMALY", {"severity": "critical"}) == "critical"
    assert severity_for("DEVICE_NEW", {}) == "notice"


def test_evidence_completion_is_audit_notice_not_incident_recovery():
    assert severity_for("EVIDENCE_SAVED", {}) == "notice"
    assert severity_for("EVIDENCE_FAILED", {}) == "anomaly"


def test_incident_title_translates_detector_output():
    assert incident_title("ALERT", "THREAT INTEL: egress to 8.8.8.8") == "Known-bad destination contacted"
    assert incident_title("ARP_ANOMALY", "anything") == "ARP identity anomaly"


def test_incident_store_correlates_repeats_and_escalates(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    def payload():
        return make_message("DOD_CORE", "ALERT", socket.inet_aton("8.8.8.8"),
                            {"message": "THREAT INTEL: egress to 8.8.8.8"})
    first = store.add(payload(), severity="anomaly", now=10)
    second = store.add(payload(), severity="critical", now=20)

    assert first["incident_id"] == second["incident_id"]
    assert second["count"] == 2
    assert second["last_seen"] == 20
    assert second["severity"] == "critical"
    assert store.open_count() == 1
    assert store.critical_count() == 1


def test_incident_store_rejects_invalid_envelopes_but_accepts_future_actions():
    store = IncidentStore()
    assert store.add({"action": "ALERT"}) is None
    row = store.add(make_message(
        "DOD_CORE",
        "FUTURE_DETECTOR",
        "SYSTEM",
        {"message": "Future detector finding"},
    ))
    assert row["action"] == "FUTURE_DETECTOR"


def test_durable_store_tracks_case_status_and_response(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    row = store.add(make_message(
        "DOD_CORE",
        "ALERT",
        socket.inet_aton("8.8.8.8"),
        {"message": "THREAT INTEL: egress to 8.8.8.8"},
    ))
    assert store.update_case(row["incident_id"], actor="test", status="Contained",
                             response="Firewall block active")
    stored = store.snapshot()[0]
    assert stored["status"] == "Contained"
    assert stored["response"] == "Firewall block active"
    assert store.open_count() == 1
    store.update_case(row["incident_id"], actor="test", status="Dismissed", closure_reason="test")
    assert store.open_count() == 0


def test_incident_store_uses_structured_arp_offender_and_recovers_action():
    store = IncidentStore()
    row = store.add(make_message(
        "DOD_CORE",
        "ARP_ANOMALY",
        "UI_SHELL",
        {
            "message": "ARP-SPOOF: gateway binding changed",
            "offender_ip": "10.0.0.34",
        },
    ))
    assert row["target"] == "10.0.0.34"


def test_filter_incident_rows_matches_operational_card_scopes():
    rows = [
        {"incident_id": "NW-1", "severity": "critical", "status": "Open"},
        {"incident_id": "NW-2", "severity": "alert", "status": "Pending"},
        {"incident_id": "NW-3", "severity": "critical", "status": "Dismissed"},
    ]

    assert [row["incident_id"] for row in filter_incident_rows(rows)] == ["NW-1", "NW-2"]
    assert [row["incident_id"] for row in filter_incident_rows(rows, "CRITICAL ONLY")] == ["NW-1"]
    assert len(filter_incident_rows(rows, "ALL INCIDENTS")) == 3
    assert [row["incident_id"] for row in filter_incident_rows(rows, "unknown")] == ["NW-1", "NW-2"]


def test_filter_traffic_events_applies_filters_and_normalizes():
    events = [
        {
            "time_str": "12:00:00",
            "src": socket.inet_aton("10.0.0.2"),
            "dst": socket.inet_aton("8.8.8.8"),
            "domain": "dns.google",
            "protocol": "UDP",
            "port": 53,
            "size": 72,
            "os_guess": "WIN",
            "mac": "00:11:22:33:44:55",
            "country": "US",
            "alert": True,
            "is_lan_to_lan": False,
        },
        {
            "src": socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
            "dst": socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
            "is_lan_to_lan": True,
        },
    ]

    rows = filter_traffic_events(events, {
        "scope": "EXTERNAL (HIDE LOCAL)",
        "os": "WIN",
        "alerts": "ALERTS ONLY",
        "family": "IPv4",
    })

    assert rows == [{
        "time": "12:00:00",
        "source": "10.0.0.2",
        "target": "dns.google",
        "destination": "8.8.8.8",
        "protocol": "UDP",
        "port": 53,
        "size": 72,
        "os": "WIN",
        "mac": "00:11:22:33:44:55",
        "country": "US",
        "family": 4,
        "alert": True,
        "scope": "External",
        "signal": "OBSERVED ACTIVITY",
    }]


def test_filter_traffic_events_separates_human_signal_from_web_noise():
    base = {
        "time_str": "12:00:00",
        "src": socket.inet_aton("10.0.0.2"),
        "dst": socket.inet_aton("8.8.8.8"),
        "protocol": "TCP",
        "port": 443,
        "size": 517,
        "is_lan_to_lan": False,
    }
    likely = dict(base, web_observation={
        "label": "HUMAN LIKELY",
        "score": 7,
        "reason": "named host · new destination",
        "domain": "chatgpt.com",
    })
    noise = dict(base, web_observation={
        "label": "WEB NOISE",
        "score": 0,
        "reason": "background-service hostname",
        "domain": "telemetry.example",
    })

    human_rows = filter_traffic_events([likely, noise], {"observation": "HUMAN SIGNAL"})
    noise_rows = filter_traffic_events([likely, noise], {"observation": "WEB NOISE"})

    assert [row["target"] for row in human_rows] == ["chatgpt.com"]
    assert human_rows[0]["signal"].startswith("HUMAN LIKELY")
    assert [row["target"] for row in noise_rows] == ["telemetry.example"]


def test_filter_traffic_events_can_hide_secure_sources_or_all_secure_endpoints():
    def event(src, dst, mac, mac_dst):
        return {
            "src": socket.inet_aton(src),
            "dst": socket.inet_aton(dst),
            "mac": mac,
            "mac_dst": mac_dst,
            "port": 443,
            "size": 100,
        }

    events = [
        event("10.0.0.15", "8.8.8.8", "00:00:00:00:00:01", "00:00:00:00:00:02"),
        event("8.8.4.4", "100.64.0.2", "00:00:00:00:00:03", "00:00:00:00:00:04"),
        event("10.0.0.50", "1.1.1.1", "02-00-00-00-02-01", "00:00:00:00:00:05"),
        event("9.9.9.9", "10.0.0.51", "00:00:00:00:00:06", "02-00-00-00-02-02"),
        event("10.0.0.60", "1.0.0.1", "00:00:00:00:00:07", "00:00:00:00:00:08"),
    ]
    filters = {
        "node_scope": "HIDE SECURE SOURCES",
        "secure_nodes": {
            "node-1": {"ips": ["10.0.0.15"]},
            "node-2": {"ips": ["100.64.0.2"]},
            "node-3": {"macs": ["02:00:00:00:02:01"]},
            "node-4": {"macs": ["02:00:00:00:02:02"]},
        },
    }

    rows = filter_traffic_events(events, filters)

    assert [row["source"] for row in rows] == ["8.8.4.4", "9.9.9.9", "10.0.0.60"]

    filters["node_scope"] = "HIDE SECURE ENDPOINTS"
    rows = filter_traffic_events(events, filters)

    assert [row["source"] for row in rows] == ["10.0.0.60"]


def test_filter_traffic_events_exposes_any_and_unclassified_outbound_activity():
    base = {
        "src": socket.inet_aton("10.0.0.60"),
        "dst": socket.inet_aton("8.8.8.8"),
        "protocol": "TCP",
        "size": 100,
        "direction": "egress",
    }
    unclassified = dict(base, port=5228)
    web = dict(base, port=443, web_observation={
        "label": "HUMAN POSSIBLE", "domain": "example.com",
    })
    inbound = dict(
        base,
        src=socket.inet_aton("1.1.1.1"),
        dst=socket.inet_aton("10.0.0.60"),
        direction="ingress",
        port=443,
    )

    outbound = filter_traffic_events(
        [unclassified, web, inbound], {"observation": "ANY OUTBOUND"},
    )
    unclassified_only = filter_traffic_events(
        [unclassified, web, inbound], {"observation": "UNCLASSIFIED OUTBOUND"},
    )

    assert [row["port"] for row in outbound] == [5228, 443]
    assert [row["port"] for row in unclassified_only] == [5228]
    assert unclassified_only[0]["signal"] == "OUTBOUND UNCLASSIFIED"


def test_load_web_observation_events_reconstructs_durable_sessions(tmp_path):
    import sqlite3

    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE web_observations (
                flow_id TEXT, timestamp REAL, src_ip TEXT, dst_ip TEXT,
                mac_src TEXT, mac_dst TEXT, protocol TEXT, port INTEGER,
                domain TEXT, label TEXT, score INTEGER, reason TEXT,
                os_guess TEXT, country TEXT, size_bytes INTEGER
            )
        """)
        conn.execute(
            "INSERT INTO web_observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "flow-1", 10.0, "10.0.0.2", "8.8.8.8", "src", "dst",
                "TCP", 443, "example.com", "HUMAN LIKELY", 7,
                "named host", "WIN", "US", 517,
            ),
        )
        conn.execute(
            "INSERT INTO web_observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "invalid-time", 1e30, "10.0.0.3", "1.1.1.1", "src", "dst",
                "TCP", 443, "invalid.example", "HUMAN LIKELY", 7,
                "new destination", "WIN", "US", 517,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    events = load_web_observation_events(str(db_path))

    assert len(events) == 1
    assert socket.inet_ntoa(events[0]["src"]) == "10.0.0.2"
    assert events[0]["web_observation"]["label"] == "HUMAN LIKELY"


def test_load_recent_traffic_events_reconstructs_direction_and_activity(tmp_path):
    import sqlite3

    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE network_events (
                uuid TEXT, timestamp REAL, mac_src TEXT, mac_dst TEXT,
                src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
                tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER,
                sni_domain TEXT, country TEXT, packet_count INTEGER
            )
        """)
        conn.executemany(
            "INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    "outbound-v4", 20.0, "src", "dst", "10.0.0.60", "8.8.8.8",
                    "TCP", 5228, "S", 64, 300, "", "US", 4,
                ),
                (
                    "lateral-v6", 10.0, "src6", "dst6",
                    "2601:281:da82:ba80::10", "2601:281:da82:ba80::20",
                    "UDP", 5353, "", 255, 200, "", "--", 2,
                ),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    events = load_recent_traffic_events(
        str(db_path),
        local_prefixes=("10.",),
        local_prefixes6=("2601:281:da82:ba80::/64",),
    )
    rows = filter_traffic_events(events)

    assert [event["event_id"] for event in events] == ["outbound-v4", "lateral-v6"]
    assert [event["direction"] for event in events] == ["egress", "lateral"]
    assert [event["packet_count"] for event in events] == [4, 2]
    assert [row["signal"] for row in rows] == [
        "OUTBOUND UNCLASSIFIED", "DISCOVERY / BROADCAST",
    ]


def test_raw_durable_filters_run_before_the_row_limit(tmp_path):
    import sqlite3

    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE network_events (
                uuid TEXT, timestamp REAL, mac_src TEXT, mac_dst TEXT,
                src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
                tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER,
                sni_domain TEXT, country TEXT, packet_count INTEGER
            )
        """)
        conn.executemany(
            "INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("trusted-new", 20.0, "aa:aa:aa:aa:aa:aa", "dst", "10.0.0.2",
                 "8.8.8.8", "TCP", 443, "A", 128, 100, "", "US", 1),
                ("other-old", 10.0, None, "dst", "10.0.0.60",
                 "1.1.1.1", "TCP", 443, "A", 64, 100, "", "US", 1),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    events = load_recent_traffic_events(
        str(db_path),
        limit=1,
        local_prefixes=("10.",),
        filters={
            "node_scope": "HIDE SECURE SOURCES",
            "observation": "ANY OUTBOUND",
            "secure_nodes": {"node-1": {"ips": ["10.0.0.2"]}},
        },
    )

    assert [event["event_id"] for event in events] == ["other-old"]


def test_web_durable_filters_run_before_the_row_limit(tmp_path):
    import sqlite3

    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE web_observations (
                flow_id TEXT, timestamp REAL, src_ip TEXT, dst_ip TEXT,
                mac_src TEXT, mac_dst TEXT, protocol TEXT, port INTEGER,
                domain TEXT, label TEXT, score INTEGER, reason TEXT,
                os_guess TEXT, country TEXT, size_bytes INTEGER
            )
        """)
        conn.executemany(
            "INSERT INTO web_observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                ("trusted-new", 20.0, "10.0.0.2", "8.8.8.8", "src", "dst",
                 "TCP", 443, "trusted.example", "HUMAN LIKELY", 7, "named host",
                 "WIN", "US", 100),
                ("other-old", 10.0, "10.0.0.60", "1.1.1.1", "src", "dst",
                 "TCP", 443, "other.example", "HUMAN POSSIBLE", 5, "new destination",
                 "NIX/MOB", "US", 100),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    events = load_web_observation_events(
        str(db_path),
        limit=1,
        filters={
            "node_scope": "HIDE SECURE SOURCES",
            "observation": "HUMAN SIGNAL",
            "secure_nodes": {"node-1": {"ips": ["10.0.0.2"]}},
        },
    )

    assert [event["flow_id"] for event in events] == ["other-old"]
    assert events[0]["os_guess"] == "LOW TTL"

    likely = load_web_observation_events(
        str(db_path), filters={"observation": "LIKELY HUMAN"},
    )
    possible = load_web_observation_events(
        str(db_path), filters={"observation": "POSSIBLE HUMAN"},
    )
    assert [event["flow_id"] for event in likely] == ["trusted-new"]
    assert [event["flow_id"] for event in possible] == ["other-old"]


def test_filter_traffic_events_skips_malformed_numeric_fields():
    valid = {
        "src": socket.inet_aton("10.0.0.2"),
        "dst": socket.inet_aton("8.8.8.8"),
        "port": 53,
        "size": 72,
    }
    invalid = dict(valid, port={"not": "scalar"})
    rows = filter_traffic_events([invalid, valid])
    assert len(rows) == 1
    assert rows[0]["port"] == 53


def test_filter_traffic_events_skips_infinite_numeric_fields():
    event = {
        "src": socket.inet_aton("10.0.0.2"),
        "dst": socket.inet_aton("8.8.8.8"),
        "port": float("inf"),
        "size": 72,
    }
    assert filter_traffic_events([event]) == []


def test_incident_store_handles_unhashable_target_safely():
    store = IncidentStore()
    row = store.add(make_message(
        "DOD_CORE",
        "FUTURE_DETECTOR",
        {"opaque": "target"},
        {"message": "Future detector finding"},
    ))
    assert row["target"] == "{'opaque': 'target'}"


def test_load_inventory_snapshot_is_tolerant_and_sorted(tmp_path):
    ledger = tmp_path / "devices.json"
    ledger.write_text(json.dumps({"devices": {
        "00:11:22:33:44:55": {
            "vendor": "Older", "first_seen": 1, "last_seen": 2,
            "ips": ["10.0.0.2"], "count": 4,
        },
        "00:11:22:33:44:66": {
            "vendor": "Newer", "first_seen": 1, "last_seen": 3,
            "ips": ["10.0.0.3"], "count": 5,
        },
        "00:11:22:33:44:77": {
            "vendor": "Malformed", "first_seen": [], "last_seen": {},
            "ips": ["10.0.0.4"], "count": "not-a-count",
        },
    }}), encoding="utf-8")

    rows = load_inventory_snapshot(ledger)
    assert [row["vendor"] for row in rows] == ["Newer", "Older"]
    assert load_inventory_snapshot(tmp_path / "missing.json") == []
