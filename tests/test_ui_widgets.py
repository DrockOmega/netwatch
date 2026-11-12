import os
import queue
import socket
import sqlite3
import threading
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from netwatch_core import make_message
from netwatch_quarantine import Quarantine, RecordingQuarantineEffector
from netwatch_security_store import DurableIncidentStore
from netwatch_suricata import EveCollector
from netwatch_ui import OperationsDashboard, StatCard


def _app():
    return QApplication.instance() or QApplication([])


def _settle(window, timeout=5.0):
    """Wait for queued effector-thread calls and deliver their results on this thread."""
    app = _app()
    deadline = time.monotonic() + timeout
    while window._effects_pending and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    app.processEvents()
    assert not window._effects_pending


@pytest.fixture(autouse=True)
def close_test_windows():
    yield
    app = QApplication.instance()
    if app is not None:
        for widget in app.topLevelWidgets():
            widget.close()
        app.processEvents()


def test_case_survives_missing_queue_and_dashboard_restart(tmp_path):
    app = _app()
    path = str(tmp_path / "security.db")
    payload = make_message("sensor", "ALERT", "8.8.8.8", {
        "message": "THREAT INTEL: egress to 8.8.8.8", "severity": "critical",
    })
    collector = DurableIncidentStore(path)
    case = collector.add(payload)
    collector.close()
    config = {"INCIDENT_DB": path, "MITIGATION_ENABLED": False,
              "QUARANTINE_ENABLED": False, "DB_NAME": str(tmp_path / "packets.db"),
              "DEVICE_LEDGER": str(tmp_path / "devices.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}

    def dashboard():
        return OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(),
                                   queue.Queue(), config=config)

    window = dashboard()
    window._refresh_periodic_ui()
    assert window.incident_model.rowCount() == 1
    window._incident_selected(window.incident_model.index(0, 0))
    assert "THREAT INTEL" in window.case_evidence.toPlainText()
    window._acknowledge_case()
    window.case_assignment.setText("Home security")
    window.case_note.setText("Verified endpoint connection")
    window._save_case()
    window._resolve_case()  # Empty reason must leave the case open.
    assert window.incidents.get(case["incident_id"])["status"] == "Acknowledged"
    window.case_closure_reason.setText("Approved service after investigation")
    window._resolve_case()
    window.close()
    app.processEvents()  # Queued render/history callbacks must not access closed SQLite.

    window = dashboard()
    restored = window.incidents.get(case["incident_id"])
    assert restored["assignment"] == "Home security"
    assert restored["status"] == "Resolved"
    assert any(entry["body"].get("note") == "Verified endpoint connection"
               for entry in window.incidents.audit(case["incident_id"]))
    window.close()
    app.processEvents()


def test_native_source_drilldown_and_engine_health_are_independent_of_reader_liveness(tmp_path):
    app = _app()
    source_path = tmp_path / "eve.json"
    source_path.write_text('{"event_type":"dns","timestamp":"2026-10-07T12:00:00+00:00",'
                           '"src_ip":"10.0.0.12","dest_ip":"8.8.8.8","dns":{"rrname":"example.test"}}\n')
    ledger = str(tmp_path / "security.db")
    store = DurableIncidentStore(ledger)
    collector = EveCollector(store, {"SURICATA_EVE_PATH": str(source_path)})
    collector.poll()
    collector.close()
    store.close()
    status = queue.Queue()
    config = {"INCIDENT_DB": ledger, "SURICATA_EVE_ENABLED": True,
              "MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False,
              "DB_NAME": str(tmp_path / "packets.db"), "DEVICE_LEDGER": str(tmp_path / "devices.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"), "LOG_DIR": str(tmp_path),
              "LOG_TO_CONSOLE": False}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), status, config=config)
    window._show_page("Sources")
    window._refresh_sources(force=True)
    assert window.source_model.rowCount() == 1
    window._source_selected(window.source_model.index(0, 0))
    assert "example.test" in window.source_detail.toPlainText()
    window._source_hold(True)
    assert "failed" in window.source_action_status.text()
    window.source_hold_reason.setText("Investigate the DNS observation")
    window._source_hold(True)
    assert window.incidents.native_retention_status(window.selected_source)["hold"]
    window._source_hold(False)
    assert window.incidents.native_retention_status(window.selected_source)["hold"] is None
    status.put(make_message("SURICATA", "WORKER_HEARTBEAT", "UI_SHELL", {"status": "ALIVE"}))
    window.poll_queues()
    window._refresh_periodic_ui()
    assert "Nominal" not in window.pipeline_health.text()
    status.put(make_message("SURICATA", "WORKER_HEARTBEAT", "UI_SHELL",
                            {"status": "FRESH", "last_stats_time": time.time()}))
    window.poll_queues()
    window._refresh_periodic_ui()
    assert "FRESH" in window.system_suricata.text()
    window.suricata_health["last_stats_time"] = time.time() - 120
    window._refresh_periodic_ui()
    assert "STALE" in window.system_suricata.text()
    window.suricata_health["status"] = "FRESH"
    window.suricata_health["last_stats_time"] = float("nan")
    window._refresh_periodic_ui()
    assert "UNVERIFIED" in window.system_suricata.text()
    window.close()
    app.processEvents()


def test_interactive_stat_card_activates_by_mouse_and_keyboard():
    app = _app()
    activations = []
    card = StatCard("Critical", action_text="Prioritize", on_activate=lambda: activations.append(True))
    card.resize(280, 90)
    card.show()
    app.processEvents()

    QTest.mouseClick(card, Qt.MouseButton.LeftButton)
    QTest.keyClick(card, Qt.Key.Key_Return)

    assert len(activations) == 2
    assert card.focusPolicy() == Qt.FocusPolicy.StrongFocus
    assert card.accessibleName() == "Critical: open details"
    card.close()


def test_posture_cards_route_to_operational_drilldowns(tmp_path):
    app = _app()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    window._record_incident(make_message(
        "DOD_CORE",
        "ARP_ANOMALY",
        "8.8.8.8",
        {"message": "ARP identity anomaly"},
    ))
    window.show()
    app.processEvents()

    QTest.mouseClick(window.card_open, Qt.MouseButton.LeftButton)
    assert window.nav_buttons["Incidents"].isChecked()
    assert window.incident_scope.currentText() == "OPEN INCIDENTS"
    assert window.selected_incident["severity"] == "critical"

    QTest.mouseClick(window.card_critical, Qt.MouseButton.LeftButton)
    assert window.incident_scope.currentText() == "CRITICAL ONLY"
    assert window.incident_detail_model.rowCount() == 1

    window.incidents.set_incident_status(window.selected_incident["incident_id"], "Dismissed")
    window._refresh_incident_views()
    QTest.mouseClick(window.card_critical, Qt.MouseButton.LeftButton)
    assert window.selected_incident is None
    assert window.overview_detail_title.text() == "No matching incident"
    assert window.investigation_focus.text() == "No incident selected"

    QTest.mouseClick(window.card_pending, Qt.MouseButton.LeftButton)
    assert window.nav_buttons["Enforcement"].isChecked()
    assert window.history_thread._mode == "off"

    window._show_page("Investigate")
    assert window.history_thread._mode == "detail"

    window.combo_alerts.setCurrentText("ALERTS ONLY")
    window.combo_nodes.setCurrentText("HIDE SECURE SOURCES")
    window.combo_observation.setCurrentText("HUMAN SIGNAL")
    QTest.mouseClick(window.card_observed, Qt.MouseButton.LeftButton)
    assert window.nav_buttons["Traffic"].isChecked()
    assert window.combo_alerts.currentText() == "ALL EVENTS"
    assert window.combo_nodes.currentText() == "ALL SOURCES"
    assert window.combo_observation.currentText() == "ALL CAPTURED"

    window.close()
    app.processEvents()


def test_observation_filter_rebuilds_existing_traffic_without_new_batch(tmp_path):
    app = _app()
    render_queue = queue.Queue()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        render_queue, queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    base = {
        "time_str": "12:00:00",
        "src": socket.inet_aton("10.0.0.2"),
        "dst": socket.inet_aton("8.8.8.8"),
        "protocol": "TCP",
        "port": 443,
        "size": 517,
        "is_lan_to_lan": False,
    }
    render_queue.put(make_message("DOD_CORE", "RENDER_BATCH", 0, {
        "events": [
            dict(base, web_observation={
                "label": "HUMAN LIKELY", "reason": "new destination",
                "domain": "chatgpt.com",
            }),
            dict(base, web_observation={
                "label": "WEB NOISE", "reason": "regular cadence",
                "domain": "telemetry.example",
            }),
        ],
        "total_ingested": 2,
    }))
    QTest.qWait(200)
    assert window.traffic_model.rowCount() == 2

    window.combo_observation.setCurrentText("HUMAN SIGNAL")
    QTest.qWait(200)

    assert window.traffic_model.rowCount() == 1
    assert window.traffic_model.rows[0]["target"] == "chatgpt.com"
    window.close()
    app.processEvents()


def test_live_raw_tail_keeps_newest_event_first(tmp_path):
    app = _app()
    render_queue = queue.Queue()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        render_queue, queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    base = {
        "src": socket.inet_aton("10.0.0.60"),
        "dst": socket.inet_aton("8.8.8.8"),
        "protocol": "TCP",
        "port": 443,
        "size": 100,
    }
    render_queue.put(make_message("DOD_CORE", "RENDER_BATCH", 0, {
        "events": [dict(base, event_id="old"), dict(base, event_id="new")],
        "total_ingested": 2,
    }))
    QTest.qWait(200)

    assert [event["event_id"] for event in window.drain_thread.raw_events] == ["new", "old"]
    window.close()
    app.processEvents()


def test_priority_observation_survives_packet_tail_load_shedding(tmp_path):
    app = _app()
    render_queue = queue.Queue()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        render_queue, queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    base = {
        "time_str": "12:00:00",
        "src": socket.inet_aton("10.0.0.60"),
        "dst": socket.inet_aton("8.8.8.8"),
        "protocol": "TCP",
        "port": 443,
        "size": 517,
        "is_lan_to_lan": False,
    }
    observation = dict(base, flow_id="flow-priority", web_observation={
        "flow_id": "flow-priority",
        "label": "HUMAN LIKELY",
        "reason": "new destination",
        "domain": "example.com",
    })
    noise = [dict(base, port=53, flow_id=f"noise-{index}") for index in range(200)]
    render_queue.put(make_message("DOD_CORE", "RENDER_BATCH", 0, {
        "events": [observation, *noise],
        "observations": [observation],
        "total_ingested": 201,
    }))
    QTest.qWait(200)

    window.combo_observation.setCurrentText("HUMAN SIGNAL")
    QTest.qWait(200)

    assert window.traffic_model.rowCount() == 1
    assert window.traffic_model.rows[0]["target"] == "example.com"
    window.close()
    app.processEvents()


def test_durable_observation_reloads_after_dashboard_restart(tmp_path):
    app = _app()
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
                "persisted", 10.0, "10.0.0.60", "8.8.8.8", "src", "dst",
                "TCP", 443, "persisted.example", "HUMAN POSSIBLE", 4,
                "new destination", "NIX/MOB", "US", 200,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(db_path),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    QTest.qWait(100)

    window.combo_observation.setCurrentText("HUMAN SIGNAL")
    QTest.qWait(200)

    assert window.traffic_model.rowCount() == 1
    assert window.traffic_model.rows[0]["target"] == "persisted.example"
    window.close()
    app.processEvents()


def test_durable_raw_activity_reloads_after_dashboard_restart(tmp_path):
    app = _app()
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
        conn.execute(
            "INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "persisted-raw", 10.0, "src", "dst", "10.0.0.60", "8.8.8.8",
                "TCP", 5228, "S", 64, 300, "", "US", 4,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(db_path),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
        "LOCAL_PREFIXES": ("10.",),
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    QTest.qWait(200)
    window.combo_observation.setCurrentText("ANY OUTBOUND")
    QTest.qWait(200)

    assert window.traffic_model.rowCount() == 1
    assert window.traffic_model.rows[0]["source"] == "10.0.0.60"
    assert window.traffic_model.rows[0]["signal"] == "OUTBOUND UNCLASSIFIED"
    window.close()
    app.processEvents()


def test_active_observation_filter_reconciles_sqlite_after_ipc_loss(tmp_path):
    app = _app()
    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE web_observations (
            flow_id TEXT, timestamp REAL, src_ip TEXT, dst_ip TEXT,
            mac_src TEXT, mac_dst TEXT, protocol TEXT, port INTEGER,
            domain TEXT, label TEXT, score INTEGER, reason TEXT,
            os_guess TEXT, country TEXT, size_bytes INTEGER
        )
    """)
    conn.commit()
    conn.close()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(db_path),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
        "UI_OBSERVATION_RELOAD_SEC": 1,
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    window.combo_observation.setCurrentText("HUMAN SIGNAL")
    QTest.qWait(100)

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO web_observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "reconciled", 11.0, "10.0.0.61", "1.1.1.1", "src", "dst",
            "UDP", 443, "reconciled.example", "HUMAN LIKELY", 6,
            "irregular timing", "NIX/MOB", "US", 300,
        ),
    )
    conn.commit()
    conn.close()
    QTest.qWait(1200)

    assert window.traffic_model.rowCount() == 1
    assert window.traffic_model.rows[0]["target"] == "reconciled.example"
    window.close()
    app.processEvents()


def test_sensor_coverage_status_marks_endpoint_capture_as_partial(tmp_path):
    app = _app()
    worker_status = queue.Queue()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), worker_status, config=config,
    )
    worker_status.put(make_message("DOD_CORE", "SENSOR_COVERAGE", "UI_SHELL", {
        "active_sources": {"malformed": True},
        "web_sources": 3,
        "window_sec": 900,
        "topology": "endpoint",
    }))
    worker_status.put(make_message("DOD_CORE", "SENSOR_COVERAGE", "UI_SHELL", {
        "active_sources": 8,
        "web_sources": 3,
        "window_sec": 900,
        "topology": "endpoint",
    }))

    window.poll_queues()

    assert "COVERAGE PARTIAL" in window.coverage_status.text()
    assert "8 observed LAN" in window.coverage_status.text()
    window.close()
    app.processEvents()


def test_mirror_capture_does_not_claim_complete_coverage_without_assertion(tmp_path):
    app = _app()
    worker_status = queue.Queue()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), worker_status, config=config,
    )
    worker_status.put(make_message("DOD_CORE", "SENSOR_COVERAGE", "UI_SHELL", {
        "active_sources": 8,
        "web_sources": 3,
        "window_sec": 900,
        "topology": "mirror",
        "coverage_assertion": "unverified",
    }))

    window.poll_queues()

    assert "COVERAGE UNVERIFIED" in window.coverage_status.text()
    window.close()
    app.processEvents()


def test_secure_node_filter_rebuilds_existing_traffic_without_new_batch(tmp_path):
    app = _app()
    render_queue = queue.Queue()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
        "SECURE_NODES": {"Console1": {"ips": ["10.0.0.15"]}},
    }
    window = OperationsDashboard(
        render_queue, queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    base = {
        "time_str": "12:00:00",
        "dst": socket.inet_aton("8.8.8.8"),
        "protocol": "TCP",
        "port": 443,
        "size": 517,
        "is_lan_to_lan": False,
    }
    render_queue.put(make_message("DOD_CORE", "RENDER_BATCH", 0, {
        "events": [
            dict(base, src=socket.inet_aton("10.0.0.15")),
            dict(base, src=socket.inet_aton("10.0.0.60")),
        ],
        "total_ingested": 2,
    }))
    QTest.qWait(200)
    assert window.traffic_model.rowCount() == 2

    window.combo_nodes.setCurrentText("HIDE SECURE SOURCES")
    QTest.qWait(200)

    assert window.traffic_model.rowCount() == 1
    assert window.traffic_model.rows[0]["source"] == "10.0.0.60"
    window.close()
    app.processEvents()


def test_autonomous_mode_keeps_arp_containment_approval_gated(tmp_path):
    app = _app()
    config = {
        "MITIGATION_ENABLED": False,
        "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"),
        "LOG_TO_CONSOLE": False,
    }
    window = OperationsDashboard(
        queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config,
    )
    effector = RecordingQuarantineEffector(mac_table={
        "10.0.0.1": "02:00:00:00:03:01",
        "10.0.0.34": "1c:53:f9:00:00:07",
    })
    window.quarantine = Quarantine(effector, gateway_ip="10.0.0.1", auto=True)
    window.response_mode = "autonomous"

    window._handle_quarantine_alert(make_message(
        "DOD_CORE",
        "ARP_ANOMALY",
        "UI_SHELL",
        {
            "message": "confirmed ARP ownership conflict",
            "offender_ip": "10.0.0.34",
            "offender_mac": "1c:53:f9:00:00:07",
            "offender_owned_ips": ["10.0.0.77"],
        },
    ))
    _settle(window)

    assert "10.0.0.77" in window.quarantine.pending and "10.0.0.34" not in window.quarantine.pending
    assert window.quarantine.active == {}
    assert effector.poisoned == []
    for owned in ([], ["10.0.0.77", "10.0.0.78"]):  # unattributable: queue nothing
        window.quarantine.pending.clear()
        window._handle_quarantine_alert(make_message("DOD_CORE", "ARP_ANOMALY", "UI_SHELL", {
            "message": "x", "offender_ip": "10.0.0.34", "offender_mac": "1c:53:f9:00:00:07",
            "offender_owned_ips": owned}))
        assert window.quarantine.pending == {}
    window.close()
    app.processEvents()


def test_evidence_workflow_survives_console_restart(tmp_path, monkeypatch):
    from netwatch_evidence import EvidenceRecorder
    from netwatch_evidence_catalog import verify_export

    app = _app()
    path = tmp_path / "security.db"
    root = tmp_path / "evidence"
    recorder = EvidenceRecorder(root, catalog_path=path, pre_sec=0, post_sec=0)
    recorder.add(100, b"packet")
    recorder.request({"trigger_ts": 100, "action": "ALERT"}, now=100)
    recorder.poll(now=100, force=True)
    recorder.write_jobs.join()
    result = recorder.poll(now=100)[0]
    recorder.close()
    config = {"INCIDENT_DB": str(path), "EVIDENCE_DIR": str(root), "MITIGATION_ENABLED": False,
              "QUARANTINE_ENABLED": False, "DB_NAME": str(tmp_path / "packets.db"),
              "DEVICE_LEDGER": str(tmp_path / "devices.json"), "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config)
    window._show_page("Evidence")
    window._refresh_evidence(force=True)
    window._evidence_selected(window.evidence_model.index(0, 0))
    window._evidence_action("hold")
    assert window.evidence_task is None
    window.evidence_reason.setText("Keep for investigation")

    def operation(action):
        window._evidence_action(action)
        assert window.evidence_task.wait(5000)
        app.processEvents()
        assert window.evidence_task is None

    operation("hold")
    assert window.evidence_catalog.get(result["evidence_id"])["held"]
    operation("verify")
    destination = tmp_path / "export.zip"
    monkeypatch.setattr("netwatch_ui.QFileDialog.getSaveFileName", lambda *a: (str(destination), ""))
    operation("export")
    assert verify_export(destination)["ok"]
    window.close()
    app.processEvents()
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config)
    window._refresh_evidence(force=True)
    assert window.evidence_model.rows[0]["held"]
    window._evidence_selected(window.evidence_model.index(0, 0))
    window.evidence_reason.setText("Investigation concluded")
    operation("release")
    assert not window.evidence_catalog.get(result["evidence_id"])["held"]
    window.close()


def test_control_source_health_and_review_survive_queue_redelivery(tmp_path):
    app = _app()
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "SENSOR_ID": "sensor-a", "NIC_INTERFACE": "mirror",
              "MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False, "DB_NAME": str(tmp_path / "packets.db"),
              "DEVICE_LEDGER": str(tmp_path / "devices.json"), "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    status = queue.Queue()
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), status, config=config)
    window._refresh_periodic_ui()
    assert "Awaiting collector" in window.source_health_label.text()
    collector = DurableIncidentStore(config["INCIDENT_DB"])
    key = "CONTROL:sensor-a:mirror"
    collector.record_source_health(key, {"state": "running", "status": "RUNNING", "accepted": 3,
                                         "dropped": 1, "backlog": 0, "policy": {}})
    window._refresh_periodic_ui()
    assert "committed 3" in window.source_health_label.text()
    assert "unconfigured" in window.source_health_label.text()
    assert "ARP replay: Awaiting analyzer" in window.source_health_label.text()
    collector.record_source_health("ANALYSIS:ARP:v1", {"status": "DEGRADED"})
    window._refresh_periodic_ui()
    assert "ARP replay: DEGRADED" in window.source_health_label.text()
    collector.record_source_health("ANALYSIS:ARP:v1", {"status": "RUNNING"}, now=time.time() - 60)
    window._refresh_periodic_ui()
    assert "ARP replay: STALE" in window.source_health_label.text()
    payload = make_message("CONTROL", "CONTROL_REVIEW", "SYSTEM", {
        "source_event_id": "control-fixture", "sensor_id": "sensor-a", "containment_eligible": False,
        "message": "Router advertisement needs review", "severity": "anomaly",
    }, correlation_id="control-fixture")
    collector.add(payload)
    status.put(payload)
    status.put(payload)
    window.poll_queues()
    window._refresh_periodic_ui()
    case = next(row for row in window.incident_model.rows if row["action"] == "CONTROL_REVIEW")
    assert case["count"] == 1 and case["target"] == "system"
    collector.record_source_health(key, {"state": "running", "status": "RUNNING"}, now=time.time() - 60)
    window._refresh_periodic_ui()
    assert "STALE" in window.source_health_label.text()
    collector.close()
    window.close()
    app.processEvents()


def test_worker_health_requires_observed_progress_and_driver_measurement(tmp_path):
    app = _app()
    status, db_status = queue.Queue(), queue.Queue()
    config = {"CONTROL_CAPTURE_ENABLED": False, "ARP_DETECTION_ENABLED": False,
              "MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False,
              "DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "DEVICE_LEDGER": str(tmp_path / "devices.json"), "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), db_status, status, config=config)
    window._refresh_periodic_ui()
    assert "Awaiting heartbeat" in window.system_sniffer.text()
    assert "Unverified" in window.capture_health.text()
    assert "Nominal" not in window.pipeline_health.text()
    for source in ("IO_WORKER", "DOD_CORE"):
        status.put(make_message(source, "WORKER_HEARTBEAT", "UI_SHELL", {"status": "IDLE"}))
    db_status.put(make_message("DB_WORKER", "DB_HEARTBEAT", "UI_SHELL"))
    window.poll_queues()
    window._refresh_periodic_ui()
    assert "Idle" in window.system_sniffer.text() and window.incidents.open_count() == 0
    assert "Unverified" in window.capture_health.text()
    status.put(make_message("IO_WORKER", "WORKER_HEARTBEAT", "UI_SHELL",
                            {"status": "IDLE", "capture_stats": {"available": True, "timestamp": time.time()}}))
    window.poll_queues()
    window._refresh_periodic_ui()
    assert "Measured" in window.capture_health.text() and "Nominal" in window.pipeline_health.text()
    status.put(make_message("IO_WORKER", "WORKER_HEARTBEAT", "UI_SHELL",
                            {"status": "CAPTURE_UNAVAILABLE", "capture_stats": "invalid"}))
    window.poll_queues()
    window._refresh_periodic_ui()
    assert "Read unavailable" in window.system_sniffer.text() and "Nominal" not in window.pipeline_health.text()
    window.close()
    app.processEvents()


def test_console_close_uses_ordered_callback_and_persists_unverified_drain(tmp_path):
    app = _app()
    signal = threading.Event()
    called = []
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "DB_NAME": str(tmp_path / "packets.db"),
              "MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False,
              "DEVICE_LEDGER": str(tmp_path / "devices.json"), "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    def shutdown():
        assert not signal.is_set()
        called.append(True)
        return {"ordered_drain": False, "forced_workers": ["core"]}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(),
                                 config=config, shutdown_event=signal, shutdown_callback=shutdown)
    window.close()
    app.processEvents()
    assert called == [True]
    store = DurableIncidentStore(config["INCIDENT_DB"])
    assert store.snapshot()[0]["action"] == "RUNTIME_COLLECTION_GAP"
    store.close()


def test_desktop_displays_durable_spool_gap_without_status_delivery(tmp_path):
    from netwatch_spool import TelemetrySpool

    app = _app()
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "MITIGATION_ENABLED": False,
              "QUARANTINE_ENABLED": False, "DB_NAME": str(tmp_path / "packets.db"),
              "DEVICE_LEDGER": str(tmp_path / "devices.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config)
    store = DurableIncidentStore(config['INCIDENT_DB'])
    spool = TelemetrySpool(str(tmp_path / 'spool.db'))
    spool._record_admission_refusal(100, 7, 3, 0, spool.max_bytes)
    spool.transfer_gaps(store)
    spool.transfer_gaps(store)
    window._refresh_periodic_ui()
    rows = [row for row in window.incident_model.rows if row['action'] == 'SPOOL_COLLECTION_GAP']
    assert len(rows) == 1
    assert '7 rows, 3 observations' in rows[0]['detail']
    assert len(store.detections(rows[0]['incident_id'])) == 1
    spool.close()
    store.close()
    window.close()
    app.processEvents()


def _bare_window(tmp_path, **extra):
    config = {
        "MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False,
        "DB_NAME": str(tmp_path / "missing-ledger.db"),
        "DEVICE_LEDGER": str(tmp_path / "missing-devices.json"),
        "RESPONSE_MODE_LEDGER": str(tmp_path / "response-mode.json"),
        "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False,
    }
    return OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config, **extra)


def test_unblock_firewall_failure_keeps_entry_and_reports(tmp_path):
    from netwatch_mitigation import FirewallError, Mitigator

    class Failing:
        def block(self, ip, rule_name):
            pass

        def unblock(self, rule_name):
            raise FirewallError("netsh timeout")

    app = _app()
    window = _bare_window(tmp_path)
    window.mitigator = Mitigator(Failing(), auto=True)
    window.mitigator.request("8.8.4.4", "test")
    assert "8.8.4.4" in window.mitigator.active
    window._refresh_enforcement()
    window.active_list.setCurrentRow(0)
    window._unblock_selected()  # must not raise
    _settle(window)
    assert "8.8.4.4" in window.mitigator.active
    assert "unblock of 8.8.4.4 failed" in window.audit_log.toPlainText()
    window.close()
    app.processEvents()


def test_engine_side_quarantine_release_resolves_incident_and_audits(tmp_path):
    app = _app()
    window = _bare_window(tmp_path)
    window.quarantine = Quarantine(RecordingQuarantineEffector(), gateway_ip="10.0.0.1", auto=True)
    window.quarantine.enforce("10.0.0.34", "test", now=time.time())
    window._q_seen = {"10.0.0.34"}
    calls = []
    window.incidents.set_target_status = lambda ip, status, detail: calls.append((ip, status))
    window.quarantine.release("10.0.0.34")  # as the engine's own thread would
    window.last_reconcile = 0
    window.poll_queues()
    _settle(window)
    assert calls == [("10.0.0.34", "Resolved")]
    assert "released 10.0.0.34 by engine" in window.audit_log.toPlainText()
    window.close()
    app.processEvents()


def test_attached_console_shows_service_reported_mode(tmp_path):
    class Client:
        _lock = threading.Lock()
        data = {"health": {"response_mode": "autonomous"}}
        state = "Connected"
        last_success = None
        poll_interval = 1
        gaps = []

        def source_health(self, key):
            return {}

        def snapshot(self):
            return []

        def open_count(self):
            return 0

        def critical_count(self):
            return 0

        def close(self):
            pass

    app = _app()
    window = _bare_window(tmp_path, service_client=Client())
    window._refresh_periodic_ui()
    assert window.response_mode == "autonomous"
    assert window.mode_selector.currentData() == "autonomous"
    assert not os.path.exists(window.config["RESPONSE_MODE_LEDGER"]) or "autonomous" not in open(
        window.config["RESPONSE_MODE_LEDGER"]).read()
    window.close()
    app.processEvents()


def test_attached_case_history_failure_is_visible(tmp_path):
    class Client:
        state = "Disconnected / stale"

        def close(self):
            pass

    app = _app()
    window = _bare_window(tmp_path)
    window.service_client = Client()
    window.incidents.audit = lambda incident_id: []  # what ServiceClient.audit returns on timeout
    window._refresh_case_audit("x")
    _settle(window)
    assert "unreachable" in window.case_audit.toPlainText()
    window.service_client = None
    window.close()
    app.processEvents()


# --- desktop alert-to-block path (TD-006) -------------------------------------------------

class _FakeFirewall:
    def __init__(self, dry_run=False):
        self.dry_run, self.blocked = dry_run, []

    def block(self, ip, rule_name):
        self.blocked.append(ip)

    def unblock(self, rule_name):
        pass


def _response_window(tmp_path, mode, firewall, quarantine=None):
    from netwatch_mitigation import Mitigator

    config = {"MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False,
              "DB_NAME": str(tmp_path / "missing-ledger.db"), "DEVICE_LEDGER": str(tmp_path / "d.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"), "LOG_DIR": str(tmp_path / "logs"),
              "LOG_TO_CONSOLE": False}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(), config=config)
    window.mitigator = Mitigator(effector=firewall)
    window.quarantine = quarantine
    window.response_mode = mode
    return window


def _alert(action, target, **data):
    return make_message("DOD_CORE", action, target, {"message": "m", **data})


@pytest.mark.parametrize("mode,blocked,pending", [
    ("ids_only", [], []), ("ready", [], ["8.8.4.4"]), ("autonomous", ["8.8.4.4"], [])])
def test_alert_reaches_the_firewall_per_response_mode(tmp_path, mode, blocked, pending):
    app = _app()
    firewall = _FakeFirewall()
    window = _response_window(tmp_path, mode, firewall)
    window._handle_mitigation(_alert("ALERT", bytes([8, 8, 4, 4])))
    window._handle_mitigation(_alert("ALERT", "UI_SHELL"))  # not an address: ignored
    window._handle_mitigation(_alert("DNS_ANOMALY", bytes([8, 8, 4, 4])))  # wrong action: ignored
    _settle(window)
    assert (firewall.blocked, list(window.mitigator.pending)) == (blocked, pending)
    window.close()
    app.processEvents()


@pytest.mark.parametrize("mode,direction,dry,expect", [
    ("ids_only", "egress", False, ("", "")),
    ("ready", "egress", False, ("pending", "")),
    ("autonomous", "egress", False, ("", "fw")),
    ("autonomous", "egress", True, ("", "fw")),
    ("autonomous", "lateral", False, ("", "q")),
])
def test_policy_decision_routes_lateral_to_quarantine_and_labels_dry_run(tmp_path, mode, direction, dry, expect):
    app = _app()
    firewall = _FakeFirewall(dry_run=dry)
    q_effector = RecordingQuarantineEffector(mac_table={"10.0.0.1": "02:00:00:00:03:01", "10.0.0.77": "1c:53:f9:00:00:07"})
    q_effector.dry_run = dry
    window = _response_window(tmp_path, mode, firewall, Quarantine(q_effector, gateway_ip="10.0.0.1"))
    ip = "10.0.0.77" if direction == "lateral" else "8.8.4.4"
    notes = []
    window._write_alert = lambda text, _kind="info": notes.append(text)
    window._handle_policy_decision(_alert("POLICY_DECISION", bytes(int(p) for p in ip.split(".")),
                                          configured_action="block", direction=direction))
    _settle(window)
    engine = window.quarantine if direction == "lateral" else window.mitigator
    assert (ip in engine.pending) == (expect[0] == "pending")
    assert (ip in engine.active) == (expect[1] in ("fw", "q"))
    if expect[1]:
        assert (firewall.blocked == [ip]) == (direction != "lateral")
    if expect[1]:
        assert notes == [f"POLICY: {'simulated' if dry else 'enforced'} block for {ip}"]
    other = window.mitigator if direction == "lateral" else window.quarantine
    assert not (other.active or other.pending)  # never cross-routed
    window._handle_policy_decision(_alert("POLICY_DECISION", bytes([8, 8, 4, 4]), configured_action="allow"))
    window.close()
    app.processEvents()


def test_attached_case_calls_run_off_the_gui_thread_and_lock_buttons(tmp_path):
    release, entered, threads = threading.Event(), threading.Event(), []

    class Client:
        state = "Connected"

        def close(self):
            pass

        def audit(self, incident_id):
            threads.append(threading.current_thread())
            entered.set()
            release.wait(5)
            return [{"timestamp": 1.0, "actor": "svc", "operation": "detection", "body": {}}]

    app = _app()
    window = _bare_window(tmp_path)
    window.ui_timer.stop()  # its attached-mode refresh needs a full ServiceClient
    window.service_client = Client()
    window.incidents.audit = window.service_client.audit  # keep the local store for the KPI cards
    window.selected_incident = {"incident_id": "x"}
    window._refresh_case_audit("x")  # returns while audit() is still blocked
    assert entered.wait(5) and not release.is_set()
    assert not any(button.isEnabled() for button in window.case_buttons)
    release.set()
    _settle(window)
    assert threads[0] is not threading.main_thread()
    assert all(button.isEnabled() for button in window.case_buttons)
    assert "Detection recorded" in window.case_audit.toPlainText()
    window.service_client = None
    window.close()
    app.processEvents()


def test_alert_effects_shed_at_backlog_cap(tmp_path):
    release = threading.Event()

    class Blocking(_FakeFirewall):
        def block(self, ip, rule_name):
            release.wait(10)
            super().block(ip, rule_name)

    app = _app()
    window = _response_window(tmp_path, "autonomous", Blocking())
    try:
        for i in range(300):
            window._handle_mitigation(_alert("ALERT", bytes([10, 0, i // 250, i % 250 + 1])))
        assert window._effects_pending <= 256
        assert getattr(window, "_effects_shed", 0) == 44
        policy = _alert("POLICY_DECISION", bytes([9, 9, 9, 9]), configured_action="block")
        window._handle_policy_decision(policy)  # no-drop verdicts are never shed
        assert window._effects_pending == 257
    finally:
        release.set()
    _settle(window, timeout=15)
    window.close()
    app.processEvents()


def test_poll_tick_bounds_alerts_refreshes_once_and_blocks_off_gui_thread(tmp_path):
    threads = []

    class Firewall(_FakeFirewall):
        def block(self, ip, rule_name):
            threads.append(threading.current_thread())
            super().block(ip, rule_name)

    app = _app()
    window = _response_window(tmp_path, "autonomous", Firewall())
    window.poll_timer.stop()  # this test drives the ticks itself
    window.last_reconcile = time.time()  # keep the reconcile out of this tick
    for i in range(120):
        window.alert_queue.put(_alert("ALERT", bytes([8, 8, 4, i + 1])))
    replaced = []
    real_replace = window.incident_model.replace
    window.incident_model.replace = lambda rows: (replaced.append(1), real_replace(rows))[1]
    window.poll_queues()
    assert window.alert_queue.qsize() == 70  # ALERTS_PER_TICK drained, rest next tick
    assert len(replaced) == 1
    _settle(window)
    assert len(window.mitigator.active) == 50
    assert all(thread is not threading.main_thread() for thread in threads)
    window.close()
    app.processEvents()


def test_poll_tick_bounds_status_and_policy_drains(tmp_path, monkeypatch):
    app = _app()
    window = _response_window(tmp_path, "ids_only", _FakeFirewall())
    window.poll_timer.stop()  # this test drives the tick itself
    window.last_reconcile = time.time()
    monkeypatch.setattr(OperationsDashboard, "DRAIN_PER_TICK", 3, raising=False)
    window.policy_queue = queue.Queue()
    for _ in range(5):
        window.db_status_queue.put(make_message("DB_WORKER", "DB_HEARTBEAT", "db", {}))
        window.worker_status_queue.put(make_message("SNIFFER", "NOOP", "x", {}))
        window.policy_queue.put(make_message("DOD_CORE", "NOOP", "x", {}))
    window.poll_queues()
    assert window.db_status_queue.qsize() == 2
    assert window.worker_status_queue.qsize() == 2
    assert window.policy_queue.qsize() == 2
    window.close()
    app.processEvents()


def test_render_drain_takes_at_most_cap_per_pass(monkeypatch):
    import netwatch_ui
    from netwatch_ui import RenderDrainThread

    monkeypatch.setattr(RenderDrainThread, "DRAIN_PER_TICK", 5, raising=False)
    q = queue.Queue()
    for i in range(7):
        q.put({"events": [], "n": i})
    thread = RenderDrainThread(q, {}, threading.Lock(), db_path=None)
    seen = []

    def fake(payloads, **kwargs):
        seen.append(len(payloads))
        thread.stop()
        return [], [], 0

    monkeypatch.setattr(netwatch_ui, "newest_render_data", fake)
    thread.run()  # synchronous: stop() ends it after the first pass
    assert seen[0] == 5
    assert q.qsize() == 2


def test_activity_reload_does_not_resurface_evicted_rows_or_misorder(tmp_path):
    from netwatch_ui import RenderDrainThread

    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE network_events (
        uuid TEXT, timestamp REAL, mac_src TEXT, mac_dst TEXT, src_ip TEXT, dst_ip TEXT,
        protocol TEXT, port INTEGER, tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER,
        sni_domain TEXT, country TEXT, packet_count INTEGER)""")
    for uuid, ts in (("a", 10.0), ("b", 20.0), ("c", 30.0)):
        conn.execute("INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (uuid, ts, "s", "d", "10.0.0.60", "8.8.8.8", "TCP", 443, "S", 64, 1, "", "US", 1))
    conn.commit()
    conn.close()
    thread = RenderDrainThread(queue.Queue(), {}, threading.Lock(), max_events=2, db_path=str(db_path),
                               local_prefixes=("10.",))
    thread._reload_persisted_activity()
    assert [e["event_id"] for e in thread.raw_events] == ["c", "b"]
    thread._remember_raw({"event_id": "live", "timestamp": 40.0})  # evicts b
    assert thread._reload_persisted_activity() == []  # b is evicted, not new
    assert [e["event_id"] for e in thread.raw_events] == ["live", "c"]


def test_dead_core_shard_or_stalled_merge_raises_core_heartbeat_stale(tmp_path):
    app = _app()
    status, db_status = queue.Queue(), queue.Queue()
    config = {"CONTROL_CAPTURE_ENABLED": False, "ARP_DETECTION_ENABLED": False,
              "MITIGATION_ENABLED": False, "QUARANTINE_ENABLED": False, "CORE_SHARDS": 2,
              "DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "DEVICE_LEDGER": str(tmp_path / "devices.json"), "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"),
              "LOG_DIR": str(tmp_path / "logs"), "LOG_TO_CONSOLE": False}
    window = OperationsDashboard(queue.Queue(), queue.Queue(), db_status, status, config=config)

    def beat(*sources, state="ALIVE"):
        status.put(make_message("IO_WORKER", "WORKER_HEARTBEAT", "UI_SHELL", {"status": "ALIVE"}))
        for source in sources:
            status.put(make_message(source, "WORKER_HEARTBEAT", "UI_SHELL", {"status": state}))
        db_status.put(make_message("DB_WORKER", "DB_HEARTBEAT", "UI_SHELL"))
        window.poll_queues()
        return {c["action"]: c["status"] for c in window.incidents.snapshot()}.get("CORE_HEARTBEAT_STALE")

    assert beat("DOD_CORE", "DOD_CORE_0", "DOD_CORE_1") is None
    window.core_heartbeats["DOD_CORE_1"] = time.time() - 20  # shard 1 died: its heartbeats stopped
    # The merge, waiting on that shard, still heartbeats but reports its loop stalled.
    assert beat("DOD_CORE", state="DEADLOCK_DETECTED") not in (None, "Recovered")
    assert beat("DOD_CORE", "DOD_CORE_0", "DOD_CORE_1") == "Recovered"
    window.close()
    app.processEvents()
