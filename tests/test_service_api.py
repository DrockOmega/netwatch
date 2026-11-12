import json
import multiprocessing as mp
import os
import queue
import socket
import stat
import threading
import time
import uuid
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest

import netwatch_api
from netwatch_api import ServiceAPI, load_secret
from netwatch_client import ServiceClient
from netwatch_core import make_message
from netwatch_security_store import DurableIncidentStore
from netwatch_ui_state import service_connection_label


@pytest.fixture
def service(tmp_path):
    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence"), "LOG_DIR": str(tmp_path / "logs"),
              "LOG_TO_CONSOLE": False, "DEVICE_LEDGER": str(tmp_path / "devices.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json")}
    store = DurableIncidentStore(config["INCIDENT_DB"])
    supervisor = SimpleNamespace(store=store, runtime=SimpleNamespace(config=config))
    secret = load_secret(tmp_path / "api.secret", create=True)
    api = ServiceAPI(supervisor, secret, port=0).start()
    client = ServiceClient(f"http://127.0.0.1:{api.server.server_port}", secret, timeout=0.3)
    yield api, client, config, secret
    api.close()
    store.close()


def test_secret_owner_permissions_and_no_rotation(tmp_path):
    path = tmp_path / "secret"
    secret = load_secret(path, create=True)
    assert len(secret) == 32
    assert load_secret(path, create=True) == secret
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        path.chmod(0o644)
        with pytest.raises(ValueError):
            load_secret(path)
        path.chmod(0o600)
        link = tmp_path / "link"
        link.symlink_to(path)
        with pytest.raises((OSError, ValueError)):
            load_secret(link)


@pytest.mark.parametrize("authorization", [None, "Bearer wrong"])
def test_auth_rejects_without_state(service, authorization):
    _, client, _, _ = service
    headers = {} if authorization is None else {"Authorization": authorization}
    for endpoint in ("health", "cases", "sources", "flows/x"):
        request = Request(client.url + "/v1/" + endpoint, headers=headers)
        with pytest.raises(HTTPError) as rejected:
            build_opener(ProxyHandler({})).open(request)
        assert rejected.value.code == 401
        assert b'"instance"' not in rejected.value.read()
    for method in ("POST", "PUT", "HEAD", "DELETE"):
        request = Request(client.url + "/v1/cases", headers=headers, method=method)
        with pytest.raises(HTTPError) as rejected:
            build_opener(ProxyHandler({})).open(request)
        assert rejected.value.code == 401
    assert client.request("health")["data"]["actions"]


def test_non_loopback_requires_explicit_config(service, caplog):
    api, _, config, secret = service
    with pytest.raises(ValueError, match="loopback"):
        ServiceAPI(api.supervisor, secret, host="0.0.0.0", port=0)
    allowed = ServiceAPI(api.supervisor, secret, host="0.0.0.0", port=0,
                         config={**config, "SERVICE_API_ALLOW_NON_LOOPBACK": True})
    allowed.close()
    assert "Non-loopback" in caplog.text


def test_versioned_reads_workflow_and_preview_never_enforce(service, monkeypatch):
    from netwatch_mitigation import RecordingFirewall
    from netwatch_quarantine import ArpQuarantineEffector, RecordingQuarantineEffector

    def forbidden(*args, **kwargs):
        pytest.fail("API called a response effector")
    for cls in (RecordingFirewall, ArpQuarantineEffector, RecordingQuarantineEffector):
        monkeypatch.setattr(cls, "__init__", forbidden)
    api, client, _, _ = service
    case = api.store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "fixture", "severity": "critical"}))
    api.store.add(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {"message": "fixture gap"}))
    api.store.record_source_health("RUNTIME:SERVICE", {"status": "DEGRADED", "workers": {"core": "STALE"}})
    normalized = {"event_id": "fixture", "source": "fixture", "sensor_id": "test", "event_type": "dns",
                  "event_time": time.time(), "received_at": time.time()}
    api.store.accept_source_record("fixture", {"offset": 1}, normalized, {"dns": "example.test"})
    from netwatch_evidence_catalog import file_digest, write_manifest

    capture = api.catalog.directory / "capture.pcap"
    capture.write_bytes(bytes(24))
    manifest = {"evidence_id": uuid.uuid4().hex, "filename": capture.name, "created_at": time.time(),
                "file_bytes": 24, "sha256": file_digest(capture)}
    write_manifest(str(capture) + ".manifest.json", manifest)
    api.catalog.register(manifest)
    assert client.request("evidence")["data"][0]["evidence_id"] == manifest["evidence_id"]
    for endpoint in ("health", "cases", "detections", "sources", "collection-health", "gaps", "evidence", "workflow"):
        result = client.request(endpoint, case=case["incident_id"])
        assert result["version"] == 1
        assert result["instance"] == api.instance
        assert result["data"] is not None
    assert client.request("sources")["data"][0]["normalized"]["event_id"] == "fixture"
    assert client.request("gaps")["data"]
    assert client.request("cases", {"case": case["incident_id"], "assignment": "operator", "acknowledge": True})["data"]
    audit = client.request("workflow", case=case["incident_id"])["data"][-1]
    assert audit["actor"] == "authenticated-console"
    assert audit["body"]["assignment"] == "operator"
    with pytest.raises(HTTPError):
        client.request("cases", {"case": case["incident_id"], "response": "enforce"})
    with pytest.raises(HTTPError):
        client.request("firewall", {"target": "8.8.8.8"})


def test_restart_reconnect_marks_stale_and_gap(service):
    api, client, _, secret = service
    assert client.poll(now=0)
    old_instance = client.instance
    api.close()
    assert not client.poll(now=2)
    assert client.state == "Disconnected / stale"
    assert not client.poll(now=2.5)  # Bounded backoff does not spin.
    replacement = ServiceAPI(api.supervisor, secret, port=api.server.server_port).start()
    try:
        assert client.poll(now=4)
        assert client.instance != old_instance
        assert client.gaps[-1]["service_restarted"]
        assert "gap" in service_connection_label(client)
        assert service_connection_label(client, now=client.last_success + 10) == "Disconnected / stale"
    finally:
        replacement.close()


def test_attached_console_uses_api_and_never_owns_effectors(service, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    from netwatch_ui import OperationsDashboard

    api, client, config, _ = service
    case = api.store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "service detection"}))
    assert client.poll(now=0)
    def forbidden(*args):
        pytest.fail("attached console initialized local effectors")
    monkeypatch.setattr(OperationsDashboard, "_build_mitigator", forbidden)
    monkeypatch.setattr(OperationsDashboard, "_build_quarantine", forbidden)
    app = QApplication.instance() or QApplication([])
    window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(),
                                 config={**config, "MITIGATION_ENABLED": True, "QUARANTINE_ENABLED": True},
                                 service_client=client)
    try:
        window._refresh_periodic_ui()
        assert "Connected" in window.sensor_health.text()
        assert window.incident_model.rowCount() == 1
        window._incident_selected(window.incident_model.index(0, 0))
        assert "service detection" in window.case_evidence.toPlainText()
        window.case_assignment.setText("operator")
        window._save_case()
        deadline = time.monotonic() + 5  # case writes run off the GUI thread
        while window._effects_pending and time.monotonic() < deadline:
            app.processEvents()
        assert api.store.get(case["incident_id"])["assignment"] == "operator"
        assert window.mitigator is None and window.quarantine is None
        assert not window.mode_selector.isEnabled()
        window.started_at = 0
        window.poll_queues()  # No phantom local-worker failures.
        client.state = "Disconnected / stale"
        window._refresh_periodic_ui()
        assert "stale" in window.sensor_health.text()
    finally:
        window.close()
        app.processEvents()


def _api_child(config, secret, port, ready):
    store = DurableIncidentStore(config["INCIDENT_DB"])
    supervisor = SimpleNamespace(store=store, runtime=SimpleNamespace(config=config))
    api = ServiceAPI(supervisor, secret, port=port).start()
    ready.send(api.server.server_port)
    ready.close()
    api.thread.join()


def test_client_background_recovers_after_process_kill(service):
    _, _, config, secret = service
    context = mp.get_context("spawn")
    def launch(port):
        reader, writer = context.Pipe(duplex=False)
        process = context.Process(target=_api_child, args=(config, secret, port, writer))
        process.start()
        writer.close()
        try:
            assert reader.poll(10), "API child did not start"
            return process, reader.recv()
        except BaseException:
            process.terminate()
            process.join(5)
            raise
        finally:
            reader.close()
    def await_state(client, expected):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and client.state != expected:
            time.sleep(0.02)
        assert client.state == expected
    process, port = launch(0)
    client = ServiceClient(f"http://127.0.0.1:{port}", secret, timeout=0.3, poll_interval=0.05, max_backoff=0.2).start()
    try:
        await_state(client, "Connected")
        original = client.instance
        process.kill()
        process.join(5)
        await_state(client, "Disconnected / stale")
        process, _ = launch(port)
        await_state(client, "Connected")
        assert client.instance != original
        assert client.gaps[-1]["service_restarted"]
    finally:
        client.close()
        if process.is_alive():
            process.terminate()
        process.join(5)


def test_ipv6_loopback_contract(service):
    api, _, _, secret = service
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable on this host")
    try:
        ipv6 = ServiceAPI(api.supervisor, secret, host="::1", port=0).start()
    except OSError:
        pytest.skip("IPv6 loopback unavailable on this host")
    try:
        client = ServiceClient(f"http://[::1]:{ipv6.server.server_port}", secret)
        assert client.request("health")["version"] == 1
    finally:
        ipv6.close()


def test_client_refuses_remote_urls_and_credential_redirects():
    from netwatch_client import NoRedirect

    with pytest.raises(ValueError):
        ServiceClient("http://example.com", bytes(32))
    with pytest.raises(ValueError, match="redirects"):
        NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.com")


def test_api_exposes_exact_spool_losses_and_health(service):
    from netwatch_spool import TelemetrySpool

    api, client, config, _ = service
    spool = TelemetrySpool(str(os.path.join(os.path.dirname(config['DB_NAME']), 'spool.db')))
    spool._record_admission_refusal(100, 17, 9, 0, spool.max_bytes)
    spool.transfer_gaps(api.store)
    spool.transfer_gaps(api.store)
    gaps = client.request('gaps')['data']
    assert len(gaps) == 1
    assert gaps[0]['action'] == 'SPOOL_COLLECTION_GAP'
    assert (gaps[0]['dropped_rows'], gaps[0]['dropped_observations']) == (17, 9)
    health = client.request('collection-health')['data']['SPOOL:' + spool.identity]
    assert health['pending_batches'] == 0 and health['pending_bytes'] == 0
    assert health['limit_bytes'] == spool.max_bytes
    assert (health['refused_batches'], health['corrupt_batches'], health['rejected_batches']) == (1, 0, 0)
    spool.close()


def test_health_names_the_sensor_and_its_response_mode(service):
    from netwatch_ui_state import save_response_mode

    _, client, config, _ = service
    assert client.request('health')['data']['response_mode'] == 'ids_only'
    config["SENSOR_ID"] = "sensor-test"
    save_response_mode(config["RESPONSE_MODE_LEDGER"], "ready")
    health = client.request('health')['data']
    assert (health['sensor_id'], health['response_mode']) == ("sensor-test", "ready")
    assert health['case_retention_days'] == config.get("CASE_RETENTION_DAYS", 30)  # the gateway prunes its cache by it
    assert client.request('response-mode', {"mode": "autonomous"})['data'] == {"response_mode": "autonomous"}
    assert client.request('health')['data']['response_mode'] == "autonomous"
    for bad in ({"mode": "enforce"}, {"mode": "ready", "extra": 1}, {}):
        with pytest.raises(HTTPError):
            client.request('response-mode', bad)


def test_feed_pages_every_case_and_action_change_after_its_cursor(service):
    api, client, _, _ = service
    first = api.store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "one", "severity": "high"}))
    api.store.add(make_message("sensor", "ALERT", "9.9.9.9", {"message": "two", "severity": "low"}))
    pages, cursor = [], "0:0"
    while True:
        page = client.request("feed", after=cursor, limit=1)["data"]
        pages.append(page)
        cursor = page["cursor"]
        if not page["more"]:
            break
    seen = {case["incident_id"] for page in pages for case in page["cases"]}
    assert first["incident_id"] in seen and len(seen) == 2
    assert any(page["detections"] for page in pages)
    client.request("cases", {"case": first["incident_id"], "note": "looked"})
    action = client.request("actions", {"op": "request", "kind": "block_ip", "target": "8.8.8.8",
                                        "reason": "r", "case": first["incident_id"]})["data"]
    delta = client.request("feed", after=cursor)["data"]
    assert [case["incident_id"] for case in delta["cases"]] == [first["incident_id"]]
    assert [row["id"] for row in delta["actions"]] == [action["id"]]
    assert not delta["reset"] and client.request("feed", after=delta["cursor"])["data"]["cases"] == []
    rebuilt = client.request("feed", after="999999:0")["data"]
    assert rebuilt["reset"] and len(rebuilt["cases"]) == 2
    with pytest.raises(HTTPError):
        client.request("feed", after="1;DROP")


def test_traffic_summarises_the_ledger_window(service):
    from netwatch_history import HistoryStore

    api, client, config, _ = service
    traffic = client.request("traffic", window=3600, bucket=60)["data"]
    assert traffic["summary"]["events"] == 0 and traffic["timeline"] == []
    assert traffic["summary"] == HistoryStore(config["DB_NAME"]).summary(
        {"since": traffic["since"], "until": traffic["end"]})
    assert client.request("traffic", window=600, end=1000.0)["data"]["since"] == 400.0
    for bad in ({"window": 10}, {"window": 3600, "bucket": 1}, {"window": 604800, "bucket": 60}, {"window": "x"},
                {"end": "nan"}):
        with pytest.raises(HTTPError):
            client.request("traffic", **bad)


def test_api_lists_zeek_records_and_health_through_generic_source_reads(service, tmp_path):
    from netwatch_zeek import ZeekCollector
    from tests.test_zeek import FIXTURES, append

    api, client, _, _ = service
    append(tmp_path / "conn.log", FIXTURES["conn"])
    collector = ZeekCollector(api.store, {"ZEEK_LOG_PATHS": [str(tmp_path / "*.log")]})
    assert collector.poll(now=1700000010) == 1
    api.store.record_source_health(collector.channel, collector.health(1700000010))
    collector.close()
    rows = client.request('sources')['data']
    assert [(row['source'], row['event_type']) for row in rows] == [('ZEEK', 'conn')]
    assert rows[0]['normalized']['community_id'] == FIXTURES["conn"]["community_id"]
    health = client.request('collection-health')['data'][collector.channel]
    assert health['source'] == 'ZEEK' and health['status'] == 'FRESH'


def test_flow_join_returns_netwatch_suricata_and_zeek_records_for_one_community_id(service, tmp_path):
    import sqlite3
    from urllib.parse import quote

    from netwatch_db import EVENT_INSERT_SQL, ensure_network_event_columns, ledger_event_rows
    from netwatch_suricata import normalize_eve_record
    from netwatch_zeek import ZeekCollector
    from tests.test_capture import ethernet, ipv4, tcp
    from tests.test_community_id import ledger_row
    from tests.test_zeek import FIXTURES, append

    api, client, config, _ = service
    cid = FIXTURES["conn"]["community_id"]
    with sqlite3.connect(config["DB_NAME"]) as conn:
        conn.execute("CREATE TABLE network_events (uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, "
                     "mac_dst TEXT, src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER, tcp_flags TEXT, "
                     "ttl INTEGER, size_bytes INTEGER, sni_domain TEXT, country TEXT)")
        ensure_network_event_columns(conn)
        conn.executemany(EVENT_INSERT_SQL, ledger_event_rows([
            ledger_row(ethernet(ipv4(tcp(sport=34855, dport=80), 6, "128.232.110.120", "66.35.250.204")), "out"),
            ledger_row(ethernet(ipv4(tcp(sport=80, dport=34855), 6, "66.35.250.204", "128.232.110.120")), "back"),
            ledger_row(ethernet(ipv4(tcp(sport=1, dport=2), 6)), "other")]))
    for event_id, community_id in (("eve-1", cid), ("eve-2", "1:" + "A" * 27 + "=")):
        native = {"event_type": "flow", "src_ip": "128.232.110.120", "src_port": 34855,
                  "dest_ip": "66.35.250.204", "dest_port": 80, "proto": "TCP", "community_id": community_id}
        api.store.accept_source_record("SURICATA:test", {"offset": event_id}, normalize_eve_record(
            native, event_id=event_id, sensor_id="s", reference={}, received_at=time.time()), native)
    append(tmp_path / "conn.log", FIXTURES["conn"], FIXTURES["dns"])
    collector = ZeekCollector(api.store, {"ZEEK_LOG_PATHS": [str(tmp_path / "*.log")]})
    assert collector.poll(now=1700000010) == 2
    collector.close()

    data = client.request("flows/" + quote(cid, safe=""))["data"]
    assert data["community_id"] == cid
    assert sorted(row["uuid"] for row in data["netwatch"]) == ["back", "out"]
    assert [row["event_id"] for row in data["suricata"]] == ["eve-1"]
    assert [row["normalized"]["flow_id"] for row in data["zeek"]] == [FIXTURES["conn"]["uid"]]
    plan = api.store._read("EXPLAIN QUERY PLAN SELECT * FROM security_source_events "
                           "WHERE json_extract(normalized, '$.community_id')=?", (cid,))
    assert "idx_source_events_community" in str([tuple(row) for row in plan])
    for bad in ("flows/not-an-id", "flows/" + quote("1:" + "A" * 40, safe="")):
        with pytest.raises(HTTPError) as rejected:
            client.request(bad)
        assert rejected.value.code == 400


def connect(api):
    return socket.create_connection(("127.0.0.1", api.server.server_port))


def test_trickling_header_client_does_not_stall_close(service):
    api = service[0]
    sock = connect(api)
    sock.sendall(b"GET /v1/health HTTP/1.1\r\nX-Slow: ")  # Never finishes the header.
    time.sleep(0.2)
    started = time.monotonic()
    api.close()
    assert time.monotonic() - started < 1.5
    sock.close()


def test_connections_past_cap_are_closed_without_threads(service, monkeypatch):
    api = service[0]
    monkeypatch.setattr(netwatch_api, "MAX_CONNECTIONS", 2)
    before = threading.active_count()
    held = [connect(api) for _ in range(2)]
    deadline = time.monotonic() + 2
    # `active` is filled before the handler thread starts, so wait for the threads themselves.
    while (len(api.server.active) < 2 or threading.active_count() < before + 2) and time.monotonic() < deadline:
        time.sleep(0.01)
    threads = threading.active_count()
    extra = connect(api)
    extra.settimeout(2)
    assert extra.recv(1) == b""  # Server closed it.
    assert threading.active_count() <= threads
    for sock in (*held, extra):
        sock.close()


def test_hello_proof_verifies_and_leaks_nothing(service):
    api, client, _, secret = service
    nonce = "ab" * 16
    with client.opener.open(client.url + "/v1/hello?nonce=" + nonce, timeout=1) as response:
        body = json.loads(response.read())
    assert body == {"proof": netwatch_api.hello_proof(secret, nonce)}
    assert client.poll(now=1e9) and client.verified


def test_impostor_server_never_sees_the_token():
    import http.server
    seen = []

    class Impostor(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            body = b'{"proof": "00"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Impostor)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = ServiceClient(f"http://127.0.0.1:{server.server_port}", bytes(32), timeout=1)
    try:
        assert not client.poll(now=1e9)
        with pytest.raises(ValueError):
            client.update_case("x", actor="a", status="Open")
    finally:
        server.shutdown()
        server.server_close()
    assert seen and set(seen) == {None}
    assert client.state == "Disconnected / stale"


def test_response_mode_change_leaves_a_durable_audit_row(service):
    api, client, _, _ = service
    client.request("response-mode", {"mode": "autonomous"})
    rows = api.store._read("SELECT actor, body FROM security_native_audit WHERE operation='response_mode'")
    assert [(r["actor"], json.loads(r["body"])) for r in rows] == [
        ("authenticated-console", {"from": "ids_only", "to": "autonomous"})]


def test_trickling_client_loses_its_slot_at_the_request_deadline(service, monkeypatch):
    monkeypatch.setattr(netwatch_api, "REQUEST_DEADLINE_SEC", 1.0)
    sock = connect(service[0])
    sock.settimeout(0.5)
    started = time.monotonic()
    closed = False
    while time.monotonic() - started < 4 and not closed:
        try:
            sock.sendall(b"X")  # one header byte at a time, well under the 3 s recv timeout
            closed = sock.recv(1024) == b""
        except TimeoutError:
            pass
        except OSError:
            closed = True
    assert closed and time.monotonic() - started < 2.5
    sock.close()
