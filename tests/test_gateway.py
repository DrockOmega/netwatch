import json
import os
import sqlite3
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from netwatch_api import ServiceAPI, load_secret
from netwatch_core import make_message
from netwatch_gateway import Cache, Gateway, Node, node_state, sync
from netwatch_security_store import DurableIncidentStore


@pytest.fixture
def sensor(tmp_path):
    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence"), "LOG_DIR": str(tmp_path / "logs"),
              "LOG_TO_CONSOLE": False, "DEVICE_LEDGER": str(tmp_path / "devices.json"),
              "RESPONSE_MODE_LEDGER": str(tmp_path / "mode.json"), "SENSOR_ID": "Sensor1"}
    store = DurableIncidentStore(config["INCIDENT_DB"])
    secret = load_secret(tmp_path / "api.secret", create=True)
    api = ServiceAPI(SimpleNamespace(store=store, runtime=SimpleNamespace(config=config)), secret, port=0).start()
    yield f"http://127.0.0.1:{api.server.server_port}", secret, store
    api.close()
    store.close()


def get(gateway, path, token):
    request = Request(f"http://127.0.0.1:{gateway.server.server_port}{path}",
                      headers={"Authorization": f"Bearer {token}"})
    with urlopen(request, timeout=3) as response:
        return json.loads(response.read())


def test_node_states_age_from_last_success():
    assert [node_state(None, 100), node_state(90, 100), node_state(50, 100), node_state(39, 100)] == [
        "never", "online", "stale", "offline"]


def test_nodes_report_sensor_identity_and_require_the_token(sensor):
    url, secret, _ = sensor
    node = Node("sensor1", url, secret)
    gateway = Gateway([node], "t" * 64, Cache(":memory:"), port=0)
    try:
        assert node.view()["state"] == "never"
        assert node.poll()
        view = get(gateway.start(), "/api/nodes", "t" * 64)["nodes"][0]
        assert (view["node"], view["state"], view["sensor_id"], view["response_mode"]) == (
            "sensor1", "online", "Sensor1", "ids_only")
        with pytest.raises(HTTPError) as denied:
            get(gateway, "/api/nodes", "wrong")
        assert denied.value.code == 401
    finally:
        gateway.close()


def test_impostor_on_the_tunnel_port_never_marks_the_node_online(sensor):
    url, _, _ = sensor
    assert not Node("sensor1", url, b"x" * 32).poll()


def test_only_offline_and_recovery_are_announced(sensor, monkeypatch):
    import netwatch_gateway

    url, secret, _ = sensor
    sent = []
    monkeypatch.setattr(netwatch_gateway, "notify", lambda summary, body, urgency="normal": sent.append(summary))
    node = Node("sensor1", url, secret)
    assert node.poll()
    start = node.last_ok
    for offset in (0, 30, 61, 61, 30, 0):  # online, stale, offline, still offline, stale, online
        state = node.transition(start + offset)
        if state:
            netwatch_gateway.announce(node, state)
    assert sent == ["Sensor1 offline", "Sensor1 back online"]


def test_a_new_service_instance_records_a_gap(sensor):
    url, secret, _ = sensor
    node = Node("sensor1", url, secret)
    assert node.poll()
    node.instance = "an-earlier-run"
    assert node.poll()
    assert node.view()["gaps"][0]["reason"] == "sensor service restarted"


def test_cache_follows_the_feed_and_resumes_from_its_cursor(sensor, tmp_path):
    url, secret, store = sensor
    node = Node("sensor1", url, secret)
    case = store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "m", "severity": "high"}))
    cache = Cache(tmp_path / "cache.db")
    assert sync(node, cache, pages=50)
    assert [row["incident_id"] for row in cache.cases()] == [case["incident_id"]]
    assert cache.open_count("sensor1") == 1
    store.update_case(case["incident_id"], actor="test", status="Resolved", closure_reason="benign")
    reopened = Cache(tmp_path / "cache.db")  # a gateway restart keeps its cursor
    cursor = reopened.cursor("sensor1")
    assert sync(node, reopened)
    assert reopened.cursor("sensor1") != cursor
    assert reopened.open_count("sensor1") == 0 and reopened.cases()[0]["status"] == "Resolved"
    reopened.conn.execute("UPDATE cursors SET cursor='999999:0'")  # sensor database rebuilt underneath us
    assert sync(node, reopened) and reopened.cursor("sensor1") != "999999:0"
    assert len(reopened.cases()) == 1
    detail = reopened.case_detail("sensor1", case["incident_id"])
    assert [row["event_id"] for row in detail["detections"]] == [
        row["event_id"] for row in store.detections(case["incident_id"])]
    assert [row["operation"] for row in detail["history"]] == [
        row["operation"] for row in store.audit(case["incident_id"]) if row["operation"] != "detection"]
    assert reopened.case_detail("sensor1", "missing") is None


def test_new_critical_cases_alert_once_and_never_on_first_sync(sensor, tmp_path):
    url, secret, store = sensor
    node = Node("sensor1", url, secret)
    alerts = []
    record = lambda node, cases: alerts.append([case["title"] for case in cases])  # noqa: E731
    store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "backlog", "severity": "critical"}))
    cache = Cache(tmp_path / "cache.db")
    assert sync(node, cache, alert=record) and alerts == []
    store.add(make_message("sensor", "BEACON", "9.9.9.9", {"message": "fresh", "severity": "critical"}))
    store.add(make_message("sensor", "SCAN", "7.7.7.7", {"message": "quiet", "severity": "low"}))
    assert sync(node, cache, alert=record) and len(alerts) == 1 and len(alerts[0]) == 1
    store.add(make_message("sensor", "BEACON", "9.9.9.9", {"message": "fresh", "severity": "critical"}))
    assert sync(node, Cache(tmp_path / "cache.db"), alert=record) and len(alerts) == 1


def post(gateway, path, payload, token="t" * 64):
    request = Request(f"http://127.0.0.1:{gateway.server.server_port}{path}", data=json.dumps(payload).encode(),
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_case_triage_reaches_the_sensor_and_the_feed(sensor):
    url, secret, store = sensor
    case = store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "m", "severity": "high"}))
    node = Node("sensor1", url, secret)
    gateway = Gateway([node], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        sync(node, gateway.cache)
        status, result = post(gateway, "/api/case", {"node": "sensor1", "body": {
            "case": case["incident_id"], "note": "checked upstream", "acknowledge": True}})
        assert (status, result["outcome"]) == (200, "accepted")
        history = gateway.cache.case_detail("sensor1", case["incident_id"])["history"]
        assert history[-1]["body"]["note"] == "checked upstream"
        assert history[-1]["actor"] == "authenticated-console"
        status, result = post(gateway, "/api/case", {"node": "sensor1", "body": {
            "case": case["incident_id"], "status": "Resolved"}})  # closing needs a reason
        assert (status, result["outcome"]) == (502, "refused")
        assert post(gateway, "/api/case", {"node": "nowhere", "body": {}})[0] == 400
        assert post(gateway, "/api/case", {"node": "sensor1", "body": {}}, token="wrong")[0] == 401
        assert [w["outcome"] for w in gateway.cache.writes()] == ["refused", "accepted"]
    finally:
        gateway.close()


def test_a_write_with_a_lost_reply_is_sent_once_and_left_unknown(sensor, monkeypatch):
    import netwatch_client

    url, secret, _ = sensor
    sends = []

    def lost_reply(self, endpoint, body=None, **query):
        sends.append(endpoint)
        raise TimeoutError("reply lost")
    monkeypatch.setattr(netwatch_client.ServiceClient, "_request", lost_reply)
    gateway = Gateway([Node("sensor1", url, secret)], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        status, result = post(gateway, "/api/case", {"node": "sensor1", "body": {"case": "x", "note": "n"}})
        assert (status, result["outcome"]) == (502, "unknown")
        assert sends.count("cases") == 1
    finally:
        gateway.close()


def test_response_request_and_deny_flow_through_the_gateway(sensor):
    url, secret, store = sensor
    case = store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "m", "severity": "high"}))
    node = Node("sensor1", url, secret)
    gateway = Gateway([node], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        status, result = post(gateway, "/api/action", {"node": "sensor1", "body": {
            "op": "request", "kind": "block_ip", "target": "8.8.8.8", "reason": "beaconing",
            "case": case["incident_id"]}})
        assert status == 200
        action_id = result["reply"]["id"]
        assert [(a["node"], a["state"]) for a in gateway.cache.actions()] == [("sensor1", "requested")]
        assert post(gateway, "/api/action", {"node": "sensor1", "body": {"op": "deny", "id": action_id}})[0] == 200
        assert gateway.cache.actions()[0]["state"] == "denied"
        history = gateway.cache.case_detail("sensor1", case["incident_id"])["history"]
        assert any(row["operation"] == "link" for row in history)
    finally:
        gateway.close()


def test_approve_then_release_reaches_the_recording_effector(sensor):
    url, secret, _ = sensor
    node = Node("sensor1", url, secret)
    gateway = Gateway([node], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        _, result = post(gateway, "/api/action", {"node": "sensor1", "body": {
            "op": "request", "kind": "block_ip", "target": "8.8.8.8", "reason": "r"}})
        action = {"node": "sensor1", "body": {"id": result["reply"]["id"]}}
        assert post(gateway, "/api/action", action | {"body": action["body"] | {"op": "approve"}})[0] == 200
        assert gateway.cache.actions()[0]["state"] == "applied"
        assert post(gateway, "/api/action", action | {"body": action["body"] | {"op": "release"}})[0] == 200
        assert gateway.cache.actions()[0]["state"] == "released"
    finally:
        gateway.close()


def test_sensor_detail_passes_collection_health_through(sensor):
    url, secret, store = sensor
    store.record_source_health("NATIVE:SURICATA", {"status": "RUNNING", "rows": 5})
    gateway = Gateway([Node("sensor1", url, secret)], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        detail = get(gateway, "/api/sensor?node=sensor1", "t" * 64)
        assert detail["collection-health"]["NATIVE:SURICATA"]["rows"] == 5
        assert "gaps" in detail and detail["node"]["node"] == "sensor1"
        with pytest.raises(HTTPError):
            get(gateway, "/api/sensor?node=nowhere", "t" * 64)
    finally:
        gateway.close()


def test_traffic_passes_the_window_through(sensor):
    url, secret, _ = sensor
    gateway = Gateway([Node("sensor1", url, secret)], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        traffic = get(gateway, "/api/traffic?node=sensor1&window=900&bucket=30", "t" * 64)
        assert (traffic["window"], traffic["bucket"]) == (900, 30)
        with pytest.raises(HTTPError) as refused:
            get(gateway, "/api/traffic?node=sensor1&window=5&bucket=30", "t" * 64)
        assert refused.value.code == 502
    finally:
        gateway.close()


@pytest.mark.skipif(os.name == "nt", reason="the gateway and its 0600 node files are Linux-only")
def test_restart_needs_the_typed_sensor_name_and_runs_once(sensor, monkeypatch, tmp_path):
    import subprocess

    import netwatch_gateway

    url, secret, _ = sensor
    (tmp_path / "sensor1.tunnel").write_text('LOCAL_PORT=18765\nRESTART="schtasks /End /TN NetWatchService"\n')
    (tmp_path / "sensor1.secret").write_bytes(secret)
    (tmp_path / "sensor1.secret").chmod(0o600)
    assert netwatch_gateway.discover_nodes(tmp_path)[0].restart_command == "schtasks /End /TN NetWatchService"
    runs = []
    monkeypatch.setattr(netwatch_gateway.subprocess, "run",
                        lambda argv, **kw: runs.append(argv) or subprocess.CompletedProcess(argv, 0, "SUCCESS", ""))
    node = Node("sensor1", url, secret)
    node.restart_command = "restart-it"
    assert node.poll()
    gateway = Gateway([node], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        assert post(gateway, "/api/restart", {"node": "sensor1", "confirm": "sensor1"})[0] == 400
        status, result = post(gateway, "/api/restart", {"node": "sensor1", "confirm": "Sensor1"})
        assert (status, result["outcome"]) == (200, "accepted")
        assert runs == [["ssh", "-o", "BatchMode=yes", "sensor1", "restart-it"]]
        assert gateway.cache.writes()[0]["endpoint"] == "restart"
    finally:
        gateway.close()


def test_response_mode_switch_shows_on_the_node_at_once(sensor):
    url, secret, _ = sensor
    node = Node("sensor1", url, secret)
    gateway = Gateway([node], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        status, _ = post(gateway, "/api/response-mode", {"node": "sensor1", "body": {"mode": "ready"}})
        assert status == 200 and node.view()["response_mode"] == "ready"
        assert post(gateway, "/api/response-mode", {"node": "sensor1", "body": {"mode": "bogus"}})[0] == 502
    finally:
        gateway.close()


def test_a_poll_error_does_not_end_the_poll_thread(tmp_path):
    import threading

    calls, done = [], threading.Event()

    def poll():
        calls.append(1)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        done.set()
        return False

    node = SimpleNamespace(name="n", poll=poll, transition=lambda: None)
    gw = SimpleNamespace(nodes=[node], cache=None, _stop=threading.Event(), poll_interval=0.01, announce=None)
    worker = threading.Thread(target=Gateway._poll_loop, args=(gw,), daemon=True)
    worker.start()
    assert done.wait(5)
    gw._stop.set()
    worker.join(5)


def _page(cursor, more, sev="critical", reset=False, n=1):
    cases = [{"incident_id": f"{cursor}-{i}", "severity": sev, "status": "Open", "last_seen": 1} for i in range(n)]
    return {"cursor": cursor, "more": more, "reset": reset, "cases": cases, "detections": [], "actions": [],
            "case_audit": [], "action_audit": []}


def test_every_page_of_a_first_sync_and_a_reset_resync_stays_quiet():
    cache = Cache(":memory:")
    pages = [(_page("a", True), []), (_page("b", False), []),  # first sync, two pages
             (_page("c", False), ["c-0"]),                    # later incremental page alerts
             (_page("d", True, reset=True), []), (_page("e", False), [])]  # reset resync, two pages
    for page, expected in pages:
        assert [case["incident_id"] for case in cache.apply("n", page)] == expected


def test_a_node_never_seen_is_offline_after_the_stale_window():
    assert [node_state(None, 100, 50), node_state(None, 111, 50)] == ["never", "offline"]
    node = Node("n", "http://127.0.0.1:1", b"s")
    assert node.transition(node.since + 61) == "offline"


def test_a_failing_feed_is_visible_on_the_node(sensor, monkeypatch):
    url, secret, _ = sensor
    node = Node("sensor1", url, secret)
    monkeypatch.setattr(node.client, "request", lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    assert not sync(node, Cache(":memory:"))
    assert node.view()["feed_error"] == "boom"


def test_a_malformed_node_file_skips_only_that_node(tmp_path):
    from netwatch_gateway import discover_nodes

    for name, port in (("bad", "oops"), ("good", "9")):
        (tmp_path / f"{name}.tunnel").write_text(f"LOCAL_PORT={port}\n")
        load_secret(tmp_path / f"{name}.secret", create=True)
    (tmp_path / "nosecret.tunnel").write_text("LOCAL_PORT=9\n")
    (tmp_path / "noport.tunnel").write_text("X=1\n")
    load_secret(tmp_path / "noport.secret", create=True)
    assert [node.name for node in discover_nodes(tmp_path)] == ["good"]


@pytest.mark.skipif(os.name == "nt", reason="the gateway and its 0600 token are Linux-only")
def test_an_empty_token_file_is_refused(tmp_path):
    from netwatch_gateway import load_token

    path = tmp_path / "ui.token"
    path.write_text("")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_token(path)
    path.unlink()
    assert len(load_token(path)) == 64


@pytest.mark.skipif(os.name == "nt", reason="the gateway and its 0600 token are Linux-only")
def test_a_loose_token_file_is_refused(tmp_path):
    from netwatch_gateway import load_token

    path = tmp_path / "ui.token"
    path.write_text("t" * 64)
    path.chmod(0o640)
    with pytest.raises(ValueError, match="readable only by its owner"):
        load_token(path)
    path.chmod(0o600)
    assert load_token(path) == "t" * 64


def _raw(gateway, method, path, headers=None):
    request = Request(f"http://127.0.0.1:{gateway.server.server_port}{path}", headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, response.headers
    except HTTPError as err:
        return err.code, err.headers


def test_missing_authorization_header_is_refused_and_cors_is_an_allowlist():
    from netwatch_gateway import CONSOLE_ORIGINS

    gateway = Gateway([], "t" * 64, Cache(":memory:"), port=0)
    try:
        gateway.start()
        assert _raw(gateway, "GET", "/api/nodes")[0] == 401
        assert _raw(gateway, "GET", "/api/nodes", {"Authorization": "Bearer "})[0] == 401
        origin = sorted(CONSOLE_ORIGINS)[0]
        status, headers = _raw(gateway, "OPTIONS", "/api/nodes", {"Origin": origin})
        assert status == 204 and headers["Access-Control-Allow-Origin"] == origin
        for foreign in ("https://evil.example", "null"):
            status, headers = _raw(gateway, "OPTIONS", "/api/nodes", {"Origin": foreign})
            assert status == 204 and "Access-Control-Allow-Origin" not in headers
        _, headers = _raw(gateway, "GET", "/api/nodes", {"Origin": "https://evil.example"})
        assert "Access-Control-Allow-Origin" not in headers
    finally:
        gateway.close()


def test_bad_content_length_is_400():
    import http.client

    gateway = Gateway([], "t" * 64, Cache(":memory:"), port=0).start()
    try:
        for path, length in (("/api/case", "abc"), ("/api/restart", "abc"), ("/api/restart", "-1")):
            conn = http.client.HTTPConnection("127.0.0.1", gateway.server.server_port, timeout=2)
            conn.putrequest("POST", path)
            conn.putheader("Authorization", "Bearer " + "t" * 64)
            conn.putheader("Content-Length", length)
            conn.endheaders()
            assert conn.getresponse().status == 400
            conn.close()
    finally:
        gateway.close()


def test_a_malformed_feed_page_is_a_feed_error(sensor, monkeypatch):
    url, secret, _ = sensor
    node = Node("sensor1", url, secret)
    cache = Cache(":memory:")
    monkeypatch.setattr(node.client, "request", lambda *a, **k: {"data": {"cursor": "1:0"}})
    assert not sync(node, cache)
    assert node.feed_error and cache.cursor("sensor1") == "0:0"


def test_cases_cap_keeps_every_open_case(monkeypatch):
    monkeypatch.setattr("netwatch_gateway.CASES_LIMIT", 4, raising=False)
    cache = Cache(":memory:")
    page = _page("a", False, n=0)
    page["cases"] = [{"incident_id": f"d{i}", "status": "Dismissed", "last_seen": 100 + i} for i in range(9)] + \
                    [{"incident_id": f"o{i}", "status": "Open", "last_seen": i} for i in range(3)]
    cache.apply("sensor1", page)
    rows = cache.cases()
    assert len(rows) == 4
    assert {r["incident_id"] for r in rows} >= {"o0", "o1", "o2"}
    assert cache.open_count("sensor1") == 3 and cache.case_detail("sensor1", "d0") is not None


def test_actions_cap_keeps_every_requested_action(monkeypatch):
    monkeypatch.setattr("netwatch_gateway.ACTIONS_LIMIT", 4, raising=False)
    cache = Cache(":memory:")
    page = _page("a", False, n=0)
    page["actions"] = [{"id": f"d{i}", "state": "denied", "requested_at": 100 + i} for i in range(9)] + \
                      [{"id": f"r{i}", "state": "requested", "requested_at": i} for i in range(3)]
    cache.apply("sensor1", page)
    rows = cache.actions()
    assert len(rows) == 4
    assert {r["id"] for r in rows} >= {"r0", "r1", "r2"}
