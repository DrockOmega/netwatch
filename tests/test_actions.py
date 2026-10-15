"""Service-owned response actions: lifecycle, protection, expiry, audit; recording effector by default."""

import json
import sqlite3
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import pytest

import netwatch_mitigation
import netwatch_quarantine
import netwatch_runtime
from netwatch_actions import (
    SERVICE_ACTOR,
    STATES,
    ActionService,
    Protection,
    RecordingResponseEffector,
    legal_transition,
)
from netwatch_api import ServiceAPI, load_secret
from netwatch_client import ServiceClient
from netwatch_core import make_message
from netwatch_runtime import ServiceSupervisor
from netwatch_security_store import DurableIncidentStore
from tests.test_runtime import idle_worker

ROOT = Path(__file__).resolve().parents[1]

T0 = 1_700_000_000.0
DUE = T0 + 100.0


def guard():
    return Protection(
        gateway_ip="8.8.4.4", own_ip="1.0.0.1", allowlist_ips={"1.1.1.1"},
        allowlist_networks=("2001:4860:4860:1::/64",),
        gateway_mac="aa:bb:cc:dd:ee:10", own_mac="aa:bb:cc:dd:ee:11")


@pytest.fixture
def owner(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    service = ActionService(store, RecordingResponseEffector(), guard(), clock=lambda: T0)
    yield service
    store.close()


def ask(service, target="8.8.8.8", kind="block_ip", scope="", **kwargs):
    return service.request(
        kind=kind, target=target, scope=scope, reason=kwargs.pop("reason", "because"),
        requested_by=kwargs.pop("requested_by", "analyst"), expires_at=kwargs.pop("expires_at", DUE),
        **kwargs)


def test_transition_matrix_matches_the_lifecycle():
    legal = {("requested", "approved"), ("requested", "denied"), ("approved", "applied"),
             ("approved", "failed"), ("applied", "released"), ("applied", "expired")}
    for old in STATES:
        for new in STATES:
            assert legal_transition(old, new) is ((old, new) in legal)


def test_service_refuses_illegal_transitions_and_records_only_with_a_receipt(owner):
    denied = ask(owner)
    assert owner.deny(denied["id"], actor="analyst")["state"] == "denied"
    with pytest.raises(ValueError, match="illegal transition"):
        owner.approve(denied["id"], actor="analyst")
    assert owner.store.get_action(denied["id"])["state"] == "denied"

    waiting = ask(owner, target="9.9.9.9")
    with pytest.raises(ValueError, match="illegal transition"):
        owner.release(waiting["id"], actor="analyst")
    assert owner.store.get_action(waiting["id"])["state"] == "requested"

    applied = owner.approve(waiting["id"], actor="analyst")
    assert applied["state"] == "applied"
    assert applied["readback"] == "unverified"
    assert applied["receipt"]["enforced"] is False
    assert applied["receipt"]["effector"] == "recording"
    with pytest.raises(ValueError, match="illegal transition"):
        owner.approve(waiting["id"], actor="analyst")
    with pytest.raises(ValueError, match="illegal transition"):
        owner.deny(waiting["id"], actor="analyst")
    released = owner.release(waiting["id"], actor="analyst")
    assert released["state"] == "released"
    assert released["readback"] == "unverified"
    with pytest.raises(ValueError, match="illegal transition"):
        owner.release(waiting["id"], actor="analyst")
    assert [row["operation"] for row in owner.store.action_audit(waiting["id"])] == [
        "request", "approve", "apply", "release"]
    assert owner.effector.operations[0]["operation"] == "apply"
    assert all(item["enforced"] is False for item in owner.effector.operations)


def test_applied_requires_a_non_enforcing_recording_receipt(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        class Claiming:
            def apply(self, action):
                return {"ok": True, "receipt_id": "claim", "effector": "firewall",
                        "operation": "apply", "enforced": True}

            def release(self, action):
                return {"ok": True, "receipt_id": "rel", "effector": "recording",
                        "operation": "release", "enforced": False}

        service = ActionService(store, Claiming(), guard(), clock=lambda: T0)
        record = ask(service)
        failed = service.approve(record["id"], actor="analyst")
        assert failed["state"] == "failed"
        assert failed["readback"] == "unverified"
        assert failed["applied_at"] is None
        with pytest.raises(ValueError, match="illegal transition"):
            service.release(record["id"], actor="analyst")
    finally:
        store.close()


def test_release_failure_leaves_the_action_applied(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        class Down:
            def apply(self, action):
                return {"ok": True, "receipt_id": "ok", "effector": "recording",
                        "operation": "apply", "enforced": False}

            def release(self, action):
                raise RuntimeError("adapter down")

        service = ActionService(store, Down(), guard(), clock=lambda: T0)
        record = ask(service)
        assert service.approve(record["id"], actor="analyst")["state"] == "applied"
        with pytest.raises(ValueError, match="release receipt required"):
            service.release(record["id"], actor="analyst")
        assert store.get_action(record["id"])["state"] == "applied"
        assert [row["operation"] for row in store.action_audit(record["id"])] == [
            "request", "approve", "apply"]
    finally:
        store.close()


def test_protected_targets_are_refused_before_a_record_exists(owner):
    refused = [
        ("block_ip", "8.8.4.4", ""),
        ("block_ip", "1.0.0.1", ""),
        ("block_ip", "1.1.1.1", ""),
        ("block_ip", "10.1.2.3", ""),
        ("block_ip", "192.168.5.5", ""),
        ("block_ip", "127.0.0.1", ""),
        ("block_ip", "169.254.1.1", ""),
        ("block_ip", "224.0.0.1", ""),
        ("block_ip", "255.255.255.255", ""),
        ("block_ip", "::1", ""),
        ("block_ip", "fe80::1", ""),
        ("block_ip", "2001:4860:4860:1::10", ""),
        ("block_ip", "8.8.8.8", "10.0.0.1"),
        ("quarantine_mac", "aa:bb:cc:dd:ee:10", "10.1.2.3"),
        ("quarantine_mac", "aa:bb:cc:dd:ee:11", "10.1.2.3"),
        ("quarantine_mac", "ff:ff:ff:ff:ff:ff", "10.1.2.3"),
        ("quarantine_mac", "01:00:5e:00:00:01", "10.1.2.3"),
        ("quarantine_mac", "00:00:00:00:00:00", "10.1.2.3"),
        ("quarantine_mac", "aa:bb:cc:dd:ee:22", "8.8.8.8"),  # not a local device
        ("quarantine_mac", "aa:bb:cc:dd:ee:22", "::1"),
    ]
    for kind, target, scope in refused:
        with pytest.raises(ValueError, match="protected target"):
            ask(owner, target=target, kind=kind, scope=scope)
    with pytest.raises(ValueError, match="invalid target"):
        ask(owner, target="not-an-address")
    with pytest.raises(ValueError, match="quarantine scope must be the victim IP"):
        ask(owner, kind="quarantine_mac", target="aa:bb:cc:dd:ee:22", scope="")
    assert owner.store.list_actions() == []
    allowed = ask(owner, kind="quarantine_mac", target="AA-BB-CC-DD-EE-22", scope="10.1.2.3")
    assert allowed["state"] == "requested"
    assert allowed["target"] == "aa:bb:cc:dd:ee:22"
    assert allowed["scope"] == "10.1.2.3"
    assert ask(owner, target="2001:4860:4860::8888")["state"] == "requested"


def test_database_refuses_illegal_writes_rewrites_and_verified_readback(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        store.conn.execute(
            """INSERT INTO security_response_actions (
                   action_id, case_id, kind, target, scope, requested_by, reason, state,
                   requested_at, decided_at, applied_at, closed_at, expires_at, readback, body
               ) VALUES ('a', NULL, 'block_ip', '8.8.8.8', '', 'tester', 'because', 'requested',
                         1, NULL, NULL, NULL, 2, 'unverified', '{}')""")
        store.conn.execute("UPDATE security_response_actions SET state='approved' WHERE action_id='a'")
        with pytest.raises(sqlite3.IntegrityError):
            store.conn.execute("UPDATE security_response_actions SET state='expired' WHERE action_id='a'")
        with pytest.raises(sqlite3.IntegrityError):
            store.conn.execute("UPDATE security_response_actions SET readback='verified'")
        with pytest.raises(sqlite3.IntegrityError):
            store.conn.execute("DELETE FROM security_response_actions")
        store.conn.execute(
            """INSERT INTO security_action_audit
               (action_id, timestamp, actor, operation, state, body) VALUES ('a', 1, 'tester', 'request', 'requested', '{}')""")
        with pytest.raises(sqlite3.IntegrityError):
            store.conn.execute("UPDATE security_action_audit SET actor='other'")
        with pytest.raises(sqlite3.IntegrityError):
            store.conn.execute("DELETE FROM security_action_audit")
        assert tuple(store.conn.execute(
            "SELECT state, readback FROM security_response_actions").fetchone()) == ("approved", "unverified")
    finally:
        store.close()


def test_expiry_is_durable_idempotent_and_needs_no_console(tmp_path):
    path = tmp_path / "security.db"
    store = DurableIncidentStore(str(path))
    service = ActionService(store, RecordingResponseEffector(), guard(), clock=lambda: T0)
    record = ask(service)
    applied = service.approve(record["id"], actor="analyst")
    assert applied["state"] == "applied" and applied["readback"] == "unverified"
    assert service.expire_due() == 0
    store.close()

    reopened = DurableIncidentStore(str(path))
    try:
        resumed = ActionService(reopened, RecordingResponseEffector(), guard(), clock=lambda: T0 + 500)
        assert resumed.store.get_action(record["id"])["state"] == "applied"
        assert resumed.expire_due() == 1
        expired = resumed.store.get_action(record["id"])
        assert expired["state"] == "expired"
        assert expired["readback"] == "unverified"
        assert expired["receipt"]["operation"] == "release"
        assert expired["receipt"]["enforced"] is False
        assert resumed.expire_due() == 0
        audit = resumed.store.action_audit(record["id"])
        assert [row["operation"] for row in audit] == ["request", "approve", "apply", "expire"]
        assert audit[-1]["actor"] == SERVICE_ACTOR
        assert [row["body"]["from"] for row in audit] == [None, "requested", "approved", "applied"]
        assert [row["body"]["to"] for row in audit] == ["requested", "approved", "applied", "expired"]
        for row in audit:
            assert row["actor"] and isinstance(row["timestamp"], float)
            assert row["state"] == row["body"]["to"]
    finally:
        reopened.close()

    third = DurableIncidentStore(str(path))
    try:
        again = ActionService(third, RecordingResponseEffector(), guard(), clock=lambda: T0 + 900)
        assert again.expire_due() == 0
        assert [row["operation"] for row in again.store.action_audit(record["id"])].count("expire") == 1
    finally:
        third.close()


def test_expiry_retries_after_a_failed_release_without_a_second_audit(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        class Flaky:
            def __init__(self):
                self.releases = 0

            def apply(self, action):
                return {"ok": True, "receipt_id": "apply", "effector": "recording",
                        "operation": "apply", "enforced": False}

            def release(self, action):
                self.releases += 1
                if self.releases == 1:
                    raise RuntimeError("transient")
                return {"ok": True, "receipt_id": "release", "effector": "recording",
                        "operation": "release", "enforced": False}

        flaky = Flaky()
        service = ActionService(store, flaky, guard(), clock=lambda: T0)
        record = ask(service)
        service.approve(record["id"], actor="analyst")
        service.clock = lambda: T0 + 500
        assert service.expire_due() == 0
        assert store.get_action(record["id"])["state"] == "applied"
        assert service.expire_due() == 1
        assert store.get_action(record["id"])["state"] == "expired"
        assert service.expire_due() == 0
        assert [row["operation"] for row in store.action_audit(record["id"])].count("expire") == 1
        assert flaky.releases == 2
    finally:
        store.close()


def test_supervisor_expires_after_restart_without_a_console(tmp_path, monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "DB_NAME": str(tmp_path / "packets.db"),
              "OWN_IP": "1.0.0.1", "GATEWAY_IP": "8.8.4.4", "LOG_TO_CONSOLE": False,
              "BLOCK_LEDGER": str(tmp_path / "telemetry_blocks.json"),
              "QUARANTINE_LEDGER": str(tmp_path / "telemetry_quarantine.json")}
    first = ServiceSupervisor(config)
    first.actions.clock = lambda: T0
    record = ask(first.actions, requested_by="authenticated-console")
    assert first.actions.approve(record["id"], actor="authenticated-console")["state"] == "applied"
    first.close()
    assert not (tmp_path / "telemetry_blocks.json").exists()
    assert not (tmp_path / "telemetry_quarantine.json").exists()

    second = ServiceSupervisor(config)
    try:
        assert second.store.get_action(record["id"])["state"] == "applied"
        second.actions.clock = lambda: T0 + 500
        second.tick(now=50.0)
        expired = second.store.get_action(record["id"])
        assert expired["state"] == "expired"
        assert expired["readback"] == "unverified"
        assert second.actions.expire_due() == 0
        assert second.store.action_audit(record["id"])[-1]["actor"] == SERVICE_ACTOR
        assert second.store.source_health("RUNTIME:SERVICE")["response_actions"] == "recording-only"
        assert isinstance(second.actions.effector, RecordingResponseEffector)
    finally:
        second.close()


@pytest.fixture
def service(tmp_path):
    config = {"DB_NAME": str(tmp_path / "packets.db"), "INCIDENT_DB": str(tmp_path / "security.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence"), "LOG_DIR": str(tmp_path / "logs"),
              "LOG_TO_CONSOLE": False, "OWN_IP": "1.0.0.1", "GATEWAY_IP": "8.8.4.4"}
    store = DurableIncidentStore(config["INCIDENT_DB"])
    supervisor = SimpleNamespace(store=store, runtime=SimpleNamespace(config=config))
    secret = load_secret(tmp_path / "api.secret", create=True)
    api = ServiceAPI(supervisor, secret, port=0).start()
    client = ServiceClient(f"http://127.0.0.1:{api.server.server_port}", secret, timeout=2)
    yield api, client, config, secret
    api.close()
    store.close()


def _unauthorized(url, body=None, authorization=None):
    headers = {}
    if authorization is not None:
        headers["Authorization"] = authorization
    payload = None if body is None else json.dumps(body).encode()
    request = Request(url, data=payload, headers=headers, method="POST" if body is not None else "GET")
    with pytest.raises(HTTPError) as rejected:
        build_opener(ProxyHandler({})).open(request, timeout=2)
    assert rejected.value.code == 401
    assert b'"instance"' not in rejected.value.read()


def test_action_api_requires_auth_and_attributes_every_verb(service):
    api, client, _, _ = service
    url = client.url + "/v1/actions"
    bodies = (
        None,
        {"op": "request", "kind": "block_ip", "target": "8.8.8.8", "reason": "because"},
        {"op": "approve", "id": "missing"},
        {"op": "deny", "id": "missing"},
        {"op": "release", "id": "missing"},
    )
    for body in bodies:
        _unauthorized(url, body)
        _unauthorized(url, body, authorization="Bearer wrong")
    assert api.store.list_actions() == []

    with pytest.raises(HTTPError) as rejected:
        client.request("actions", {"op": "request", "kind": "block_ip", "target": "8.8.8.8",
                                    "reason": "because", "actor": "root"})
    assert rejected.value.code == 400
    with pytest.raises(HTTPError) as rejected:  # only approve/deny/release reach the store by id
        client.request("actions", {"op": "close", "id": "x"})
    assert rejected.value.code == 400
    with pytest.raises(HTTPError) as rejected:
        client.request("actions", {"op": "request", "kind": "block_ip", "target": "10.1.2.3", "reason": "local"})
    assert rejected.value.code == 400
    with pytest.raises(HTTPError) as rejected:
        client.request("actions", {"op": "request", "kind": "block_ip", "target": "8.8.8.8",
                                    "reason": "stale", "expires_at": 1})
    assert rejected.value.code == 400
    assert api.store.list_actions() == []

    health = client.request("health")["data"]
    assert health["actions"] == "recording-only"
    case = api.store.add(make_message("sensor", "ALERT", "8.8.8.8", {"message": "fixture", "severity": "critical"}))
    requested = client.request("actions", {"op": "request", "kind": "block_ip", "target": "8.8.8.8",
                                           "reason": "contain", "case": case["incident_id"], "scope": "edge"})["data"]
    assert requested["requested_by"] == "authenticated-console"
    assert requested["readback"] == "unverified"
    assert requested["state"] == "requested"
    assert requested["case_id"] == case["incident_id"]
    denied = client.request("actions", {"op": "request", "kind": "block_ip", "target": "9.9.9.9", "reason": "no"})["data"]
    assert client.request("actions", {"op": "deny", "id": denied["id"]})["data"]["state"] == "denied"
    approved = client.request("actions", {"op": "approve", "id": requested["id"]})["data"]
    assert approved["state"] == "applied"
    assert approved["readback"] == "unverified"
    assert approved["receipt"]["enforced"] is False
    with pytest.raises(HTTPError) as rejected:
        client.request("actions", {"op": "approve", "id": requested["id"]})
    assert rejected.value.code == 400
    released = client.request("actions", {"op": "release", "id": requested["id"]})["data"]
    assert released["state"] == "released"
    assert released["readback"] == "unverified"

    listed = client.request("actions")["data"]
    assert {row["id"] for row in listed} == {requested["id"], denied["id"]}
    assert client.request("actions", state="released")["data"][0]["id"] == requested["id"]
    assert client.request("actions", case=case["incident_id"])["data"][0]["id"] == requested["id"]
    for action_id, operations in (
            (requested["id"], ["request", "approve", "apply", "release"]),
            (denied["id"], ["request", "deny"])):
        audit = api.store.action_audit(action_id)
        assert [row["operation"] for row in audit] == operations
        assert {row["actor"] for row in audit} == {"authenticated-console"}
        assert [row["body"]["from"] for row in audit][0] is None
        for previous, row in zip([None, *[item["state"] for item in audit[:-1]]], audit, strict=True):
            assert row["body"]["from"] == previous
            assert row["actor"] == "authenticated-console"
            assert isinstance(row["timestamp"], float)
            assert row["state"] == row["body"]["to"]
    case_audit = api.store.audit(case["incident_id"])
    assert case_audit[-1]["actor"] == "authenticated-console"
    assert case_audit[-1]["body"]["kind"] == "response"
    assert all(item["enforced"] is False for item in api.actions.effector.operations)


def test_service_does_not_construct_or_call_an_enforcing_effector(tmp_path, monkeypatch):
    constructed = []

    def bomb(label):
        def _init(self, *args, **kwargs):
            constructed.append(label)
            raise AssertionError(label + " constructed")
        return _init

    monkeypatch.setattr(netwatch_mitigation.WindowsFirewall, "__init__", bomb("WindowsFirewall"))
    monkeypatch.setattr(netwatch_mitigation.Mitigator, "__init__", bomb("Mitigator"))
    monkeypatch.setattr(netwatch_quarantine.ArpQuarantineEffector, "__init__", bomb("ArpQuarantineEffector"))
    monkeypatch.setattr(netwatch_quarantine.Quarantine, "__init__", bomb("Quarantine"))
    monkeypatch.setattr(netwatch_quarantine.RecordingQuarantineEffector, "__init__", bomb("RecordingQuarantineEffector"))

    secret = load_secret(tmp_path / "api.secret", create=True)  # before the bomb: icacls restricts it on Windows
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("subprocess")))
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)

    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "DB_NAME": str(tmp_path / "packets.db"),
              "EVIDENCE_DIR": str(tmp_path / "evidence"), "OWN_IP": "1.0.0.1", "GATEWAY_IP": "8.8.4.4",
              "LOG_TO_CONSOLE": False, "BLOCK_LEDGER": str(tmp_path / "telemetry_blocks.json"),
              "QUARANTINE_LEDGER": str(tmp_path / "telemetry_quarantine.json")}
    supervisor = ServiceSupervisor(config)
    api = ServiceAPI(supervisor, secret, port=0).start()
    client = ServiceClient(f"http://127.0.0.1:{api.server.server_port}", secret, timeout=2)
    try:
        supervisor.tick(now=10)
        supervisor.runtime.queues["policy"].put(make_message(
            "DOD_CORE", "POLICY_DECISION", "8.8.8.8",
            {"configured_action": "block", "mode": "enforce", "message": "fixture"}))
        for _ in range(50):  # let the policy message cross the queue
            supervisor.tick(now=10)
            time.sleep(0.01)
        assert supervisor.store.list_actions() == []
        record = client.request("actions", {"op": "request", "kind": "block_ip", "target": "9.9.9.9",
                                            "reason": "record only"})["data"]
        applied = client.request("actions", {"op": "approve", "id": record["id"]})["data"]
        assert applied["state"] == "applied"
        assert applied["readback"] == "unverified"
        assert applied["receipt"]["effector"] == "recording"
        assert applied["receipt"]["enforced"] is False
        released = client.request("actions", {"op": "release", "id": record["id"]})["data"]
        assert released["state"] == "released"
        assert all(item["enforced"] is False and item["effector"] == "recording"
                   for item in supervisor.actions.effector.operations)
        assert [item["operation"] for item in supervisor.actions.effector.operations] == ["apply", "release"]
        assert constructed == []
        assert not (tmp_path / "telemetry_blocks.json").exists()
        assert not (tmp_path / "telemetry_quarantine.json").exists()
        for name in ("netwatch_actions.py", "netwatch_api.py", "netwatch_runtime.py", "netwatch_service.py"):
            text = (ROOT / name).read_text()
            for banned in ("WindowsFirewall", "ArpQuarantineEffector", "RecordingQuarantineEffector", "netsh", "sendp"):
                assert banned not in text, name
    finally:
        api.close()
        supervisor.close()


def test_expired_before_apply_does_not_call_the_effector(owner):
    record = ask(owner, expires_at=T0 + 10)
    owner.clock = lambda: T0 + 10
    failed = owner.approve(record["id"], actor="analyst")
    assert failed["state"] == "failed"
    assert failed["readback"] == "unverified"
    assert owner.effector.operations == []
    assert [row["operation"] for row in owner.store.action_audit(record["id"])] == ["request", "approve", "fail"]
    assert failed["readback"] == "unverified"


def test_an_undecided_request_expires_without_calling_the_effector(owner):
    record = ask(owner, expires_at=T0 + 10)
    assert owner.expire_due(now=T0 + 9) == 0
    assert owner.expire_due(now=T0 + 10) == 1
    assert owner.store.get_action(record["id"])["state"] == "denied"
    assert owner.store.action_audit(record["id"])[-1]["operation"] == "expire"
    assert owner.effector.operations == []
    assert owner.expire_due(now=T0 + 11) == 0


def test_quarantine_protects_local_gateway_host_and_allowlist(tmp_path):
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        local = Protection(gateway_ip="10.0.0.1", own_ip="10.0.0.5", allowlist_ips={"10.0.0.9"})
        service = ActionService(store, RecordingResponseEffector(), local, clock=lambda: T0)
        for victim in ("10.0.0.1", "10.0.0.5", "10.0.0.9"):
            with pytest.raises(ValueError, match="protected target"):
                ask(service, kind="quarantine_mac", target="aa:bb:cc:dd:ee:22", scope=victim)
        assert ask(service, kind="quarantine_mac", target="aa:bb:cc:dd:ee:22", scope="10.0.0.42")["state"] == "requested"
    finally:
        store.close()


def test_expiry_beyond_the_ttl_cap_is_refused_and_legacy_rows_fail_at_approve(owner):
    with pytest.raises(ValueError, match="exceeds MITIGATION_TTL_SEC"):
        ask(owner, expires_at=T0 + owner.default_ttl + 1)
    assert owner.store.list_actions() == []
    real = owner.default_ttl
    owner.default_ttl = real * 10
    legacy = ask(owner, expires_at=T0 + real + 1)
    owner.default_ttl = real
    failed = owner.approve(legacy["id"], actor="analyst")
    assert failed["state"] == "failed"
    assert owner.effector.operations == []


def test_allowlisted_resolver_can_never_be_a_response_target(tmp_path):
    from netwatch_actions import service_actions
    from netwatch_config import DEFAULTS
    from netwatch_security_store import DurableIncidentStore

    assert DEFAULTS["ALLOWLIST_IPS"] == []  # a known key, so a host overlay is not ignored
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        actions = service_actions(store, {"ALLOWLIST_IPS": ["75.75.75.75", "2001:558:feed::1"]})
        for target in ("75.75.75.75", "2001:558:feed::1"):
            with pytest.raises(ValueError):
                actions.request(kind="block_ip", target=target, reason="dns", requested_by="t")
        assert actions.request(kind="block_ip", target="8.8.8.8", reason="r", requested_by="t")["state"] == "requested"
    finally:
        store.close()


def test_zoned_or_non_canonical_forms_cannot_dodge_the_allowlist(tmp_path):
    from netwatch_actions import service_actions

    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        actions = service_actions(store, {"ALLOWLIST_IPS": ["2606:4700:4700:0:0:0:0:1111"]})
        for target in ("2606:4700:4700::1111", "2606:4700:4700::1111%1"):
            with pytest.raises(ValueError):
                actions.request(kind="block_ip", target=target, reason="dns", requested_by="t")
    finally:
        store.close()


def test_retried_request_returns_the_open_action_instead_of_a_second(owner):
    first = ask(owner)
    assert ask(owner)["id"] == first["id"]
    assert len(owner.store.list_actions()) == 1
    owner.deny(first["id"], actor="analyst")
    assert ask(owner)["id"] != first["id"]  # a closed action does not block a new one


def test_recording_effector_bounded():
    from netwatch_actions import RecordingResponseEffector

    effector = RecordingResponseEffector()
    for index in range(1000):
        effector.apply({"kind": "block_ip", "target": f"203.0.113.{index % 250}"})
    assert len(effector.operations) == 256 and effector.operations[-1]["target"] == "203.0.113.249"
