import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

import netwatch_privilege
import netwatch_runtime
from netwatch_runtime import ServiceSupervisor
from tests.test_runtime import idle_worker

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "packaging" / "linux" / "netwatch.service"
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux capabilities")


def unit_settings():
    settings = {}
    for line in UNIT.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            settings.setdefault(key, []).append(value)
    return settings


def test_unit_grants_only_capture_capabilities_to_unprivileged_hardened_user():
    unit = unit_settings()
    assert unit["AmbientCapabilities"] == unit["CapabilityBoundingSet"] == ["CAP_NET_RAW CAP_NET_ADMIN"]
    assert unit["User"][0] not in {"root", "0"}
    assert "-m netwatch_service" in unit["ExecStart"][0]
    for key, value in {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
                       "PrivateTmp": "yes", "ReadWritePaths": "/var/lib/netwatch",
                       "SystemCallFilter": "@system-service"}.items():
        assert unit[key] == [value], key
    assert unit["KillMode"] == ["mixed"]
    assert "AF_PACKET" in unit["RestrictAddressFamilies"][0]


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
def test_unit_check_script_passes():
    result = subprocess.run(["sh", str(UNIT.parent / "check_unit.sh")], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


class FakeLibc:
    def __init__(self, capset_result=0):
        self.prctl_calls, self.capset_data, self.capset_result = [], None, capset_result

    def prctl(self, *args):
        self.prctl_calls.append(args)
        return 0

    def capget(self, _header, data):
        for word in data:
            word.effective = word.permitted = word.inheritable = 1 << 13 | 1 << 12  # NET_RAW | NET_ADMIN
        return 0

    def capset(self, _header, data):
        self.capset_data = [(w.effective, w.permitted, w.inheritable) for w in data]
        return self.capset_result


@linux_only
def test_drop_privileges_clears_every_set_and_ambient(monkeypatch):
    libc = FakeLibc()
    monkeypatch.setattr(netwatch_privilege, "_libc", lambda: libc)
    netwatch_privilege.drop_privileges()
    assert (47, 4, 0, 0, 0) in libc.prctl_calls and (38, 1, 0, 0, 0) in libc.prctl_calls
    assert libc.capset_data == [(0, 0, 0), (0, 0, 0)]


@linux_only
def test_supervisor_drop_keeps_permitted_for_capture_respawn(monkeypatch):
    libc = FakeLibc()
    monkeypatch.setattr(netwatch_privilege, "_libc", lambda: libc)
    netwatch_privilege.drop_effective_privileges()
    assert libc.capset_data == [(0, 0x3000, 0x3000)] * 2 and not libc.prctl_calls


@linux_only
def test_failed_drop_fails_closed(monkeypatch):
    monkeypatch.setattr(netwatch_privilege, "_libc", lambda: FakeLibc(capset_result=-1))
    with pytest.raises(OSError):
        netwatch_privilege.drop_privileges()


def report_privilege_worker(*args):
    name = multiprocessing.current_process().name
    state = netwatch_privilege.get_privilege_state()
    (Path(os.environ["NETWATCH_TEST_PRIV_DIR"]) / name).write_text(json.dumps(state))
    idle_worker(*args)


@linux_only
def test_runtime_drops_privileges_in_every_worker_except_capture(tmp_path, monkeypatch):
    monkeypatch.setenv("NETWATCH_TEST_PRIV_DIR", str(tmp_path))
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, report_privilege_worker)
    runtime = netwatch_runtime.MonitoringRuntime({})
    try:
        runtime.start()
        deadline = time.time() + 20
        while len(list(tmp_path.iterdir())) < 4 and time.time() < deadline:
            time.sleep(0.05)
        states = {p.name: json.loads(p.read_text()) for p in tmp_path.iterdir()}
    finally:
        runtime.stop(drain=False)
    assert states["db"]["no_new_privs"] and states["core"]["no_new_privs"] and states["analysis"]["no_new_privs"]
    assert states["db"]["status"] == states["core"]["status"] == states["analysis"]["status"] == "unprivileged"
    # Capture keeps whatever the parent passes down (no drop, no no_new_privs of its own).
    assert states["sniffer"]["no_new_privs"] == netwatch_privilege.get_privilege_state()["no_new_privs"]


def test_service_health_reports_privilege_per_worker(tmp_path, monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick(now=100.0)
        supervisor.health = {"IO_WORKER": (104, {"status": "ALIVE", "privilege": {"status": "privileged"}}),
                             "DB_WORKER": (104, {"status": "ALIVE"})}
        supervisor.tick(now=105.0)
        privileges = supervisor.store.source_health("RUNTIME:SERVICE")["worker_privileges"]
    finally:
        supervisor.close()
    assert privileges["IO_WORKER"] == {"status": "privileged"}
    assert privileges["DB_WORKER"] == {"status": "unverified"}
    assert privileges["SERVICE"] == netwatch_privilege.get_privilege_state()


@linux_only
def test_run_without_ambient_clears_then_restores_ambient(monkeypatch):
    libc, seen = FakeLibc(), []
    monkeypatch.setattr(netwatch_privilege, "_libc", lambda: libc)
    real_open = open
    monkeypatch.setattr("builtins.open", lambda path, *a, **k: (
        __import__("io").StringIO("CapAmb:\t0000000000003000\n") if path == "/proc/self/status"
        else real_open(path, *a, **k)))
    assert netwatch_privilege.run_without_ambient(lambda: seen.append(list(libc.prctl_calls)) or "ok") == "ok"
    assert seen == [[(47, 4, 0, 0, 0)]]  # cleared before the helper ran
    assert libc.prctl_calls[1:] == [(47, 2, 12, 0, 0), (47, 2, 13, 0, 0)]  # NET_ADMIN, NET_RAW raised back
