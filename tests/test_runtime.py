import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import netwatch_runtime
from netwatch_config import DEFAULTS, PATH_KEYS
from netwatch_core import make_message
from netwatch_runtime import ServiceSupervisor
from netwatch_service import service_lock


def idle_worker(*args):
    if len(args) == 8:  # Capture pause handshake, with evidence consumer kept alive.
        while not args[5].wait(0.01):
            if args[4].is_set():
                return
        args[0].close()
        args[0].join_thread()
        args[6].set()
        args[4].wait()
    else:
        args[-1].wait()


def runtime_config(tmp_path):
    config = dict(DEFAULTS, SURICATA_EVE_ENABLED=False, LOG_TO_CONSOLE=False)
    for name in PATH_KEYS:
        if config.get(name):
            config[name] = str(tmp_path / Path(config[name]).name)
    for name in ("SIG_FILE", "POLICY_FILE", "JA3_BLOCKLIST", "OUI_DB"):
        config[name] = str(Path(__file__).resolve().parents[1] / Path(DEFAULTS[name]).name)
    return config


def fixture_capture_worker(*args):
    import netwatch_capture
    from netwatch_workers import io_sniffer_process
    from tests.test_capture import ethernet, ipv4, tcp

    class FixtureSocket:
        def __init__(self):
            self.pcap_fd = self
        def setnonblock(self, _):
            pass
        def close(self):
            pass
        @staticmethod
        def select(sockets, _timeout):
            time.sleep(0.01)
            return sockets

    frame = ethernet(ipv4(tcp(b"fixture packet"), 6))
    ready = Path(args[2]["LOG_DIR"]) / "capture-fixture.ready"
    delivered = [ready.exists()]  # A replacement generation must not re-deliver the fixture.
    def dispatcher(_sock, callback):
        def dispatch(_batch):
            if not delivered[0]:
                for _ in range(20):
                    callback(frame, time.time())
                delivered[0] = True
                ready.write_text("ready")
                return 20
            return 0
        return dispatch
    netwatch_capture.open_capture_socket = lambda *_: FixtureSocket()
    netwatch_capture.set_capture_buffer = lambda *_: True
    netwatch_capture.make_capture_dispatcher = dispatcher
    netwatch_capture.pcap_stats = lambda *_: {"recv": 20, "drop": 0, "ifdrop": 0}
    io_sniffer_process(*args)


def test_headless_import_and_help_need_no_gui_libraries():
    code = """
import sys
class RejectGUI:
    def find_spec(self, fullname, *args):
        if fullname.split('.')[0] in {'PyQt6','OpenGL'}:
            raise AssertionError('headless service imported graphical dependencies')
sys.meta_path.insert(0, RejectGUI())
import netwatch_service
assert not any(key.startswith(('PyQt6','OpenGL')) for key in sys.modules)
assert netwatch_service.main(['--help']) == 0
"""
    result = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "Supervised NetWatch" in result.stdout


def test_service_lock_excludes_another_process_and_releases_after_exit(tmp_path):
    path = str(tmp_path / "monitor.lock")
    code = "from netwatch_service import service_lock\nimport sys\nwith service_lock(sys.argv[1]): pass"
    with service_lock(path):
        result = subprocess.run([sys.executable, "-c", code, path], text=True, capture_output=True, timeout=15)
        assert result.returncode != 0 and "already owns" in result.stderr
    result = subprocess.run([sys.executable, "-c", code, path], text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o777 == 0o600


def test_supervisor_replaces_crashed_generation_and_preserves_cases(tmp_path, monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    clock = [100.0]
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick(now=clock[0])
        original = list(supervisor.runtime.workers)
        assert len(original) == 4 and supervisor.runtime.generation == 1
        assert supervisor.store.source_health("RUNTIME:SERVICE")["status"] == "DEGRADED"
        supervisor.store.add(make_message("DOD_CORE", "ALERT", "8.8.8.8", {"message": "Fixture rule", "severity": "alert"}))
        supervisor.runtime.queues["worker_status"].put(
            make_message("IO_WORKER", "WORKER_HEARTBEAT", "UI_SHELL", {"status": "IDLE"}))
        # Multiprocessing feeder visibility is asynchronous.
        deadline = time.time() + 5
        while time.time() < deadline:
            supervisor.tick(now=clock[0])
            if supervisor.store.open_count() and "IO_WORKER" in supervisor.health:
                break
            time.sleep(0.01)
        assert supervisor.store.snapshot()[0]["action"] == "ALERT"
        assert supervisor.health["IO_WORKER"][1]["status"] == "IDLE"
        original[0].terminate()
        original[0].join(5)
        supervisor.tick(now=clock[0])
        assert not supervisor.runtime.workers
        assert supervisor.store.open_count() == 2
        assert any(case["action"] == "RUNTIME_COLLECTION_GAP" for case in supervisor.store.snapshot())
        clock[0] += 3
        supervisor.tick(now=clock[0])
        assert supervisor.runtime.generation == 2 and len(supervisor.runtime.workers) == 4
        assert not supervisor.health
        assert supervisor.store.open_count() == 2
    finally:
        supervisor.close()


def test_observed_stalled_progress_restarts_even_a_live_worker(tmp_path, monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    clock = [100.0]
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick(now=clock[0])
        supervisor.health = {source: (119, {"status": "ALIVE"}) for source in ("IO_WORKER", "DOD_CORE", "DB_WORKER")}
        supervisor.health["DOD_CORE"] = (119, {"status": "DEADLOCK_DETECTED"})
        clock[0] = 120
        supervisor.tick(now=clock[0])
        assert not supervisor.runtime.workers
        assert supervisor.store.detections(supervisor.store.snapshot()[0]["incident_id"])[0]["payload"]["data"]["failed_workers"] == ["core"]
    finally:
        supervisor.close()


def test_runtime_start_cannot_replace_running_processes(tmp_path, monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    runtime = netwatch_runtime.MonitoringRuntime({})
    try:
        runtime.start()
        with pytest.raises(RuntimeError, match="already started"):
            runtime.start()
    finally:
        runtime.stop()


def test_real_headless_core_replays_evidence_with_no_console(tmp_path, monkeypatch):
    from netwatch_control import ControlCollector
    from tests.test_arp_replay import A, B, record

    monkeypatch.setattr(netwatch_runtime, "io_sniffer_process", idle_worker)
    config = runtime_config(tmp_path)
    supervisor = ServiceSupervisor(config)
    collector = ControlCollector(supervisor.store, config)
    record(collector, A, 1)
    for timestamp in (2, 3, 4):
        record(collector, B, timestamp)
    try:
        supervisor.tick()
        deadline = time.time() + 15
        while time.time() < deadline:
            supervisor.tick()
            cases = supervisor.store.snapshot()
            # Health is recorded just after the case in the same worker loop; wait for both.
            if any(case["action"] == "ARP_ANOMALY" for case in cases) and \
                    supervisor.store.source_health("ANALYSIS:ARP:v1") is not None:
                break
            time.sleep(0.05)
        assert any(case["action"] == "ARP_ANOMALY" for case in supervisor.store.snapshot())
        assert supervisor.store.cursor("ANALYSIS:ARP:v1")["sequence"] == 4
        assert supervisor.store.source_health("ANALYSIS:ARP:v1")["status"] == "RUNNING"
        assert supervisor.runtime.generation == 1
    finally:
        supervisor.close()


def test_worker_start_failure_retries_with_backoff_and_durable_finding(tmp_path, monkeypatch):
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    attempts = []
    def refuse():
        attempts.append(1)
        raise OSError("simulated process creation failure")
    monkeypatch.setattr(supervisor.runtime, "start", refuse)
    try:
        supervisor.tick(now=100)
        supervisor.tick(now=101)
        assert len(attempts) == 1
        supervisor.tick(now=103)
        assert len(attempts) == 2
        assert supervisor.store.snapshot()[0]["action"] == "RUNTIME_START_FAILED"
        assert supervisor.store.source_health("RUNTIME:SERVICE")["status"] == "DEGRADED"
    finally:
        supervisor.close()


def test_ordered_shutdown_flushes_real_capture_core_database_and_late_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(netwatch_runtime, "io_sniffer_process", fixture_capture_worker)
    config = runtime_config(tmp_path)
    config.update(CONTROL_CAPTURE_ENABLED=False, ARP_DETECTION_ENABLED=False,
                  INGEST_BATCH_MAX=1000, INGEST_BATCH_SEC=3600,
                  EVIDENCE_CAPTURE_ACTIONS=["DEVICE_NEW"])
    runtime = netwatch_runtime.MonitoringRuntime(config)
    try:
        runtime.start()
        ready = Path(config["LOG_DIR"]) / "capture-fixture.ready"
        deadline = time.time() + 15
        while time.time() < deadline and not ready.exists():
            time.sleep(0.02)
        assert ready.exists()
        assert runtime.stop(grace=15) == []
        assert runtime.shutdown_report["ordered_drain"]
        with sqlite3.connect(config["DB_NAME"]) as conn:
            assert conn.execute("SELECT SUM(packet_count) FROM network_events").fetchone()[0] == 20
        manifests = list(Path(config["EVIDENCE_DIR"]).glob("*.manifest.json"))
        assert manifests
        assert all(json.loads(path.read_text())["frames"] == 20 for path in manifests)
    finally:
        runtime.stop()


def test_service_survives_a_locked_store_tick(tmp_path, monkeypatch):
    import sqlite3

    import netwatch_service

    calls = []

    class Supervisor:
        def __init__(self, config):
            pass

        def tick(self):
            calls.append(1)
            if len(calls) == 1:
                raise sqlite3.OperationalError("database is locked")
            raise KeyboardInterrupt  # ends the loop once the locked tick was survived

        def close(self):
            pass

    class API:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return self

        def close(self):
            pass

    monkeypatch.setattr(netwatch_service, "ServiceSupervisor", Supervisor)
    monkeypatch.setattr(netwatch_service, "ServiceAPI", API)
    monkeypatch.setattr(netwatch_service, "load_secret", lambda *a, **k: b"x" * 32)
    with pytest.raises(KeyboardInterrupt):
        netwatch_service.main(["--base-dir", str(tmp_path)])
    assert len(calls) == 2



def test_stop_file_requests_an_ordered_stop(tmp_path, monkeypatch):
    import netwatch_service

    closed, ticks = [], []

    class Supervisor:
        def __init__(self, config):
            pass

        def tick(self):
            ticks.append(1)
            if len(ticks) == 2:
                (tmp_path / netwatch_service.STOP_FILE).touch()

        def close(self):
            closed.append(1)

    class API:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return self

        def close(self):
            pass

    (tmp_path / netwatch_service.STOP_FILE).touch()  # stale from an earlier run: must not stop this start
    monkeypatch.setattr(netwatch_service, "ServiceSupervisor", Supervisor)
    monkeypatch.setattr(netwatch_service, "ServiceAPI", API)
    monkeypatch.setattr(netwatch_service, "load_secret", lambda *a, **k: b"x" * 32)
    monkeypatch.setattr(netwatch_service.signal, "signal", lambda *a: None)
    assert netwatch_service.main(["--base-dir", str(tmp_path)]) == 0
    assert closed == [1] and len(ticks) == 2
    assert not (tmp_path / netwatch_service.STOP_FILE).exists()


def test_startup_failures_reach_the_service_log(tmp_path, monkeypatch):
    import logging

    import netwatch_service

    def broken(config):
        raise ValueError("invalid correlation rule pack")

    logger = logging.getLogger("netwatch.service")
    monkeypatch.setattr(logger, "handlers", [])  # setup_logging reuses an earlier test's file handler
    monkeypatch.setattr(netwatch_service, "ServiceSupervisor", broken)
    monkeypatch.setattr(netwatch_service.signal, "signal", lambda *a: None)
    with pytest.raises(ValueError):
        netwatch_service.main(["--base-dir", str(tmp_path)])
    for handler in logger.handlers:
        handler.close()
    assert "invalid correlation rule pack" in (tmp_path / "logs" / "netwatch-service.log").read_text()

    def bad_config(*args, **kwargs):
        raise ValueError("bad overlay value")

    monkeypatch.setattr(netwatch_service, "build_config", bad_config)
    with pytest.raises(ValueError):
        netwatch_service.main(["--base-dir", str(tmp_path / "fresh")])
    assert "bad overlay value" in (tmp_path / "fresh" / "logs" / "netwatch-service.log").read_text()


def killed_in_drain_worker(*args):
    args[-1].wait()
    os.kill(os.getpid(), getattr(signal, "SIGKILL", signal.SIGTERM))  # SIGTERM is TerminateProcess on Windows


def held_db_worker(*args):
    """Real persistence worker that blocks once at a spool step so the test can SIGKILL it there."""
    import netwatch_spool
    from netwatch_db import db_persistence_worker

    point = args[2]["_TEST_DB_HOLD"]
    marker = Path(args[2]["LOG_DIR"]) / "db-held"
    original = getattr(netwatch_spool.TelemetrySpool, point)

    def hold(self, *a, **k):
        if not marker.exists():
            marker.write_text(point)
            while True:
                time.sleep(1)
        return original(self, *a, **k)
    setattr(netwatch_spool.TelemetrySpool, point, hold)
    db_persistence_worker(*args)


def test_worker_killed_during_ordered_drain_is_not_a_clean_drain(tmp_path, monkeypatch):
    from netwatch_security_store import DurableIncidentStore

    monkeypatch.setattr(netwatch_runtime, "io_sniffer_process", idle_worker)
    monkeypatch.setattr(netwatch_runtime, "dod_core_process", idle_worker)
    monkeypatch.setattr(netwatch_runtime, "durable_analysis_process", idle_worker)
    monkeypatch.setattr(netwatch_runtime, "db_persistence_worker", killed_in_drain_worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    supervisor.tick(now=100)
    supervisor.close()
    report = supervisor.runtime.shutdown_report
    assert not report["ordered_drain"]
    assert report["failed_workers"] == ["db"]
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        assert [case["action"] for case in store.snapshot()] == ["RUNTIME_COLLECTION_GAP"]
    finally:
        store.close()


def slow_drain_db_worker(*args):
    """Clean persistence drain on a slow host: 8 s spool replay plus fsyncs/joins, then exit 0."""
    args[-1].wait()
    time.sleep(10.5)


def hung_db_worker(*args):
    args[-1].wait()
    time.sleep(3600)


def _stop_with_db_worker(tmp_path, monkeypatch, worker, **config):
    from netwatch_security_store import DurableIncidentStore

    monkeypatch.setattr(netwatch_runtime, "io_sniffer_process", idle_worker)
    monkeypatch.setattr(netwatch_runtime, "dod_core_process", idle_worker)
    monkeypatch.setattr(netwatch_runtime, "durable_analysis_process", idle_worker)
    monkeypatch.setattr(netwatch_runtime, "db_persistence_worker", worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db"), **config})
    supervisor.tick(now=100)
    supervisor.close()
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        return supervisor.runtime.shutdown_report, [case for case in store.snapshot()
                                                    if case["action"] == "RUNTIME_COLLECTION_GAP"]
    finally:
        store.close()


def test_slow_but_complete_persistence_drain_is_verified(tmp_path, monkeypatch):
    # The VM's stops forced core/db/sniffer at the old fixed 10 s budget although nothing failed.
    report, gaps = _stop_with_db_worker(tmp_path, monkeypatch, slow_drain_db_worker)
    assert report["ordered_drain"] and report["forced_workers"] == [] and gaps == []


def test_drain_still_running_at_the_stop_budget_records_a_gap(tmp_path, monkeypatch):
    report, gaps = _stop_with_db_worker(tmp_path, monkeypatch, hung_db_worker, RUNTIME_STOP_GRACE_SEC=1)
    assert not report["ordered_drain"] and "db" in report["forced_workers"]
    assert len(gaps) == 1


def _wait(predicate, supervisor, now, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        supervisor.tick(now=now)
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _ledger_packets(config):
    if not os.path.exists(config["DB_NAME"]):
        return 0
    with sqlite3.connect(config["DB_NAME"]) as conn:
        try:
            return conn.execute("SELECT COALESCE(SUM(packet_count), 0) FROM network_events").fetchone()[0]
        except sqlite3.OperationalError:
            return 0


@pytest.mark.parametrize("victim, hold, expected_packets", [
    ("sniffer", None, {0}),                 # 20 frames buffered in capture, never sent
    ("core", None, {0, 20}),                # batch in core/IPC/spool: all or nothing, never doubled
    ("core-1", None, {0, 20}),              # an analytics shard: the merge never sees a half round
    ("db", "enqueue_batch", {0}),           # dequeued from IPC, killed before spool receipt
    ("db", "acknowledge_batch", {20}),      # ledger committed, killed before spool ack: replayed once
    ("analysis", None, {0, 20}),            # store consumer only: replaced with the generation like the others
])
def test_sigkill_mid_batch_records_unknown_gap_and_replaces_generation(
        tmp_path, monkeypatch, victim, hold, expected_packets):
    from netwatch_spool import TelemetrySpool

    monkeypatch.setattr(netwatch_runtime, "io_sniffer_process", fixture_capture_worker)
    if hold:
        monkeypatch.setattr(netwatch_runtime, "db_persistence_worker", held_db_worker)
    config = runtime_config(tmp_path)
    config.update(CONTROL_CAPTURE_ENABLED=False, ARP_DETECTION_ENABLED=False, INGEST_BATCH_SEC=3600,
                  INGEST_BATCH_MAX=1000 if victim == "sniffer" else 20, _TEST_DB_HOLD=hold)
    ready = Path(config["LOG_DIR"]) / ("db-held" if hold else "capture-fixture.ready")
    supervisor = ServiceSupervisor(config)
    try:
        assert _wait(ready.exists, supervisor, 100)
        process = next(p for p in supervisor.runtime.workers if p.name == victim)
        process.kill()
        process.join(5)
        supervisor.tick(now=100)
        assert not supervisor.runtime.workers
        gaps = [case for case in supervisor.store.snapshot() if case["action"] == "RUNTIME_COLLECTION_GAP"]
        assert len(gaps) == 1
        detail = supervisor.store.detections(gaps[0]["incident_id"])[0]["payload"]["data"]
        assert detail["failed_workers"] == [victim] and detail["count"] is None and detail["generation"] == 1
        supervisor.tick(now=103)
        assert supervisor.runtime.generation == 2
        assert [p.name for p in supervisor.runtime.workers if p.is_alive()] == [
            "db", "sniffer", "core", "analysis", "core-0", "core-1", "core-2", "core-3"]  # CORE_SHARDS=4
        assert _wait(lambda: "DB_WORKER" in supervisor.health, supervisor, 103)
        if expected_packets == {20}:
            assert _wait(lambda: _ledger_packets(config) == 20, supervisor, 103)
    finally:
        supervisor.close()
    assert _ledger_packets(config) in expected_packets
    spool = TelemetrySpool(config["SPOOL_PATH"])
    try:
        assert spool.count_pending()["batches"] == 0
    finally:
        spool.close()


def test_slow_starting_generation_gets_start_grace_then_restarts(tmp_path, monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db"), "RUNTIME_START_GRACE_SEC": 60})
    try:
        supervisor.tick(now=100.0)
        supervisor.tick(now=150.0)  # silent for 50s while starting: still within grace
        assert supervisor.runtime.generation == 1 and len(supervisor.runtime.workers) == 4
        supervisor.tick(now=161.0)
        assert not supervisor.runtime.workers
    finally:
        supervisor.close()


def test_stop_survives_a_worker_that_outlives_sigkill():
    class Unkillable:  # a process stuck in an uninterruptible disk wait
        name, exitcode = "sniffer", None

        def is_alive(self):
            return True

        def join(self, timeout=None):
            pass

        terminate = kill = join

        def close(self):
            raise ValueError("Cannot close a process while it is still running.")

    import multiprocessing

    worker = Unkillable()
    multiprocessing.process._children.add(worker)
    runtime = netwatch_runtime.MonitoringRuntime({})
    runtime.workers, runtime.worker_stops = [worker], {"sniffer": SimpleNamespace(set=lambda: None, close=lambda: None)}
    runtime.stop(grace=0, drain=False)
    assert runtime.shutdown_report["forced_workers"] == ["sniffer"]
    # VM: multiprocessing's atexit join on such a child kept the stopped service alive until systemd's SIGKILL.
    assert worker not in multiprocessing.process._children


def stop_ignoring_lock_holder(*args):
    """Collector caught mid-write by the stop: holds the store's writer lock and ignores stop and SIGTERM."""
    args[-1].wait()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    conn = sqlite3.connect(args[2]["INCIDENT_DB"], isolation_level=None)
    conn.execute("BEGIN IMMEDIATE")
    Path(args[2]["INCIDENT_DB"] + ".held").touch()
    time.sleep(3600)


@pytest.mark.skipif(os.name == "nt", reason="ignoring SIGTERM needs POSIX signals")
def test_hung_collector_is_killed_without_spending_the_drain_budget(tmp_path, monkeypatch):
    import multiprocessing

    import netwatch_suricata
    from netwatch_security_store import DurableIncidentStore

    _idle_workers(monkeypatch)
    monkeypatch.setattr(netwatch_suricata, "suricata_eve_process", stop_ignoring_lock_holder)
    monkeypatch.setattr(netwatch_runtime, "NATIVE_STOP_SEC", 1)
    path = str(tmp_path / "security.db")
    supervisor = ServiceSupervisor({"INCIDENT_DB": path, "SURICATA_EVE_ENABLED": True, "RUNTIME_STOP_GRACE_SEC": 30})
    supervisor.tick(now=100)
    began = time.monotonic()
    supervisor.close()
    elapsed = time.monotonic() - began
    report = supervisor.runtime.shutdown_report
    assert Path(path + ".held").exists()
    # Core, persistence and capture still drained in order; only the collector was forced, by SIGKILL.
    assert report["forced_workers"] == ["suricata-eve"] and report["capture_drained"] and not report["ordered_drain"]
    assert elapsed < 15, elapsed  # The old stop joined the collector for the whole 30 s budget first.
    assert not [p for p in multiprocessing.active_children() if p.name == "suricata-eve"]
    store = DurableIncidentStore(path)
    try:
        gaps = [case for case in store.snapshot() if case["action"] == "RUNTIME_COLLECTION_GAP"]
        assert len(gaps) == 1 and store.source_health("RUNTIME:SERVICE")["status"] == "STOPPED"
    finally:
        store.close()


def test_service_exits_within_budget_when_close_blocks(tmp_path, monkeypatch):
    import threading

    import netwatch_service

    released = threading.Event()
    codes = []

    class Supervisor:
        def __init__(self, config):
            pass

        def tick(self):
            signal.raise_signal(signal.SIGTERM)

        def close(self):
            released.wait(30)  # stands in for an fsync or child join stuck in a disk stall

    class API:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return self

        def close(self):
            pass

    def fake_exit(code):
        codes.append(code)
        released.set()

    (tmp_path / "netwatch.config.json").write_text(json.dumps({"RUNTIME_STOP_GRACE_SEC": 0}))
    monkeypatch.setattr(netwatch_service, "ServiceSupervisor", Supervisor)
    monkeypatch.setattr(netwatch_service, "ServiceAPI", API)
    monkeypatch.setattr(netwatch_service, "load_secret", lambda *a, **k: b"x" * 32)
    monkeypatch.setattr(netwatch_service, "STOP_CLOSE_SEC", 0.5)
    monkeypatch.setattr(netwatch_service.os, "_exit", fake_exit)
    handlers = {name: signal.getsignal(name) for name in (signal.SIGINT, signal.SIGTERM)}
    began = time.monotonic()
    try:
        netwatch_service.main(["--base-dir", str(tmp_path)])
    finally:
        for name, handler in handlers.items():
            signal.signal(name, handler)
    assert codes == [1] and time.monotonic() - began < 10


def test_queued_heartbeats_count_before_staleness_is_judged(tmp_path, monkeypatch):
    import queue as stdlib_queue

    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick(now=100.0)
        # The supervisor itself stalled: its last view of every worker is 30s old,
        # but each worker's fresh heartbeat is already waiting in the queue.
        supervisor.health = {source: (100.0, {"status": "ALIVE"}) for source in ("IO_WORKER", "DOD_CORE", "DB_WORKER")}
        waiting = stdlib_queue.Queue()
        for source in ("IO_WORKER", "DOD_CORE", "DB_WORKER"):
            waiting.put(make_message(source, "WORKER_HEARTBEAT", "UI_SHELL", {"status": "ALIVE"}))
        real, supervisor.runtime.queues["worker_status"] = supervisor.runtime.queues["worker_status"], waiting
        supervisor.tick(now=130.0)
        supervisor.runtime.queues["worker_status"] = real
        assert supervisor.runtime.generation == 1 and len(supervisor.runtime.workers) == 4
    finally:
        supervisor.close()


def test_heartbeat_intake_never_waits_on_the_store(tmp_path, monkeypatch):
    """VM 2026-10-08: one locked health write per heartbeat left the queue unread for 30-77s."""
    import queue as stdlib_queue

    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick(now=100.0)
        waiting = stdlib_queue.Queue()
        for _ in range(50):
            for source in ("IO_WORKER", "DOD_CORE"):
                waiting.put(make_message(source, "WORKER_HEARTBEAT", "UI_SHELL", {"status": "ALIVE"}))
        real, supervisor.runtime.queues["worker_status"] = supervisor.runtime.queues["worker_status"], waiting
        writes = []
        store_write = supervisor.store.record_source_health
        monkeypatch.setattr(supervisor.store, "record_source_health",
                            lambda key, body, now=None: (writes.append(key), store_write(key, body, now)))
        supervisor._drain(101.0)
        assert writes == [] and waiting.empty()  # 100 heartbeats taken, no store write
        supervisor.tick(now=106.0)  # the health interval writes each source once
        supervisor.runtime.queues["worker_status"] = real
        assert sorted(writes) == ["RUNTIME:DOD_CORE", "RUNTIME:IO_WORKER", "RUNTIME:SERVICE"]
        assert supervisor.store.source_health("RUNTIME:IO_WORKER")["status"] == "ALIVE"
    finally:
        supervisor.close()


def _idle_workers(monkeypatch):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)


def test_tick_reads_clock_after_expire_due_so_heartbeats_stay_fresh(tmp_path, monkeypatch):
    _idle_workers(monkeypatch)
    clock = [1000.0]
    monkeypatch.setattr(netwatch_runtime, "time", SimpleNamespace(
        monotonic=lambda: clock[0], time=time.time, sleep=time.sleep))
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick()
        assert supervisor.runtime.generation == 1 and len(supervisor.runtime.workers) == 4

        def slow_expire():  # a slow store/release: the clock moves, fresh heartbeats get queued
            clock[0] += 35
            for source in ("IO_WORKER", "DOD_CORE", "DB_WORKER"):
                supervisor.runtime.queues["worker_status"].put(
                    make_message(source, "WORKER_HEARTBEAT", "UI_SHELL", {"status": "IDLE"}))
            time.sleep(0.3)  # multiprocessing feeder visibility is asynchronous

        monkeypatch.setattr(supervisor.actions, "expire_due", slow_expire)
        supervisor.tick()
        clock[0] += 0.2
        supervisor.tick()
        assert supervisor.runtime.generation == 1 and len(supervisor.runtime.workers) == 4
    finally:
        monkeypatch.undo()  # close() calls expire_due too
        supervisor.close()


def test_locked_gap_write_still_backs_off_and_lands_once(tmp_path, monkeypatch):
    _idle_workers(monkeypatch)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    real_add, locked = supervisor.store.add, [True]

    def add(message):
        if locked[0] and message["action"] == "RUNTIME_COLLECTION_GAP":
            locked[0] = False
            raise sqlite3.OperationalError("database is locked")
        return real_add(message)

    try:
        supervisor.tick(now=100.0)
        supervisor.runtime.workers[0].terminate()
        supervisor.runtime.workers[0].join(5)
        monkeypatch.setattr(supervisor.store, "add", add)
        with pytest.raises(sqlite3.OperationalError):
            supervisor.tick(now=150.0)
        assert supervisor.failures == 1 and supervisor.health == {} and supervisor.next_start == 152.0
        supervisor.tick(now=150.2)
        assert not supervisor.runtime.workers  # flushed, but still backing off
        supervisor.tick(now=151.0)
        assert not supervisor.runtime.workers
        gaps = [c for c in supervisor.store.snapshot() if c["action"] == "RUNTIME_COLLECTION_GAP"]
        assert len(gaps) == 1 and not supervisor.pending_findings
    finally:
        supervisor.close()


def test_start_after_unordered_stop_records_exactly_one_gap(tmp_path):
    config = {"INCIDENT_DB": str(tmp_path / "security.db"), "DB_NAME": str(tmp_path / "packets.db")}
    crashed = ServiceSupervisor(config)
    crashed.store.record_source_health("RUNTIME:SERVICE", {"status": "OK"})  # never reached STOPPED
    crashed.store.close()
    restarted = ServiceSupervisor(config)
    assert [f["data"]["message"] for f in restarted.pending_findings] == [
        "Previous run ended without an ordered stop; queued telemetry may be missing"]
    restarted.close()
    assert ServiceSupervisor(config).pending_findings == []


def _sniffer_progress_case(tmp_path, monkeypatch, progress_age):
    """Sniffer heartbeats last seen 30 s ago; its capture loop stamped progress `progress_age` s ago (None = never)."""
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, idle_worker)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    supervisor.tick(now=100.0)
    if progress_age is not None:
        supervisor.runtime.sniffer_progress.value = time.monotonic() - progress_age
    supervisor.health = {"IO_WORKER": (70.0, {"status": "ALIVE"}),
                         "DOD_CORE": (99.0, {"status": "ALIVE"}), "DB_WORKER": (99.0, {"status": "ALIVE"})}
    supervisor.tick(now=100.0)
    return supervisor


def test_sniffer_with_starved_heartbeat_but_live_capture_is_not_restarted(tmp_path, monkeypatch):
    supervisor = _sniffer_progress_case(tmp_path, monkeypatch, progress_age=1.0)
    try:
        assert supervisor.runtime.generation == 1 and len(supervisor.runtime.workers) == 4
    finally:
        supervisor.close()


@pytest.mark.parametrize("age", [None, 60.0])
def test_sniffer_with_no_heartbeat_and_no_capture_progress_is_restarted(tmp_path, monkeypatch, age):
    supervisor = _sniffer_progress_case(tmp_path, monkeypatch, progress_age=age)
    try:
        assert not supervisor.runtime.workers
    finally:
        supervisor.close()


def test_response_mode_queues_or_approves_one_block_per_target(tmp_path, monkeypatch):
    import ipaddress
    import queue as stdlib_queue

    from netwatch_ui_state import save_response_mode

    _idle_workers(monkeypatch)
    mode = str(tmp_path / "mode.json")
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db"), "RESPONSE_MODE_LEDGER": mode})
    try:
        supervisor.tick(now=100.0)
        real = supervisor.runtime.queues["alert"]

        def alert(ip):
            waiting = stdlib_queue.Queue()
            waiting.put(make_message("DOD_CORE", "ALERT", ipaddress.ip_address(ip).packed, {"message": f"scan {ip}"}))
            supervisor.runtime.queues["alert"] = waiting
            supervisor._drain(101.0)
            return [(a["target"], a["state"], a["requested_by"]) for a in supervisor.store.list_actions()]

        assert alert("8.8.8.8") == []  # ids_only is the default
        save_response_mode(mode, "ready")
        assert alert("8.8.8.8") == [("8.8.8.8", "requested", "response-mode:ready")]
        assert len(alert("8.8.8.8")) == 1  # one open request per target
        save_response_mode(mode, "autonomous")
        assert alert("9.9.9.9")[-1] == ("9.9.9.9", "applied", "response-mode:autonomous")
        supervisor.runtime.queues["alert"] = real
    finally:
        supervisor.close()


def test_stop_during_restart_backoff_files_no_second_gap(tmp_path, monkeypatch):
    from netwatch_security_store import DurableIncidentStore

    _idle_workers(monkeypatch)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    supervisor.tick(now=100)
    supervisor.runtime.workers[0].terminate()
    supervisor.runtime.workers[0].join(5)
    supervisor.tick(now=100)  # failure gap; next start is in backoff
    assert not supervisor.runtime.workers
    supervisor.close()
    store = DurableIncidentStore(str(tmp_path / "security.db"))
    try:
        gaps = [case for case in store.snapshot() if case["action"] == "RUNTIME_COLLECTION_GAP"]
        health = store.source_health("RUNTIME:SERVICE")
    finally:
        store.close()
    assert len(gaps) == 1 and gaps[0]["count"] == 1
    assert health["status"] == "STOPPED" and health["ordered_drain"] and health["failed_workers"] == []


def test_stop_signal_threads_never_poll_the_pipe_concurrently_or_blocking():
    """Concurrent blocking polls of one pipe stalled Sensor1's capture loop ~32 s (Windows wait())."""
    import multiprocessing as mp
    import threading

    from netwatch_runtime import StopSignal

    signal = StopSignal(mp.get_context("spawn"))
    real_poll, active, seen = signal.reader.poll, [0], {"max": 0, "timeouts": set()}
    guard = threading.Lock()

    def poll(timeout=0.0):
        with guard:
            active[0] += 1
            seen["max"] = max(seen["max"], active[0])
            seen["timeouts"].add(timeout)
        try:
            time.sleep(0.002)  # widen the window an overlapping poll would need
            return real_poll(timeout)
        finally:
            with guard:
                active[0] -= 1

    signal.reader = SimpleNamespace(poll=poll, recv_bytes=signal.reader.recv_bytes, close=signal.reader.close)
    results = []
    threads = [threading.Thread(target=lambda: results.append(signal.wait(5))) for _ in range(8)]
    for thread in threads:
        thread.start()
    time.sleep(0.2)
    StopSignal.set(SimpleNamespace(_lock=threading.Lock(), _set=False, writer=signal.writer))  # the other end's set()
    for thread in threads:
        thread.join(5)
    assert results == [True] * 8
    assert seen["max"] == 1 and seen["timeouts"] == {0}
    signal.close()


def test_pending_findings_cap_coalesces_into_counted_summary(tmp_path, monkeypatch):
    _idle_workers(monkeypatch)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    real_add = supervisor.store.add

    def locked(message):
        raise sqlite3.OperationalError("database is locked")

    try:
        monkeypatch.setattr(supervisor.store, "add", locked)
        for i in range(70):
            supervisor._queue_finding(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {
                "message": f"gap {i}", "count": None, "severity": "critical", "containment_eligible": False}))
        assert len(supervisor.pending_findings) == 64 and supervisor.coalesced_findings == 6
        monkeypatch.setattr(supervisor.store, "add", real_add)
        supervisor.tick(now=100.0)
        gaps = [c for c in supervisor.store.snapshot() if c["action"] == "RUNTIME_COLLECTION_GAP"]
        assert len(gaps) == 65  # 64 queued + 1 summary
        assert [g["detail"] for g in gaps].count("6 further runtime findings coalesced while the security store refused writes") == 1
        assert not supervisor.pending_findings and supervisor.coalesced_findings == 0
    finally:
        supervisor.close()
