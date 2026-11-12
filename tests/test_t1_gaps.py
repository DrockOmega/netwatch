"""T1 test gaps from the battle plan: small regressions for fixes that landed without a test."""

import ast
import io
import logging
import sys
import threading
import time
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import netwatch_runtime
import netwatch_scan
import threatintel_update
from netwatch_capture import CaptureProgress
from netwatch_history import HistoryStore
from netwatch_runtime import ServiceSupervisor
from netwatch_sources import JSONLinesReader
from tests.test_core_publish import drain, run_core

ROOT = Path(__file__).resolve().parents[1]


def test_capture_report_never_ages_negative_under_concurrent_reads():
    progress = CaptureProgress(started_at=time.monotonic())
    progress.read_complete()
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            progress.read_complete()

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        statuses = {progress.report()["status"] for _ in range(10_000)}
    finally:
        stop.set()
        thread.join(5)
    assert "DEADLOCK_DETECTED" not in statuses


def test_sniffer_never_writes_the_store_directly():
    source = (ROOT / "netwatch_workers.py").read_text()
    sniffer = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "io_sniffer_process")
    direct = [ast.get_source_segment(source, n) for n in ast.walk(sniffer)
              if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "publish_detection"]
    assert direct == []  # every sniffer finding goes through the detection-publisher thread


def test_reader_rests_between_full_batches_but_not_after_the_last(monkeypatch):
    reader = JSONLinesReader("/nonexistent/x.jsonl", SimpleNamespace(sensor_id="s"), "T")
    sizes = iter([reader.BATCH_RECORDS, reader.BATCH_RECORDS, 5])
    monkeypatch.setattr(reader, "_discover", lambda: None)
    monkeypatch.setattr(reader, "_poll", lambda *a, **k: next(sizes))
    sleeps = []
    monkeypatch.setattr(time, "sleep", sleeps.append)

    @contextmanager
    def transaction():
        yield

    assert reader.poll(None, limit=1000, transaction=transaction) == 2 * reader.BATCH_RECORDS + 5
    assert len(sleeps) == 2 and all(s >= 0.1 for s in sleeps)


def exits_at_once(*_args):  # module level so spawned workers can pickle it
    return


def test_supervisor_logs_which_worker_exited(tmp_path, monkeypatch, caplog):
    for name in ("io_sniffer_process", "dod_core_process", "db_persistence_worker", "durable_analysis_process"):
        monkeypatch.setattr(netwatch_runtime, name, exits_at_once)
    supervisor = ServiceSupervisor({"INCIDENT_DB": str(tmp_path / "security.db")})
    try:
        supervisor.tick(now=100.0)
        for worker in supervisor.runtime.workers:
            worker.join(10)
        service_log = logging.getLogger("netwatch.service")  # may not propagate; attach the handler directly
        service_log.addHandler(caplog.handler)
        try:
            supervisor.tick(now=101.0)
        finally:
            service_log.removeHandler(caplog.handler)
    finally:
        supervisor.close()
    line = next(r.getMessage() for r in caplog.records if "restarting generation" in r.getMessage())
    assert any(f"{name}: exited" in line for name in ("sniffer", "core", "db"))


def test_scan_main_reads_stdin_and_refuses_oversize(tmp_path, monkeypatch, capsys):
    xml = (ROOT / "tests" / "fixtures" / "nmap_lan.xml").read_bytes()
    argv = ["scan", "-", str(tmp_path / "s.db"), "10.0.0.0/24"]
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(xml)))
    netwatch_scan.main(argv)
    assert "'hosts': 1" in capsys.readouterr().out
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b" " * (netwatch_scan.MAX_BYTES + 1))))
    with pytest.raises(ValueError):
        netwatch_scan.main(argv)


def test_threatintel_update_keeps_cache_when_every_feed_fails(tmp_path, monkeypatch):
    cache = tmp_path / "intel.json"
    cache.write_bytes(b'{"keep": "me"}')
    feeds = tmp_path / "feeds.json"
    feeds.write_text('[{"name": "a", "url": "http://x.invalid/a", "type": "ipset"}]')

    def fail(*_args):
        raise OSError("offline")

    monkeypatch.setattr(threatintel_update, "_fetch", fail)
    args = Namespace(cache=str(cache), feeds_file=str(feeds), timeout=1)
    assert threatintel_update.cmd_update(args) == 1
    assert cache.read_bytes() == b'{"keep": "me"}'


def test_history_store_on_missing_file_is_empty_and_creates_nothing(tmp_path):
    path = tmp_path / "absent.db"
    store = HistoryStore(str(path))
    assert store.query() == [] and store.summary()["events"] == 0
    store.close()
    assert not path.exists()


def test_new_mac_flood_alerts_at_most_twenty_one_device_new(tmp_path):
    qs = run_core(tmp_path, count=100, macs=True)
    assert 1 <= sum(m["action"] == "DEVICE_NEW" for m in drain(qs["alert"])) <= 21
