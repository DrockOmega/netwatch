"""A slow security store must not stall the core's packet consumption (Sensor1 2026-10-12)."""

import queue
import threading
import time

import netwatch_arp
import netwatch_workers
from netwatch_capture import parse_ethernet_frame
from netwatch_core import make_message
from tests.test_capture import ethernet, ipv4, tcp
from tests.test_core_publish import run_core, worker_config


def test_core_never_runs_the_durable_analyzers(tmp_path, monkeypatch):
    polls = []

    def slow_poll(self, limit=32):
        polls.append(time.time())
        time.sleep(1)  # a writer-lock wait behind another process
        return 0

    monkeypatch.setattr(netwatch_arp.DurableArpAnalyzer, "poll", slow_poll)
    config = dict(worker_config(tmp_path), ARP_DETECTION_ENABLED=True)
    qs = {name: queue.Queue() for name in ("ingest", "render", "alert", "policy", "db", "evidence", "status", "inventory")}
    data = parse_ethernet_frame(ethernet(ipv4(tcp(b"x"), 6)), time.time())[1]
    data.update(sensor_id="t", interface="t")
    for _ in range(20):
        qs["ingest"].put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": [dict(data) for _ in range(64)]}))
    stop = threading.Event()
    thread = threading.Thread(target=netwatch_workers.dod_core_process, daemon=True, args=(
        qs["ingest"], qs["render"], qs["alert"], qs["policy"], qs["db"], qs["evidence"], config, qs["status"], qs["inventory"], stop))
    thread.start()
    deadline = time.time() + 3
    while time.time() < deadline and not qs["ingest"].empty():
        time.sleep(0.05)
    consumed = 20 - qs["ingest"].qsize()
    stop.set()
    thread.join(15)
    assert not polls  # they run in durable_analysis_process, off the core's GIL (Sensor1 10k events/s burst)
    assert consumed == 20
    assert not thread.is_alive()


def test_durable_analysis_worker_runs_analyzers_and_publishes_alerts(tmp_path):
    from netwatch_control import ControlCollector
    from netwatch_security_store import security_store_from_config
    from tests.test_arp_replay import A, B, record

    config = dict(worker_config(tmp_path), ARP_DETECTION_ENABLED=True)
    store = security_store_from_config(config)
    collector = ControlCollector(store, config)
    record(collector, A, 1)
    for timestamp in (2, 3, 4):
        record(collector, B, timestamp)
    qs = {name: queue.Queue() for name in ("alert", "evidence", "inventory", "status")}
    qs["inventory"].put(make_message("DOD_CORE", "INVENTORY_SNAPSHOT", "DURABLE_ANALYSIS", {"devices": [
        {"mac": "02:00:00:00:00:01", "vendor": "Unknown", "first_seen": 1.0, "last_seen": 2.0,
         "ips": ["10.0.0.9"], "count": 3}]}))
    stop = threading.Event()
    thread = threading.Thread(target=netwatch_workers.durable_analysis_process, daemon=True, args=(
        qs["alert"], qs["evidence"], qs["inventory"], config, qs["status"], stop))
    thread.start()
    alerts = []
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            while not qs["alert"].empty():
                alerts.append(qs["alert"].get_nowait()["action"])
            if "ARP_ANOMALY" in alerts and all(store.source_health(key) for key in (
                    "ANALYSIS:ARP:v1", "ANALYSIS:ASSETS:v1", "ANALYSIS:WIRELESS:v1")) and not qs["status"].empty():
                break
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(10)
    try:
        assert "ARP_ANOMALY" in alerts and qs["inventory"].empty()
        assert store.cursor("ANALYSIS:ARP:v1")["sequence"] == 4
        assert store.source_health("ANALYSIS:WIRELESS:v1") is not None
        assert qs["status"].get_nowait()["source"] == "DURABLE_ANALYSIS"
        assert not thread.is_alive()
    finally:
        store.close()


def test_core_logs_throughput_line(tmp_path, monkeypatch):
    import logging
    import re

    monkeypatch.setattr(netwatch_workers, "THROUGHPUT_LOG_SEC", 0.3)
    lines = []

    class Grab(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    grab = Grab()
    logging.getLogger("netwatch.core").addHandler(grab)
    try:
        run_core(tmp_path, count=5, extra={"LOG_LEVEL": "INFO"}, linger=1.2)
    finally:
        logging.getLogger("netwatch.core").removeHandler(grab)
    hits = [m for m in lines if m.startswith("throughput:")]
    assert hits, lines
    assert re.search(r"events_per_sec=\d+\.\d batches=1 cpu_pct=\d+\.\d ingest_queue=\d+", " ".join(hits)), hits
