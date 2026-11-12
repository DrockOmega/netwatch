import logging
import multiprocessing as mp
import os
import queue
import re
import threading
import time

import netwatch_capture
import netwatch_runtime
import netwatch_workers
from netwatch_config import DEFAULTS
from netwatch_workers import io_sniffer_process
from tests.test_capture import ethernet, ipv4, tcp
from tests.test_runtime import runtime_config


def test_stalled_core_bounds_ingestion_and_counts_every_dropped_packet(tmp_path, monkeypatch, caplog):
    # The bound counts batches; at full batches it must stay near the original 100k-packet design.
    assert netwatch_runtime.INGESTION_QUEUE_BATCHES * DEFAULTS["INGEST_BATCH_MAX"] <= 100_000
    batch, slots, offered = 8, 4, 8 * 50 + 3  # the +3 leaves a partial batch for the forced final flush
    config = dict(runtime_config(tmp_path), EVIDENCE_CAPTURE_ENABLED=False, CONTROL_CAPTURE_ENABLED=False,
                  INGEST_BATCH_MAX=batch, INGEST_BATCH_SEC=60)
    ingestion = mp.get_context("spawn").Queue(maxsize=slots)  # nobody reads it: a stalled core
    monkeypatch.setattr(netwatch_workers, "INGEST_HOLD_BATCHES", 4)  # hold 32 events, hard cap 64
    shutdown = threading.Event()
    frame = ethernet(ipv4(tcp(b"flood"), 6))

    class FixtureSocket:
        def __init__(self):
            self.pcap_fd = self
        def setnonblock(self, _):
            pass
        def close(self):
            pass
        @staticmethod
        def select(sockets, _timeout):
            return sockets

    def dispatcher(_sock, callback):
        def dispatch(_batch):
            if not shutdown.is_set():
                for _ in range(offered):
                    callback(frame, time.time())
                shutdown.set()
            return 0
        return dispatch

    monkeypatch.setattr(netwatch_capture, "open_capture_socket", lambda *_: FixtureSocket())
    monkeypatch.setattr(netwatch_capture, "set_capture_buffer", lambda *_: True)
    monkeypatch.setattr(netwatch_capture, "make_capture_dispatcher", dispatcher)
    monkeypatch.setattr(netwatch_capture, "pcap_stats", lambda *_: None)

    sniffer_log = logging.getLogger("netwatch.sniffer")  # setup_logging is per-process idempotent
    monkeypatch.setattr(sniffer_log, "propagate", False)  # caplog's root handler would count each line twice
    sniffer_log.addHandler(caplog.handler)
    status = queue.Queue(100)
    try:
        io_sniffer_process(ingestion, queue.Queue(), config, status, shutdown)
    finally:
        sniffer_log.removeHandler(caplog.handler)

    # The producer-side feeder buffer is where the VM leak lived; it never exceeds the queue bound.
    assert ingestion.qsize() <= slots and len(ingestion._buffer) <= slots
    delivered = 0
    while True:
        try:
            delivered += len(ingestion.get(timeout=1)["data"]["events"])
        except queue.Empty:
            break
    ingestion.close()
    ingestion.join_thread()
    dropped = sum(int(n) for n in re.findall(r"backpressure: dropped (\d+) packets", caplog.text))
    assert 0 < delivered <= slots * batch
    assert delivered + dropped == offered and dropped >= offered - slots * batch - 64
    # Drops are a durable collection gap, not only a log line; the forced final flush reports them.
    messages = [status.get_nowait() for _ in range(status.qsize())]
    gaps = [m["data"]["count"] for m in messages if m["action"] == "CAPTURE_INGEST_GAP"]
    assert sum(gaps) == dropped and len(gaps) == 1


def test_unclean_control_close_still_signals_capture_drained(tmp_path, monkeypatch):
    import netwatch_control

    class UncleanControl:
        def __init__(self, *_a, **_k):
            pass

        def submit(self, *_a):
            pass

        def close(self, timeout=3):
            return False  # last control commit failed

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
            return []

    monkeypatch.setattr(netwatch_control, "ControlCaptureWorker", UncleanControl)
    monkeypatch.setattr(netwatch_control, "ControlCollector", lambda *_a, **_k: None)
    monkeypatch.setattr(netwatch_capture, "open_capture_socket", lambda *_: FixtureSocket())
    monkeypatch.setattr(netwatch_capture, "set_capture_buffer", lambda *_: True)
    monkeypatch.setattr(netwatch_capture, "make_capture_dispatcher", lambda *_: lambda _b: 0)
    monkeypatch.setattr(netwatch_capture, "pcap_stats", lambda *_: None)
    config = dict(runtime_config(tmp_path), EVIDENCE_CAPTURE_ENABLED=False, CONTROL_CAPTURE_ENABLED=True)
    ingestion = mp.get_context("spawn").Queue()
    shutdown, capture_stop, drained = threading.Event(), threading.Event(), threading.Event()
    thread = threading.Thread(target=io_sniffer_process, daemon=True,
                              args=(ingestion, queue.Queue(), config, queue.Queue(100), shutdown, capture_stop, drained))
    thread.start()
    capture_stop.set()
    try:
        # Ingestion is flushed, so core/db must not wait out the whole stop grace on a control problem.
        assert drained.wait(10)
    finally:
        shutdown.set()
        thread.join(15)


def test_stall_watchdog_rearms_once_a_second_not_per_wake(tmp_path, monkeypatch):
    import netwatch_workers

    config = dict(runtime_config(tmp_path), EVIDENCE_CAPTURE_ENABLED=False, CONTROL_CAPTURE_ENABLED=False)
    os.makedirs(config["LOG_DIR"], exist_ok=True)  # logging is set up once per process, maybe for another tmp dir
    shutdown, wakes, arms = threading.Event(), [], []

    class IdleSocket:
        def __init__(self):
            self.pcap_fd = self
        def setnonblock(self, _):
            pass
        def close(self):
            pass
        @staticmethod
        def select(sockets, _timeout):
            return sockets

    def dispatcher(_sock, _callback):
        def dispatch(_batch):  # an idle wire: every wake drains nothing
            wakes.append(time.monotonic())
            if wakes[-1] - wakes[0] > 1.5:
                shutdown.set()
            return 0
        return dispatch

    monkeypatch.setattr(netwatch_capture, "open_capture_socket", lambda *_: IdleSocket())
    monkeypatch.setattr(netwatch_capture, "set_capture_buffer", lambda *_: True)
    monkeypatch.setattr(netwatch_capture, "make_capture_dispatcher", dispatcher)
    monkeypatch.setattr(netwatch_capture, "pcap_stats", lambda *_: None)
    monkeypatch.setattr(netwatch_workers.faulthandler, "dump_traceback_later", lambda *a, **k: arms.append(a))
    monkeypatch.setattr(netwatch_workers.faulthandler, "cancel_dump_traceback_later", lambda: None)
    io_sniffer_process(mp.get_context("spawn").Queue(), queue.Queue(), config, queue.Queue(100), shutdown)
    assert len(wakes) > 50 and 1 <= len(arms) <= 3


def test_a_briefly_stalled_core_loses_nothing_capture_pauses_instead(tmp_path, monkeypatch, caplog):
    batch, slots, total = 8, 4, 3000
    hold = netwatch_workers.INGEST_HOLD_BATCHES * batch
    config = dict(runtime_config(tmp_path), EVIDENCE_CAPTURE_ENABLED=False, CONTROL_CAPTURE_ENABLED=False,
                  INGEST_BATCH_MAX=batch, INGEST_BATCH_SEC=0.05, PCAP_DRAIN_BATCH=16)
    os.makedirs(config["LOG_DIR"], exist_ok=True)
    ingestion = mp.get_context("spawn").Queue(maxsize=slots)
    shutdown, offered, reading = threading.Event(), [0], threading.Event()
    frame = ethernet(ipv4(tcp(b"burst"), 6))
    offered_before_reading = []

    class FixtureSocket:
        def __init__(self):
            self.pcap_fd = self
        def setnonblock(self, _):
            pass
        def close(self):
            pass
        @staticmethod
        def select(sockets, _timeout):
            return sockets

    def dispatcher(_sock, callback):
        def dispatch(max_packets):  # the kernel buffer: frames wait here until the sniffer reads them
            n = min(max_packets, total - offered[0])
            for _ in range(n):
                callback(frame, time.time())
            offered[0] += n
            return n
        return dispatch

    def core():
        time.sleep(1.0)  # stalled long enough for the queue and the hold to fill
        offered_before_reading.append(offered[0])
        delivered = 0
        try:
            while delivered < total:
                delivered += len(ingestion.get(timeout=3)["data"]["events"])
            reading.set()
        finally:  # a lost frame ends the wait in a failed assertion, not a hang
            shutdown.set()

    monkeypatch.setattr(netwatch_capture, "open_capture_socket", lambda *_: FixtureSocket())
    monkeypatch.setattr(netwatch_capture, "set_capture_buffer", lambda *_: True)
    monkeypatch.setattr(netwatch_capture, "make_capture_dispatcher", dispatcher)
    monkeypatch.setattr(netwatch_capture, "pcap_stats", lambda *_: None)
    sniffer_log = logging.getLogger("netwatch.sniffer")
    monkeypatch.setattr(sniffer_log, "propagate", False)
    sniffer_log.addHandler(caplog.handler)
    reader = threading.Thread(target=core)
    reader.start()
    try:
        io_sniffer_process(ingestion, queue.Queue(), config, queue.Queue(100), shutdown)
    finally:
        sniffer_log.removeHandler(caplog.handler)
        reader.join(15)
    assert reading.is_set()  # every one of the 3,000 frames reached analytics
    assert "backpressure: dropped" not in caplog.text and "ingest held" in caplog.text
    # Reads paused at the hold: the rest of the burst stayed in the (fixture) kernel buffer.
    assert offered_before_reading[0] <= slots * batch + hold + 16
    ingestion.close()
    ingestion.join_thread()


def test_evidence_requests_drain_at_most_cap_per_pass(tmp_path, monkeypatch):
    config = dict(runtime_config(tmp_path), EVIDENCE_CAPTURE_ENABLED=False, CONTROL_CAPTURE_ENABLED=False)
    os.makedirs(config["LOG_DIR"], exist_ok=True)
    shutdown, per_pass = threading.Event(), []

    class CountingQueue(queue.Queue):
        taken = 0
        def get_nowait(self):
            item = super().get_nowait()
            self.taken += 1
            return item

    requests = CountingQueue()
    for _ in range(5):
        requests.put(None)  # not a message: taken and discarded, which is all this test counts

    class IdleSocket:
        def __init__(self):
            self.pcap_fd = self
        def setnonblock(self, _):
            pass
        def close(self):
            pass
        @staticmethod
        def select(sockets, _timeout):
            return sockets

    def dispatcher(_sock, _callback):
        def dispatch(_batch):  # one read-loop pass per wake: record how many requests it took
            per_pass.append(requests.taken - sum(per_pass))
            if requests.empty() or len(per_pass) > 20:
                shutdown.set()
            return 0
        return dispatch

    monkeypatch.setattr(netwatch_workers, "EVIDENCE_REQUESTS_PER_PASS", 2)
    monkeypatch.setattr(netwatch_capture, "open_capture_socket", lambda *_: IdleSocket())
    monkeypatch.setattr(netwatch_capture, "set_capture_buffer", lambda *_: True)
    monkeypatch.setattr(netwatch_capture, "make_capture_dispatcher", dispatcher)
    monkeypatch.setattr(netwatch_capture, "pcap_stats", lambda *_: None)
    io_sniffer_process(mp.get_context("spawn").Queue(), requests, config, queue.Queue(100), shutdown)
    assert requests.taken == 5 and max(per_pass) <= 2
