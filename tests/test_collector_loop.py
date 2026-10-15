"""A busy store must not end a native collector: a missed health write is retried next heartbeat."""

import logging
import queue
import sqlite3
import threading

from netwatch_suricata import run_collector_loop


def test_locked_health_write_keeps_the_collector_running():
    stop = threading.Event()

    class Store:
        def record_source_health(self, *args):
            raise sqlite3.OperationalError("database is locked")

        def close(self):
            pass

    class Collector:
        polls = 0

        def poll(self, notify):
            self.polls += 1
            if self.polls >= 2:
                stop.set()
            return 0

        def health(self, now):
            return {"status": "FRESH"}

        def close(self):
            pass

    status = queue.Queue()
    run_collector_loop(logging.getLogger("netwatch.test"), Store(), Collector(), "SOURCE:TEST", "TEST",
                       0, None, status, stop)
    assert status.get_nowait()["action"] == "WORKER_HEARTBEAT"  # heartbeat still sent
