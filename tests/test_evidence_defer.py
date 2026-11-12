"""A busy security store defers evidence results instead of ending the capture worker."""

import logging
import queue
import sqlite3

import netwatch_workers
from netwatch_core import make_message


def test_busy_store_defers_then_publishes_on_retry(monkeypatch):
    calls = []

    def publish(store, status_queue, message):
        calls.append(message)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(netwatch_workers, "publish_detection", publish)
    deferred, log = [], logging.getLogger("netwatch.test")
    message = make_message("IO_WORKER", "EVIDENCE_SAVED", "UI_SHELL", {"message": "saved"})
    # None, not False: the core counts only a False (full presentation queue) as a dropped alert.
    assert netwatch_workers.publish_or_defer(None, queue.Queue(), message, deferred, log) is None
    assert deferred == [message]  # kept, not lost and not raised
    waiting, deferred[:] = list(deferred), []
    for m in waiting:
        netwatch_workers.publish_or_defer(None, queue.Queue(), m, deferred, log)
    assert deferred == [] and calls[-1] is message


def test_deferral_is_bounded(monkeypatch):
    def locked(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(netwatch_workers, "publish_detection", locked)
    deferred = [object()] * 3
    netwatch_workers.publish_or_defer(None, queue.Queue(), {"x": 1}, deferred, logging.getLogger("t"), limit=3)
    assert len(deferred) == 3
