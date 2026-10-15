"""Hard disk admission floor: refusal, exact gaps, health and automatic recovery."""

import shutil
import time
from collections import namedtuple

import pytest

from netwatch_capture import parse_ethernet_frame
from netwatch_control import ControlCaptureWorker, ControlCollector
from netwatch_core import disk_admission
from netwatch_evidence import EvidenceRecorder
from netwatch_security_store import DurableIncidentStore
from tests.test_control import ra_frame
from tests.test_sources import append, collector, record
from tests.test_spool import _sample_rows

FLOOR = 1_000_000
Usage = namedtuple("Usage", "total used free")


@pytest.fixture
def disk(monkeypatch):
    state = {"free": 10 * FLOOR}
    monkeypatch.setattr(shutil, "disk_usage", lambda path: Usage(100 * FLOOR, 0, state["free"]))
    return state


def test_disk_admission_floor_and_unmeasurable_volume(disk, monkeypatch, tmp_path):
    assert disk_admission(tmp_path / "x.db", FLOOR) == (True, 10 * FLOOR)
    disk["free"] = FLOOR - 1
    assert disk_admission(tmp_path / "x.db", FLOOR) == (False, FLOOR - 1)
    assert disk_admission(tmp_path / "x.db", 0)[0]

    def broken(path):
        raise OSError("no volume")
    monkeypatch.setattr(shutil, "disk_usage", broken)
    assert disk_admission(tmp_path / "x.db", FLOOR) == (True, None)


def test_spool_refuses_below_floor_with_exact_gap_and_recovers(disk, tmp_path):
    from netwatch_spool import TelemetrySpool

    spool = TelemetrySpool(str(tmp_path / "spool.db"), min_free_bytes=FLOOR)
    store = DurableIncidentStore(tmp_path / "security.db")
    disk["free"] = FLOOR - 1
    assert spool.enqueue_batch("b-1", _sample_rows(3), [["o"]])[:2] == (False, "disk_floor")
    assert spool.enqueue_batch("b-2", _sample_rows(2, start_id=3), [])[:2] == (False, "disk_floor")
    assert spool.count_pending()["batches"] == 0
    spool.transfer_gaps(store)
    health = store.source_health("SPOOL:" + spool.identity)
    assert health["status"] == "DEGRADED" and health["disk_admission"] == "refusing"
    assert health["disk_floor_refused_batches"] == 2 and health["dropped_rows"] == 5
    assert health["dropped_observations"] == 1 and health["disk_free_bytes"] == FLOOR - 1
    gap = store.spool_gaps()[0]
    assert gap["reason"] == "disk_floor" and gap["loss_batches"] == 2 and gap["dropped_rows"] == 5

    disk["free"] = FLOOR
    assert spool.enqueue_batch("b-3", _sample_rows(1, start_id=9), [])[:2] == (True, "spooled")
    spool.transfer_gaps(store)
    health = store.source_health("SPOOL:" + spool.identity)
    assert health["disk_admission"] == "open" and health["disk_floor_refused_batches"] == 2
    spool.close()
    store.close()


def _wait(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    return predicate()


def test_control_collector_refuses_below_floor_and_commits_one_exact_gap(disk, tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    worker = ControlCaptureWorker(ControlCollector(store, {"DISK_MIN_FREE_BYTES": FLOOR}), heartbeat_sec=0.1)
    frame = ra_frame()
    data = parse_ethernet_frame(frame, 100)[1]
    disk["free"] = FLOOR - 1
    for _ in range(3):
        assert worker.submit(frame, data)
    assert _wait(lambda: worker.disk_drops == 3)
    health = worker.health()
    assert health["status"] == "DEGRADED"
    assert health["disk"] == {"admitted": False, "free_bytes": FLOOR - 1, "floor_bytes": FLOOR, "refused_frames": 3}
    assert store.source_events("CONTROL", event_type="ipv6_ra") == []
    assert store.source_events("CONTROL", event_type="collector_gap") == []

    disk["free"] = 2 * FLOOR
    assert _wait(lambda: store.source_events("CONTROL", event_type="collector_gap"))
    gaps = store.source_events("CONTROL", event_type="collector_gap")
    assert len(gaps) == 1 and gaps[0]["native"]["count"] == 3
    assert "DISK_MIN_FREE_BYTES" in gaps[0]["native"]["reason"]
    assert worker.submit(frame, data)
    assert _wait(lambda: worker.accepted == 1)
    assert worker.close()
    assert store.source_health(worker.collector.source_key)["disk"]["admitted"]
    store.close()


def test_control_gap_is_flushed_at_stop_while_still_below_floor(disk, tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    worker = ControlCaptureWorker(ControlCollector(store, {"DISK_MIN_FREE_BYTES": FLOOR}), heartbeat_sec=0.1)
    frame = ra_frame()
    disk["free"] = 0
    assert worker.submit(frame, parse_ethernet_frame(frame, 100)[1])
    assert _wait(lambda: worker.disk_drops == 1)
    assert worker.close()
    assert store.source_events("CONTROL", event_type="collector_gap")[0]["native"]["count"] == 1
    store.close()


def test_evidence_capture_refused_below_floor_then_written(disk, tmp_path):
    recorder = EvidenceRecorder(str(tmp_path), pre_sec=0, post_sec=0, min_free_bytes=FLOOR)
    recorder.add(10, b"x" * 60)
    disk["free"] = FLOOR - 1
    recorder.request({"trigger_ts": 10, "action": "ALERT", "correlation_id": "a"}, now=10)
    recorder.poll(now=10)
    recorder.write_jobs.join()
    failed = recorder.poll(now=10)[0]
    assert not failed["ok"] and "below the" in failed["error"]
    assert not list(tmp_path.glob("*.pcap"))
    disk["free"] = FLOOR
    recorder.request({"trigger_ts": 10, "action": "ALERT", "correlation_id": "b"}, now=10)
    recorder.poll(now=10)
    recorder.write_jobs.join()
    assert recorder.poll(now=10)[0]["ok"]
    recorder.close()


def test_eve_collection_pauses_below_floor_without_loss(disk, tmp_path):
    path = tmp_path / "eve.json"
    append(path, record("flow"), record("dns"))
    store, source = collector(tmp_path, DISK_MIN_FREE_BYTES=FLOOR)
    disk["free"] = FLOOR - 1
    assert source.poll(now=100) == 0
    assert store.source_events("SURICATA") == []
    health = source.health(now=100)
    assert health["status"] == "DEGRADED" and not health["disk"]["admitted"]
    disk["free"] = FLOOR
    assert source.poll(now=100) == 2
    assert source.health(now=100)["disk"]["admitted"]
    store.close()
