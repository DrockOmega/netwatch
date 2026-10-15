import json
import os
import sqlite3

import pytest

from tests.test_sources import append, collector, record

STATS = lambda packets, drops: {"capture": {"kernel_packets": packets, "kernel_drops": drops}}  # noqa: E731


def reject(store, marker):
    store.conn.execute(f"""CREATE TRIGGER reject_marked BEFORE INSERT ON security_source_events
                           WHEN NEW.native LIKE '%{marker}%'
                           BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")


def test_retry_after_failed_batch_notifies_once_per_stored_detection(tmp_path):
    append(tmp_path / "eve.json", record(), record(boom=1, src_port=2))
    store, source = collector(tmp_path)
    reject(store, "boom")
    notifications = []
    with pytest.raises(sqlite3.IntegrityError):
        source.poll(notifications.append, now=100)
    assert notifications == []  # The first alert was accepted in the failed batch but never committed.
    store.conn.execute("DROP TRIGGER reject_marked")
    source.poll(notifications.append, now=100)
    ids = [item["data"]["source_event_id"] for item in notifications]
    assert len(ids) == len(set(ids)) == len(store.source_events("SURICATA", event_type="alert")) == 2
    source.close()
    store.close()


def test_a_poll_of_several_batches_notifies_each_detection_once(tmp_path):
    append(tmp_path / "eve.json", *(record(src_port=1000 + i) for i in range(250)))
    store, source = collector(tmp_path)
    notifications = []
    source.poll(notifications.append, now=100)
    ids = [item["data"]["source_event_id"] for item in notifications]
    assert len(ids) == len(set(ids)) == 250
    source.close()
    store.close()


def test_an_overflowing_number_is_kept_as_a_collection_error_not_retried(tmp_path):
    path = tmp_path / "eve.json"
    with path.open("ab") as handle:
        handle.write(json.dumps(record()).replace('"src_port": 12345', '"src_port": 1e999').encode() + b"\n")
    append(path, record(src_port=2))
    store, source = collector(tmp_path)
    notifications = []
    source.poll(notifications.append, now=100)
    assert source.error is None
    assert sorted(item["action"] for item in notifications)[0] == "SOURCE_COLLECTION_ERROR" and len(notifications) == 2
    assert len(store.source_events("SURICATA", event_type="collector_error")) == 1
    source.close()
    store.close()


def test_rolled_back_drops_stats_still_degrade_after_retry(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record("stats", stats=STATS(1, 0)))
    store, source = collector(tmp_path)
    source.poll(now=100)
    append(path, record("stats", timestamp=101, boom=1, stats=STATS(5, 3)))
    reject(store, "boom")
    with pytest.raises(sqlite3.IntegrityError):
        source.poll(now=101)
    store.conn.execute("DROP TRIGGER reject_marked")
    source.poll(now=101)
    assert source.health(101)["status"] == "DEGRADED"
    source.close()
    store.close()


def test_stale_engine_outranks_errors_but_keeps_them(tmp_path):
    path = tmp_path / "eve.json"
    append(path, record("stats", stats=STATS(1, 0)))
    store, source = collector(tmp_path)
    source.poll(now=100)
    append(path, record("flow", boom=1))
    reject(store, "boom")
    with pytest.raises(sqlite3.IntegrityError):
        source.poll(now=101)
    assert source.health(101)["status"] == "DEGRADED"
    health = source.health(200)  # Stats are older than the timeout; the file was just written.
    assert health["status"] == "LAGGING" and health["errors"]
    os.utime(path, (0, 0))
    health = source.health(200)
    assert health["status"] == "STALE" and health["errors"]
    source.close()
    store.close()


def test_old_stats_with_drops_are_stale_not_degraded(tmp_path):
    append(tmp_path / "eve.json", record("stats", timestamp=10, stats=STATS(1, 0)),
           record("stats", timestamp=11, stats=STATS(5, 2)))
    store, source = collector(tmp_path)
    source.poll(now=100)
    assert source.health(100)["status"] == "STALE"
    source.close()
    store.close()



def test_rotated_file_ending_mid_line_is_finalized_once_quiet(tmp_path):
    rotated = tmp_path / "eve.json.1"
    rotated.write_bytes(json.dumps(record()).encode() + b"\n" + json.dumps(record())[:30].encode())
    store, source = collector(tmp_path)
    source.poll(now=100)
    assert source.health(100)["status"] == "PARTIAL_WRITE"  # Inside the grace period.
    os.utime(rotated, (1, 1))
    source.poll(now=100)
    rows = store.source_events("SURICATA", event_type="collector_error")
    assert [row["native"]["reason"] for row in rows] == ["truncated_final_record"]
    assert source.reader.handles == {}
    source.poll(now=100)
    assert source.health(100)["status"] != "PARTIAL_WRITE"
    assert len(store.source_events("SURICATA", event_type="collector_error")) == 1
    source.close()
    store.close()


def test_vanished_unread_file_reports_one_gap_and_drained_file_none(tmp_path):
    unread, drained = tmp_path / "eve.1.json", tmp_path / "eve.2.json"
    tail = json.dumps(record())[:30].encode()
    unread.write_bytes(json.dumps(record()).encode() + b"\n" + tail)
    append(drained, record())
    store, source = collector(tmp_path, path=tmp_path / "eve.*.json")
    source.poll(now=100)
    source.close()
    (tmp_path / "archive").mkdir()
    for moved in (unread, drained):
        moved.rename(tmp_path / "archive" / moved.name)
    for _ in range(2):  # A second new reader must not repeat the gap.
        store, source = collector(tmp_path, path=tmp_path / "eve.*.json")
        source.poll(now=100)
        source.close()
    gaps = [row["native"] for row in store.source_events("SURICATA", event_type="collector_gap")
            if row["native"]["reason"] == "source_file_left_glob_unread"]
    assert len(gaps) == 1 and gaps[0]["unread_bytes_at_least"] == len(tail)
    store.close()
