"""Unit tests for the cross-process IPC message contract."""

import os
import queue
import threading
import uuid

import pytest

from netwatch_core import (
    MESSAGE_PAYLOAD_KEYSET,
    acquire_single_instance_mutex,
    is_message_payload,
    make_db_batch_message,
    make_message,
    newest_render_data,
    newest_render_events,
    release_single_instance_mutex,
    start_parent_watchdog,
    try_put_drop_oldest,
    try_put_drop_oldest_with_eviction,
)


@pytest.mark.skipif(os.name != "nt", reason="named mutex is Windows-only")
def test_single_instance_mutex_rejects_a_second_owner():
    name = f"Local\\NetWatch.Test.{uuid.uuid4()}"
    first = acquire_single_instance_mutex(name)
    try:
        second = acquire_single_instance_mutex(name)
        assert first is not None
        assert second is None
    finally:
        release_single_instance_mutex(first)


class _DeadParent:
    @staticmethod
    def is_alive():
        return False


def test_parent_watchdog_stops_orphaned_workers():
    shutdown_event = threading.Event()
    watchdog = start_parent_watchdog(
        shutdown_event,
        parent=_DeadParent(),
        interval_sec=0.01,
    )

    assert shutdown_event.wait(0.5)
    watchdog.join(timeout=0.5)
    assert not watchdog.is_alive()


def test_make_message_is_valid():
    msg = make_message("DOD_CORE", "ALERT", "1.2.3.4", {"message": "hi"})
    assert is_message_payload(msg)
    assert set(msg.keys()) == MESSAGE_PAYLOAD_KEYSET


def test_make_message_wraps_non_dict_data():
    msg = make_message("SRC", "ACT", None, data=42)
    assert msg["data"] == {"value": 42}


def test_make_message_coerces_error_to_str():
    msg = make_message("SRC", "ACT", None, error=ValueError("boom"))
    assert msg["error"] == "boom"


def test_make_message_generates_correlation_id():
    a = make_message("SRC", "ACT", None)
    b = make_message("SRC", "ACT", None)
    assert a["correlation_id"] != b["correlation_id"]


def test_is_message_payload_rejects_non_dict():
    assert not is_message_payload("not a dict")
    assert not is_message_payload(None)


def test_is_message_payload_rejects_missing_key():
    msg = make_message("SRC", "ACT", None)
    del msg["error"]
    assert not is_message_payload(msg)


def test_is_message_payload_rejects_extra_key():
    msg = make_message("SRC", "ACT", None)
    msg["rogue"] = 1
    assert not is_message_payload(msg)


def test_is_message_payload_rejects_wrong_type():
    msg = make_message("SRC", "ACT", None)
    msg["data"] = "should be a dict"
    assert not is_message_payload(msg)


def test_try_put_drop_oldest_rejects_invalid_payload():
    q = queue.Queue(maxsize=2)
    assert try_put_drop_oldest(q, {"bogus": True}) is False
    assert q.empty()


def test_try_put_drop_oldest_enqueues_when_room():
    q = queue.Queue(maxsize=2)
    msg = make_message("SRC", "ACT", None)
    assert try_put_drop_oldest(q, msg) is True
    assert q.qsize() == 1


def test_try_put_drop_oldest_drops_oldest_when_full():
    q = queue.Queue(maxsize=1)
    first = make_message("SRC", "ACT", None, {"n": 1})
    second = make_message("SRC", "ACT", None, {"n": 2})
    try_put_drop_oldest(q, first)
    assert try_put_drop_oldest(q, second) is True
    # the queue still holds exactly one item, and it's the newest.
    assert q.qsize() == 1
    assert q.get_nowait()["data"]["n"] == 2


def test_try_put_drop_oldest_reports_evicted_payload():
    q = queue.Queue(maxsize=1)
    first = make_message("SRC", "ACT", None, {"n": 1})
    second = make_message("SRC", "ACT", None, {"n": 2})
    q.put_nowait(first)
    accepted, evicted = try_put_drop_oldest_with_eviction(q, second)
    assert accepted is True
    assert evicted == first


def test_newest_render_events_flattens_batches_and_preserves_volume():
    payloads = [
        make_message("CORE", "RENDER_BATCH", 0, {
            "events": [{"n": 1}, {"n": 2}, {"n": 3}], "total_ingested": 30,
        }),
        make_message("CORE", "RENDER_BATCH", 0, {
            "events": [{"n": 4}, {"n": 5}], "total_ingested": 20,
        }),
    ]
    events, total = newest_render_events(payloads, limit=3)
    assert [event["n"] for event in events] == [3, 4, 5]
    assert total == 50


def test_newest_render_data_preserves_sparse_observations_outside_packet_limit():
    observation = {"n": 1, "web_observation": {"label": "HUMAN LIKELY"}}
    payload = make_message("CORE", "RENDER_BATCH", 0, {
        "events": [observation, *({"n": value} for value in range(2, 202))],
        "observations": [observation],
        "total_ingested": 201,
    })

    events, observations, total = newest_render_data(
        [payload], event_limit=3, observation_limit=10,
    )

    assert [event["n"] for event in events] == [199, 200, 201]
    assert observations == [observation]
    assert total == 201


def test_durable_observation_payload_isolated_from_retry_buffer_clear():
    retry_buffer = [("flow-1", 1.0)]
    payload = make_db_batch_message([], retry_buffer)

    retry_buffer.clear()

    assert payload["data"]["observations"] == (("flow-1", 1.0),)


def test_newest_render_events_accepts_legacy_and_ignores_other_actions():
    payloads = [
        make_message("CORE", "ALERT", 0, {"n": 0}),
        make_message("CORE", "RENDER_UPDATE", 0, {"n": 1}),
    ]
    events, total = newest_render_events(payloads)
    assert events == [{"n": 1}]
    assert total == 1


def test_newest_render_events_rejects_invalid_volume_without_crashing():
    payload = make_message("CORE", "RENDER_BATCH", 0, {
        "events": [{"n": 1}], "total_ingested": float("nan"),
    })
    events, total = newest_render_events([payload])
    assert events == [{"n": 1}]
    assert total == 1
