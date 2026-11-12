"""Stream pages walk forward from the cursor and never skip a record of their own stream."""

from netwatch_security_store import DurableIncidentStore


def accept(store, n, event_type):
    normalized = {"event_id": f"e{n}", "source": "CONTROL", "sensor_id": "s", "event_type": event_type,
                  "event_time": float(n), "received_at": float(n)}
    store.accept_source_record("CONTROL:test", {"n": n}, normalized, {"n": n})


def test_page_steps_over_other_streams_without_missing_rows(tmp_path, monkeypatch):
    store = DurableIncidentStore(str(tmp_path / "s.db"))
    monkeypatch.setattr(DurableIncidentStore, "STREAM_SCAN_WINDOW", 3)
    kinds = ["icmp"] * 7 + ["arp"] + ["icmp"] * 5 + ["arp", "arp"]
    for n, kind in enumerate(kinds):
        accept(store, n, kind)
    seen, after = [], 0
    while True:
        rows, after_next = store.source_stream_page("CONTROL", "arp", after, limit=1)
        seen += [row["event_id"] for row in rows]
        if after_next == after:
            break
        assert after_next > after
        after = after_next
    assert seen == ["e7", "e13", "e14"]
    assert store.source_stream_page("CONTROL", "dhcp", 0, 32) == ([], 3)  # empty stream still advances
    assert [row["event_id"] for row in store.source_stream("CONTROL", "arp", 0, 32)] == ["e7"]  # pages past empty windows
    store.close()
