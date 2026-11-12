import struct

from netwatch_evidence import EvidenceRecorder


def test_evidence_recorder_writes_bounded_time_window(tmp_path):
    recorder = EvidenceRecorder(str(tmp_path), pre_sec=2, post_sec=1, max_files=2)
    for timestamp in (7, 8, 9, 10, 11, 12):
        recorder.add(timestamp, bytes([timestamp]) * 20)
    recorder.request({
        "trigger_ts": 10,
        "action": "ALERT",
        "correlation_id": "abc",
        "message": "Original detector finding",
    }, now=10)
    assert recorder.poll(now=10.5) == []
    assert recorder.poll(now=11) == []
    recorder.write_jobs.join()
    result = recorder.poll(now=11)[0]
    assert result["ok"] is True
    assert result["frames"] == 4
    assert result["trigger_message"] == "Original detector finding"
    assert "message" not in result
    with open(result["path"], "rb") as handle:
        raw = handle.read()
    assert struct.unpack_from("<I", raw)[0] == 0xA1B2C3D4
    recorder.close()


def test_evidence_recorder_prunes_oldest_files(tmp_path):
    recorder = EvidenceRecorder(str(tmp_path), pre_sec=0, post_sec=0, max_files=1)
    for index in range(2):
        recorder.add(index + 1, b"frame")
        recorder.request({"trigger_ts": index + 1, "action": "ALERT", "correlation_id": str(index)})
        recorder.poll(now=index + 1, force=True)
        recorder.write_jobs.join()
        assert recorder.poll(now=index + 1)[0]["ok"] is True
    assert len(list(tmp_path.glob("*.pcap"))) == 1
    recorder.close()


def test_evidence_requests_are_coalesced_and_pending_is_bounded(tmp_path):
    recorder = EvidenceRecorder(
        str(tmp_path), post_sec=5, coalesce_sec=1, max_pending=2,
    )
    assert recorder.request({"trigger_ts": 1, "action": "ALERT"}, now=1) is True
    assert recorder.request({"trigger_ts": 1.5, "action": "ALERT"}, now=1.5) is True
    assert len(recorder.pending) == 1
    assert recorder.pending[0]["coalesced"] == 2
    assert recorder.request({"trigger_ts": 3, "action": "DNS"}, now=3) is True
    assert recorder.request({"trigger_ts": 5, "action": "TLS"}, now=5) is False
    recorder.close(now=10)


def test_recorder_outwaits_other_writers(tmp_path):
    from netwatch_evidence import EvidenceRecorder

    recorder = EvidenceRecorder(str(tmp_path / "evidence"), catalog_path=str(tmp_path / "security.db"))
    try:
        assert recorder.catalog.store.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
    finally:
        recorder.close()
