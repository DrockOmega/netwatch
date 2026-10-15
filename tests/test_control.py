"""Raw protocol fixtures independent of the Scapy control decoder."""

import ipaddress
import struct
import time

import pytest

from netwatch_capture import parse_ethernet_frame
from netwatch_control import ControlCaptureWorker, ControlCollector
from netwatch_security_store import DurableIncidentStore
from tests.test_capture import DST_MAC, SRC_MAC, ethernet, ipv4, ipv6, udp


def _checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def _nd_frame(body, src="fe80::1", dst="ff02::1", hop_limit=255):
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + struct.pack("!I3xB", len(body), 58)
    body = body[:2] + struct.pack("!H", _checksum(pseudo + body)) + body[4:]
    header = bytearray(ipv6(body, 58, src, dst))
    header[7] = hop_limit
    return ethernet(header, 0x86DD)


def ra_frame(hop_limit=255, malformed_option=False):
    body = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0xc0, 1800, 0, 0)
    body += struct.pack("!BBBBIII16s", 3, 4, 64, 0xc0, 3600, 1800, 0,
                        ipaddress.ip_address("2001:db8:42::").packed)
    body += b"\x01\x00" if malformed_option else struct.pack("!BB6s", 1, 1, SRC_MAC)
    return _nd_frame(body, hop_limit=hop_limit)


def dhcp_frame(server="10.0.0.1", message=2):
    body = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, 42, 0, 0,
                       b"\0" * 4, ipaddress.ip_address("10.0.0.22").packed,
                       b"\0" * 4, b"\0" * 4, SRC_MAC, b"", b"")
    body += b"\x63\x82\x53\x63" + bytes([53, 1, message, 54, 4]) + ipaddress.ip_address(server).packed + b"\xff"
    return ethernet(ipv4(udp(body, sport=67, dport=68), 17, server, "255.255.255.255"))


def dhcp6_frame():
    duid = struct.pack("!HH6s", 3, 1, SRC_MAC)
    prefix = struct.pack("!HHIIB16s", 26, 25, 120, 240, 56, ipaddress.ip_address("2001:db8:100::").packed)
    delegation = struct.pack("!HHIII", 25, 12 + len(prefix), 42, 60, 120) + prefix
    body = b"\x07\x01\x02\x03" + struct.pack("!HH", 2, len(duid)) + duid + delegation
    return ethernet(ipv6(udp(body, sport=547, dport=546), 17, "fe80::1", "fe80::2"), 0x86DD), duid.hex()


def _collect(collector, frame, event_id=None):
    parsed = parse_ethernet_frame(frame, timestamp=100)
    assert parsed is not None
    return collector.process(frame, parsed[1], event_id=event_id, received_at=101)


def test_dhcp_and_ipv6_prefixes_are_durable_and_not_automatically_trusted(tmp_path):
    path = tmp_path / "security.db"
    store = DurableIncidentStore(path)
    collector = ControlCollector(store, {"SENSOR_ID": "sensor-a", "NIC_INTERFACE": "mirror"})
    dhcp = _collect(collector, dhcp_frame(), "dhcp-fixture")
    assert dhcp["summary"]["offered_ip"] == "10.0.0.22"
    assert dhcp["summary"]["server_id"] == "10.0.0.1" and dhcp["summary"]["trust"] == "unconfigured"
    ra = _collect(collector, ra_frame(), "ra-fixture")
    assert ra["summary"]["issues"] == []
    assert ra["summary"]["prefixes"][0]["prefix"] == "2001:db8:42::"
    assert ra["summary"]["trust"] == "unconfigured"
    frame, duid = dhcp6_frame()
    dhcp6 = _collect(collector, frame)
    assert dhcp6["summary"]["server_duid"] == duid
    assert dhcp6["summary"]["delegated_prefixes"][0]["prefix"] == "2001:db8:100::"
    assert dhcp6["summary"]["delegated_prefixes"][0]["plen"] == 56
    assert store.open_count() == 0
    assert len(store.source_events("CONTROL")) == 3
    assert _collect(collector, ra_frame(), "ra-fixture")["event_id"] == "ra-fixture"
    assert len(store.source_events("CONTROL")) == 3
    store.close()
    store = DurableIncidentStore(path)
    saved = store.source_events(event_id="ra-fixture")[0]
    assert bytes.fromhex(saved["native"]["frame"]) == ra_frame()
    assert saved["normalized"]["capture_interface"] == "mirror"
    store.close()


def test_trust_policy_and_nd_checks_commit_review_before_notify(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    notifications = []

    def notify(payload):
        assert store.source_events(event_id=payload["data"]["native_event_id"])
        assert store.open_count() > 0
        notifications.append(payload)

    collector = ControlCollector(store, {"CONTROL_TRUSTED_DHCP_SERVERS": ["10.0.0.1"],
                                         "CONTROL_TRUSTED_RA_MACS": ["00:11:22:33:44:55"]}, notify)
    assert _collect(collector, dhcp_frame())["summary"]["trust"] == "matched"
    _collect(collector, dhcp_frame("10.0.0.2"))
    assert len(notifications) == 1
    assert notifications[0]["data"]["containment_eligible"] is False
    assert notifications[0]["target_id"] == "SYSTEM"
    bad = _collect(collector, ra_frame(hop_limit=64, malformed_option=True))
    assert any("hop limit" in reason for reason in bad["summary"]["issues"])
    assert any("zero length" in reason for reason in bad["summary"]["issues"])
    assert len(notifications) == 2
    tagged = ethernet(struct.pack("!HH", 42, 0x86DD) + ra_frame(hop_limit=64)[14:], 0x8100)
    assert _collect(collector, tagged)["vlan_ids"] == [42]
    assert store.open_count() == 3  # Different VLANs retain separate review contexts.
    body = bytearray(ra_frame()[54:])
    body[2:4] = b"\0\0"
    body[18] = 129  # Prefix Information prefix length exceeds IPv6 width.
    prefix = _collect(collector, _nd_frame(bytes(body)))
    assert any("lifetimes are inconsistent" in reason for reason in prefix["summary"]["issues"])
    store.close()


def test_control_link_protocols_and_vlan_provenance(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    lldp = (struct.pack("!H", (1 << 9) | 7) + b"\x04" + SRC_MAC +
            struct.pack("!H", (2 << 9) | 6) + b"\x05port1" + struct.pack("!HHH", (3 << 9) | 2, 120, 0))
    stp = b"\x42\x42\x03" + struct.pack("!HBBB", 0, 0, 0, 0) + struct.pack("!H6sIH6sHHHHH", 0x8000, SRC_MAC, 0,
                                                                                      0x8000, DST_MAC, 0x8001, 256, 5120, 512, 3840)
    frames = [(ethernet(lldp, 0x88cc), "lldp"), (ethernet(stp, len(stp)), "stp"),
              (ethernet(b"\x02\x01\x00\x00", 0x888e), "eapol")]
    for frame, expected in frames:
        record = _collect(collector, frame)
        assert record["event_type"] == expected
        assert record["summary"]["issues"] == []
        assert record["summary"]["layers"]
    tagged = ethernet(struct.pack("!HH", 42, 0x88cc) + lldp, 0x8100)
    assert _collect(collector, tagged)["vlan_ids"] == [42]
    store.close()


def test_malformed_control_retains_raw_bytes_without_a_fake_decoding(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    frame = ethernet(b"\x01\x00", 0x888e)
    record = _collect(collector, frame)
    assert record["summary"]["decode_error"]
    assert record["summary"]["layers"] == []
    saved = store.source_events(event_id=record["event_id"])[0]
    assert bytes.fromhex(saved["native"]["frame"]) == frame
    assert store.open_count() == 1
    store.close()


def test_overflow_failed_commits_retry_and_unclean_session_are_visible(tmp_path, monkeypatch):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    store.record_source_health(collector.source_key, {"state": "running"})
    process = collector.process
    fail = True

    def failing(*args, **kwargs):
        if fail:
            raise OSError("simulated writer outage")
        return process(*args, **kwargs)

    monkeypatch.setattr(collector, "process", failing)
    worker = ControlCaptureWorker(collector, max_pending=1, heartbeat_sec=0.1)
    frame = ra_frame()
    data = parse_ethernet_frame(frame, 100)[1]
    assert worker.submit(frame, data)
    deadline = time.monotonic() + 2
    while worker.last_error is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker.last_error
    assert worker.submit(frame, data)
    assert not worker.submit(frame, data)
    fail = False
    deadline = time.monotonic() + 3
    while worker.accepted < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker.close()
    records = store.source_events("CONTROL")
    assert len([row for row in records if row["event_type"] == "ipv6_ra"]) == 2
    gaps = [row for row in records if row["event_type"] == "collector_gap"]
    assert len(gaps) == 2
    assert any(row["native"]["count"] == 1 for row in gaps)
    assert store.source_health(collector.source_key)["state"] == "stopped"
    store.close()


def test_invalid_policy_is_rejected_and_invalid_input_records_a_gap(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    for policy in ({"CONTROL_TRUSTED_RA_MACS": ["invalid"]}, {"CONTROL_TRUSTED_DHCP_SERVERS": ["300.1.1.1"]},
                   {"CONTROL_TRUSTED_DHCPV6_DUIDS": ["invalid"]}, {"CONTROL_TRUSTED_DHCPV6_DUIDS": [""]},
                   {"CONTROL_TRUSTED_RA_MACS": ["00:00:00:00:00:00"]}):
        with pytest.raises(ValueError):
            ControlCollector(store, policy)
    worker = ControlCaptureWorker(ControlCollector(store, {}), heartbeat_sec=0.1)
    assert not worker.submit(b"short", {"timestamp": 100})
    assert worker.close()
    assert store.source_events("CONTROL")[0]["native"]["count"] == 1
    store.close()


def test_native_record_finding_and_cursor_roll_back_together(tmp_path):
    import sqlite3

    store = DurableIncidentStore(tmp_path / "security.db")
    notifications = []
    collector = ControlCollector(store, {}, notifications.append)
    store.conn.execute("""CREATE TRIGGER fail_native BEFORE INSERT ON security_source_events
                          BEGIN SELECT RAISE(ABORT, 'simulated storage fault'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        _collect(collector, ra_frame(hop_limit=64), "atomic-fixture")
    assert store.source_events("CONTROL") == []
    assert store.open_count() == 0 and notifications == []
    assert store.cursor(collector.source_key) is None
    store.conn.execute("DROP TRIGGER fail_native")
    _collect(collector, ra_frame(hop_limit=64), "atomic-fixture")
    assert store.open_count() == 1 and len(notifications) == 1
    assert store.cursor(collector.source_key)["last_event_id"] == "atomic-fixture"
    store.close()


def test_arp_and_neighbor_changes_keep_each_raw_observation(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, SRC_MAC,
                      ipaddress.ip_address("10.0.0.22").packed, DST_MAC, ipaddress.ip_address("10.0.0.1").packed)
    claim = _collect(collector, ethernet(arp, 0x0806))
    assert claim["event_type"] == "arp" and claim["src_ip"] == "10.0.0.22"
    assert claim["summary"]["issues"] == []
    body = struct.pack("!BBHI16s", 136, 0, 0, 0x60000000, ipaddress.ip_address("fe80::22").packed)
    body += struct.pack("!BB6s", 2, 1, SRC_MAC)
    na = _collect(collector, _nd_frame(body, src="fe80::22", dst="fe80::1"))
    assert na["event_type"] == "ipv6_na" and na["summary"]["issues"] == []
    assert any(layer["layer"] == "ICMPv6NDOptDstLLAddr" for layer in na["summary"]["layers"])
    assert len(store.source_events("CONTROL")) == 2
    store.close()


def test_atomic_ipv6_fragment_is_visible_and_not_a_valid_neighbor_advertisement(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {})
    frame = ra_frame()
    original = frame[14:]
    fragment = struct.pack("!BBHI", 58, 0, 0, 42)
    header = bytearray(original[:40])
    header[6] = 44
    struct.pack_into("!H", header, 4, len(original[40:]) + 8)
    framed = ethernet(header + fragment + original[40:], 0x86DD)
    record = _collect(collector, framed)
    assert record["event_type"] == "ipv6_ra"
    assert any("fragment" in reason for reason in record["summary"]["issues"])
    store.close()


def test_busy_store_at_start_does_not_stop_the_control_collector(tmp_path, monkeypatch):
    """A locked health write at start once killed the capture worker (VM 2026-10-08 18:20)."""
    import sqlite3

    store = DurableIncidentStore(tmp_path / "security.db")
    real = store.record_source_health
    calls = []

    def locked_once(*args, **kwargs):
        calls.append(args[0])
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "record_source_health", locked_once)
    worker = ControlCaptureWorker(ControlCollector(store, {}), heartbeat_sec=0.1)
    assert worker.close()
    assert len(calls) > 1 and store.source_health(worker.collector.source_key)  # re-recorded later
    store.close()


def test_a_burst_of_frames_commits_together_and_findings_follow_the_commit(tmp_path):
    """Per-frame commits held the shared writer lock ~1 s each on the sensor VM and starved the core."""
    store = DurableIncidentStore(tmp_path / "security.db")
    found = []
    collector = ControlCollector(store, {}, found.append)
    worker = ControlCaptureWorker(collector, heartbeat_sec=60)
    commits = []
    store.conn.set_trace_callback(lambda sql: sql == "COMMIT" and commits.append(sql))
    frame = ra_frame(hop_limit=64)  # an RA with a non-standard hop limit is a review finding
    data = parse_ethernet_frame(frame, 100)[1]
    with worker.collector.store._lock:  # hold the writer so the burst queues up behind it
        for _ in range(20):
            assert worker.submit(frame, dict(data))
    deadline = time.monotonic() + 3
    while worker.accepted < 20 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert worker.close()
    assert worker.accepted == 20 and len(commits) <= 4  # one burst, plus at most stop/health rows
    assert len([r for r in store.source_events("CONTROL") if r["event_type"] == "ipv6_ra"]) == 20
    assert found  # review findings still presented, after their commit
    store.close()


def test_control_retention_drains_a_backlog_without_waiting_the_interval(tmp_path):
    from tests.test_arp_replay import A, record

    store = DurableIncidentStore(tmp_path / "security.db")
    collector = ControlCollector(store, {"CONTROL_MAX_ROWS": 1, "CONTROL_PRUNE_BATCH_ROWS": 1,
                                         "CONTROL_RETENTION_DAYS": 0, "CONTROL_PRUNE_INTERVAL_SEC": 3600,
                                         "ARP_DETECTION_ENABLED": False})
    for timestamp in range(1, 7):
        record(collector, A, timestamp)
    worker = ControlCaptureWorker(collector, heartbeat_sec=0.1)
    deadline = time.monotonic() + 5
    while len(store.source_events("CONTROL")) > 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert worker.close()
    assert len(store.source_events("CONTROL")) == 1
    store.close()


def test_a_failing_retention_pass_does_not_block_frame_commits(tmp_path, monkeypatch):
    import sqlite3

    store = DurableIncidentStore(tmp_path / "security.db")
    calls = []

    def broken(**kwargs):
        calls.append(kwargs)
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(store, "prune_control_records", broken)
    worker = ControlCaptureWorker(ControlCollector(store, {}), heartbeat_sec=60)
    frame = ra_frame(hop_limit=64)
    data = parse_ethernet_frame(frame, 100)[1]
    for _ in range(5):
        assert worker.submit(frame, dict(data))
    deadline = time.monotonic() + 3
    while worker.accepted < 5 and time.monotonic() < deadline:
        time.sleep(0.01)
    worker.close()
    assert worker.accepted == 5 and len(calls) == 1  # retried at the interval, not every turn
    store.close()


def test_notify_failure_is_counted(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db")

    def boom(payload):
        raise RuntimeError("queue closed")

    collector = ControlCollector(store, {"CONTROL_TRUSTED_DHCP_SERVERS": ["10.0.0.9"]}, boom)
    worker = ControlCaptureWorker(collector, heartbeat_sec=0.1)
    _collect(collector, dhcp_frame())
    assert store.open_count() == 1  # the finding is committed despite the failed notify
    assert collector.notify_failures == 1
    assert worker.health()["notify_failures"] == 1
    store.close()
