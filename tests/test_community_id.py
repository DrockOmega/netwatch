"""Community ID v1 vectors and its attachment to NetWatch's compacted ledger rows."""

import queue
import sqlite3
import struct
import threading

import pytest

import netwatch_db
from netwatch_capture import parse_ethernet_frame
from netwatch_core import community_id_v1, ip_str, make_message
from netwatch_db import compact_event_rows, db_persistence_worker, packet_row_metadata, row_community_id
from tests.test_capture import ethernet, ipv4, ipv6, tcp, udp

# Copied verbatim from corelight/community-id-spec baseline/baseline_deflt.json (seed 0, base64).
# ICMP rows carry the spec's port equivalents: type as sport, code/counterpart as dport.
SPEC_BASELINE = [
    (58, 'fe80::200:86ff:fe05:80da', 135, 'fe80::260:97ff:fe07:69ea', 136, '1:dGHyGvjMfljg6Bppwm3bg0LO8TY='),
    (58, 'fe80::260:97ff:fe07:69ea', 136, 'fe80::200:86ff:fe05:80da', 135, '1:dGHyGvjMfljg6Bppwm3bg0LO8TY='),
    (58, 'fe80::260:97ff:fe07:69ea', 135, 'fe80::200:86ff:fe05:80da', 136, '1:zavyT/cezQr1fmImYCwYnMXbgck='),
    (58, 'fe80::200:86ff:fe05:80da', 136, 'fe80::260:97ff:fe07:69ea', 135, '1:zavyT/cezQr1fmImYCwYnMXbgck='),
    (58, '3ffe:501:1800:2345::2', 3, '3ffe:507:0:1:200:86ff:fe05:80da', 0, '1:2ObVBgIn28oZvibYZhZMBgh7WdQ='),
    (58, '3ffe:501:410:0:2c0:dfff:fe47:33e', 1, '3ffe:507:0:1:200:86ff:fe05:80da', 4, '1:hLZd0XGWojozrvxqE0dWB1iM6R0='),
    (58, '3ffe:507:0:1:200:86ff:fe05:80da', 128, '3ffe:501:0:1001::2', 129, '1:+TW+HtLHvV1xnGhV1lv7XoJrqQg='),
    (58, '3ffe:501:0:1001::2', 129, '3ffe:507:0:1:200:86ff:fe05:80da', 128, '1:+TW+HtLHvV1xnGhV1lv7XoJrqQg='),
    (58, 'fe80::200:86ff:fe05:80da', 133, 'ff02::2', 134, '1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0='),
    (58, 'fe80::260:97ff:fe07:69ea', 134, 'ff02::1', 133, '1:pkvHqCL88/tg1k4cPigmZXUtL00='),
    (1, '192.168.0.89', 8, '192.168.0.1', 0, '1:X0snYXpgwiv9TZtqg64sgzUn6Dk='),
    (1, '192.168.0.1', 0, '192.168.0.89', 8, '1:X0snYXpgwiv9TZtqg64sgzUn6Dk='),
    (1, '10.0.0.1', 11, '10.0.0.2', 0, '1:YHxtAirCG//0OzkcVAukqKQN9xM='),
    (6, '2001:470:e5bf:dead:4957:2174:e82c:4887', 63943, '2607:f8b0:400c:c03::1a', 25, '1:/qFaeAR+gFe1KYjMzVDsMv+wgU4='),
    (6, '2607:f8b0:400c:c03::1a', 25, '2001:470:e5bf:dead:4957:2174:e82c:4887', 63943, '1:/qFaeAR+gFe1KYjMzVDsMv+wgU4='),
    (132, '192.168.170.8', 7, '192.168.170.56', 7, '1:MP2EtRCAUIZvTw6MxJHLV7N7JDs='),
    (132, '192.168.170.56', 7, '192.168.170.8', 7, '1:MP2EtRCAUIZvTw6MxJHLV7N7JDs='),
    (6, '128.232.110.120', 34855, '66.35.250.204', 80, '1:LQU9qZlK+B5F3KDmev6m5PMibrg='),
    (6, '66.35.250.204', 80, '128.232.110.120', 34855, '1:LQU9qZlK+B5F3KDmev6m5PMibrg='),
    (17, '192.168.1.52', 54585, '8.8.8.8', 53, '1:d/FP5EW3wiY1vCndhwleRRKHowQ='),
    (17, '8.8.8.8', 53, '192.168.1.52', 54585, '1:d/FP5EW3wiY1vCndhwleRRKHowQ='),
    (46, '10.1.12.1', None, '10.1.12.2', None, '1:KHlLkgoJW7ifUTyTSgyVfkFHzKw='),
    (46, '10.1.12.2', None, '10.1.12.1', None, '1:KHlLkgoJW7ifUTyTSgyVfkFHzKw='),
]


@pytest.mark.parametrize(("proto", "saddr", "sport", "daddr", "dport", "expected"), SPEC_BASELINE)
def test_spec_baseline_vectors(proto, saddr, sport, daddr, dport, expected):
    assert community_id_v1(proto, saddr, sport, daddr, dport) == expected


def test_icmp_reply_code_maps_to_request_and_one_way_types_keep_direction():
    assert community_id_v1(1, "192.168.0.1", 0, "192.168.0.89", 0) == "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="
    assert community_id_v1(1, "10.0.0.2", 3, "10.0.0.1", 1) != community_id_v1(1, "10.0.0.1", 3, "10.0.0.2", 1)
    assert community_id_v1(6, "10.0.0.1", 1, "10.0.0.2", 2, seed=1) != community_id_v1(6, "10.0.0.1", 1, "10.0.0.2", 2)


def ledger_row(frame, uuid="e"):
    """The row netwatch_workers builds for one parsed frame."""
    kind, event = parse_ethernet_frame(frame, timestamp=10.5)
    assert kind == "packet"
    return (uuid, 10.5, "src", "dst", ip_str(event["src_ip"]), ip_str(event["dst_ip"]), event["protocol"],
            event["port"], event["tcp_flags"], event["ttl"], event["size_bytes"], event["sni_domain"], "--", 1,
            *packet_row_metadata({**event, "sensor_id": "s", "interface": "eth0"}))


def icmp(icmp_type, code=0):
    return struct.pack("!BBHI", icmp_type, code, 0, 0)


def test_captured_rows_carry_the_spec_id_in_both_directions():
    out = ledger_row(ethernet(ipv4(tcp(sport=34855, dport=80), 6, "128.232.110.120", "66.35.250.204")))
    back = ledger_row(ethernet(ipv4(tcp(sport=80, dport=34855), 6, "66.35.250.204", "128.232.110.120")))
    assert row_community_id(out) == row_community_id(back) == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    dns = ledger_row(ethernet(ipv4(udp(sport=54585, dport=53), 17, "192.168.1.52", "8.8.8.8")))
    assert row_community_id(dns) == "1:d/FP5EW3wiY1vCndhwleRRKHowQ="
    ping = ledger_row(ethernet(ipv4(icmp(8), 1, "192.168.0.89", "192.168.0.1")))
    pong = ledger_row(ethernet(ipv4(icmp(0), 1, "192.168.0.1", "192.168.0.89")))
    assert row_community_id(ping) == row_community_id(pong) == "1:X0snYXpgwiv9TZtqg64sgzUn6Dk="
    v6 = ledger_row(ethernet(ipv6(udp(sport=5000, dport=53), 17), ether_type=0x86DD))
    assert row_community_id(v6) == community_id_v1(17, "2601:db8::10", 5000, "2606:4700:4700::1111", 53)
    # Compaction keeps every field the derivation reads.
    assert row_community_id(compact_event_rows([out])[0]) == row_community_id(out)


def test_rows_without_known_ports_get_no_id():
    first = ipv4(tcp(sport=1, dport=2), 6)
    later = first[:6] + struct.pack("!H", 185) + first[8:]  # fragment offset > 0
    assert row_community_id(ledger_row(ethernet(later))) is None
    assert row_community_id(ledger_row(ethernet(ipv4(b"\x00" * 8, 47)))) is None  # GRE: no ports recorded
    legacy = ["v1", 1.0, "s", "d", "10.0.0.1", "8.8.8.8", "TCP", 443, "A", 64, 60, "x", "US", 1,
              None, "null", "unknown", "unknown", 1, "{}"]  # a version-1 row already in a ledger
    assert row_community_id(legacy) is None


def test_worker_migrates_existing_ledger_and_indexes_new_rows(tmp_path, monkeypatch):
    path = tmp_path / "ledger.db"
    with sqlite3.connect(path) as conn:  # A version-2 ledger from before Community ID.
        conn.execute("""CREATE TABLE network_events (
            uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, mac_dst TEXT, src_ip TEXT, dst_ip TEXT,
            protocol TEXT, port INTEGER, tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER, sni_domain TEXT,
            country TEXT DEFAULT '--', packet_count INTEGER NOT NULL DEFAULT 1, source_port INTEGER,
            vlan_ids TEXT NOT NULL DEFAULT 'null', sensor_id TEXT NOT NULL DEFAULT 'unknown',
            capture_interface TEXT NOT NULL DEFAULT 'unknown', event_version INTEGER NOT NULL DEFAULT 1,
            packet_metadata TEXT NOT NULL DEFAULT '{}')""")
        conn.execute("INSERT INTO network_events VALUES (" + ",".join("?" * 20) + ")",
                     ledger_row(ethernet(ipv4(tcp(), 6)), "old"))
    shutdown = threading.Event()
    seen = []

    def inspect(conn, **_kwargs):
        rows = conn.execute("SELECT uuid, community_id FROM network_events ORDER BY uuid").fetchall()
        if len(rows) == 2:
            seen.extend(rows)
            seen.append(conn.execute("EXPLAIN QUERY PLAN SELECT * FROM network_events WHERE community_id=?",
                                     ("x",)).fetchall())
            shutdown.set()
        return 0, False

    monkeypatch.setattr(netwatch_db, "prune_network_events", inspect)
    db_queue = queue.Queue()
    new = ledger_row(ethernet(ipv4(tcp(sport=34855, dport=80), 6, "128.232.110.120", "66.35.250.204")), "new")
    db_queue.put(make_message("DOD_CORE", "DB_BATCH", "DB_WORKER", {"rows": [list(new)]}))
    config = {"DB_NAME": str(path), "DB_RETENTION_DAYS": 0, "DB_MAX_ROWS": 1, "DB_PRUNE_INTERVAL_SEC": 0,
              "DB_PRUNE_BATCH_ROWS": 1, "LOG_DIR": "", "LOG_TO_CONSOLE": False,
              "SPOOL_PATH": str(tmp_path / "spool.db"), "DISK_MIN_FREE_BYTES": 0}
    worker = threading.Thread(target=db_persistence_worker, args=(db_queue, queue.Queue(), config, shutdown))
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive()
    # Existing rows are kept as they were (no backfill); new rows carry the ID; lookups use the index.
    assert seen[:2] == [("new", "1:LQU9qZlK+B5F3KDmev6m5PMibrg="), ("old", None)]
    assert "idx_events_community" in str(seen[2])
