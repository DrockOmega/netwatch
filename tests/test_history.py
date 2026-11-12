"""Unit tests for the historical query layer: filtered queries, aggregations,
timeline bucketing, graceful degradation, and parameterized (injection-safe) input.
Runs against a temp ledger built with the production schema."""

import sqlite3

import pytest

from netwatch_history import HistoryStore, timeline_series

SCHEMA = """CREATE TABLE network_events (
    uuid TEXT PRIMARY KEY, timestamp REAL, mac_src TEXT, mac_dst TEXT,
    src_ip TEXT, dst_ip TEXT, protocol TEXT, port INTEGER,
    tcp_flags TEXT, ttl INTEGER, size_bytes INTEGER, sni_domain TEXT,
    country TEXT DEFAULT '--')"""

# uuid, ts, mac_src, mac_dst, src_ip, dst_ip, proto, port, flags, ttl, size, sni, country
ROWS = [
    ("u1", 1000.0, "aa", "bb", "10.0.0.5", "8.8.8.8", "UDP", 53, "---", 64, 100, "example.com", "US"),
    ("u2", 1010.0, "aa", "bb", "10.0.0.5", "1.1.1.1", "TCP", 443, "PA", 64, 5000, "encrypted-payload", "AU"),
    ("u3", 1020.0, "aa", "bb", "10.0.0.6", "8.8.8.8", "TCP", 443, "PA", 128, 2000, "evil.ru", "RU"),
    ("u4", 1200.0, "cc", "dd", "10.0.0.5", "203.0.113.9", "TCP", 80, "S", 64, 300, "test.example.com", "--"),
]


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "ledger.db"
    conn = sqlite3.connect(str(db))
    conn.execute(SCHEMA)
    conn.executemany("INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", ROWS)
    conn.commit()
    conn.close()
    s = HistoryStore(str(db), read_only=False)
    yield s
    s.close()


def test_summary(store):
    s = store.summary()
    assert s["events"] == 4
    assert s["sources"] == 2          # 10.0.0.5, 10.0.0.6
    assert s["destinations"] == 3
    assert s["bytes"] == 7400
    assert s["first_ts"] == 1000.0 and s["last_ts"] == 1200.0


def test_query_filters(store):
    assert len(store.query({"src": "10.0.0.5"})) == 3
    assert len(store.query({"protocol": "tcp"})) == 3      # case-folded to TCP
    assert len(store.query({"port": 443})) == 2
    assert len(store.query({"country": "ru"})) == 1
    assert len(store.query({"since": 1015})) == 2          # u3, u4


def test_query_domain_like(store):
    rows = store.query({"domain": "example"})
    domains = {r["sni_domain"] for r in rows}
    assert domains == {"example.com", "test.example.com"}


def test_query_order_and_limit(store):
    desc = store.query(limit=2)               # most recent first
    assert [r["timestamp"] for r in desc] == [1200.0, 1020.0]
    asc = store.query(order="asc", limit=1)
    assert asc[0]["timestamp"] == 1000.0


def test_top_talkers(store):
    by_bytes = store.top_talkers(by="bytes")
    assert by_bytes[0]["host"] == "10.0.0.5" and by_bytes[0]["bytes"] == 5400
    by_dst = store.top_talkers(by="bytes", direction="dst")
    assert by_dst[0]["host"] == "1.1.1.1"     # 5000 bytes, the single biggest dst


def test_top_domains_excludes_encrypted(store):
    domains = {r["domain"] for r in store.top_domains()}
    assert "encrypted-payload" not in domains
    assert domains == {"example.com", "evil.ru", "test.example.com"}


def test_top_countries_excludes_unknown(store):
    countries = {r["country"] for r in store.top_countries()}
    assert countries == {"US", "AU", "RU"}    # the '--' row is excluded


def test_timeline_buckets(store):
    tl = store.timeline(bucket_sec=100)
    buckets = {row["bucket"]: row["events"] for row in tl}
    assert buckets == {1000: 3, 1200: 1}      # u1/u2/u3 in the first bucket


def test_filters_combine(store):
    rows = store.query({"src": "10.0.0.5", "protocol": "TCP"})
    assert len(rows) == 2                       # u2, u4 (not u1 which is UDP)


def test_ip_family_filter(store):
    store.conn.execute(
        "INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("u6", 1210.0, "ee", "ff", "2001:db8::10", "2606:4700:4700::1111",
         "UDP", 53, "---", 64, 200, "example.net", "US"),
    )
    store.conn.commit()
    assert len(store.query({"family": 4})) == 4
    rows = store.query({"family": "IPv6"})
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "2001:db8::10"


def test_injection_is_parameterized(store):
    # A malicious value must be treated as a literal, never executed.
    rows = store.query({"domain": "'; DROP TABLE network_events; --"})
    assert rows == []
    assert store.summary()["events"] == 4       # table intact


def test_missing_table_degrades(tmp_path):
    empty = tmp_path / "empty.db"
    sqlite3.connect(str(empty)).close()         # valid db, no table
    s = HistoryStore(str(empty), read_only=False)
    assert s.query() == []
    assert s.summary()["events"] == 0
    s.close()


def test_timeline_series_fills_quiet_buckets():
    rows = [
        {"bucket": 900, "events": 2, "bytes": 100},
        {"bucket": 1020, "events": 3, "bytes": 250},
    ]
    dense = timeline_series(rows, end_ts=1079, bucket_sec=60, bucket_count=4)
    assert [row["bucket"] for row in dense] == [840, 900, 960, 1020]
    assert [row["events"] for row in dense] == [0, 2, 0, 3]
    assert [row["bytes"] for row in dense] == [0, 100, 0, 250]


def test_weighted_compacted_rows_preserve_packet_event_totals(tmp_path):
    db = tmp_path / "weighted.db"
    conn = sqlite3.connect(str(db))
    conn.execute(SCHEMA[:-1] + ", packet_count INTEGER NOT NULL DEFAULT 1)")
    conn.execute(
        "INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (*ROWS[0], 7),
    )
    conn.commit()
    conn.close()
    weighted = HistoryStore(str(db), read_only=False)
    try:
        assert weighted.summary()["events"] == 7
        assert weighted.timeline(bucket_sec=60)[0]["events"] == 7
        assert weighted.top_talkers()[0]["events"] == 7
        assert weighted.query()[0]["packet_count"] == 7
    finally:
        weighted.close()


def test_empty_compacted_ledger_summary_reports_zero_events(tmp_path):
    db = tmp_path / "empty-weighted.db"
    conn = sqlite3.connect(str(db))
    conn.execute(SCHEMA[:-1] + ", packet_count INTEGER NOT NULL DEFAULT 1)")
    conn.close()
    weighted = HistoryStore(str(db), read_only=False)
    try:
        assert weighted.summary()["events"] == 0
    finally:
        weighted.close()


def test_ledger_read_failure_raises_instead_of_empty(tmp_path):
    db = tmp_path / "ledger.db"
    conn = sqlite3.connect(str(db))
    conn.execute(SCHEMA)
    conn.commit()
    s = HistoryStore(str(db), read_only=False)
    s.conn.execute("PRAGMA busy_timeout=0")
    conn.execute("BEGIN EXCLUSIVE")              # writer holds the ledger: reads fail "database is locked"
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        s.query()
    s.close()
    conn.close()
