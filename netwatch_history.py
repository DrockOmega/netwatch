"""Historical query layer over the SQLite telemetry ledger (roadmap #8).

The DOD core writes every observed event to ``telemetry_ledger.db`` (table
``network_events``), but until now that ledger was WRITE-ONLY — there was no way to
ask it anything. This module is the read path: parameterized queries and a few
aggregations (top talkers, top domains/countries, an activity timeline) over the
ledger, returned as plain dicts.

It opens the database READ-ONLY (SQLite WAL allows readers concurrent with the live
writer), builds every query with bound parameters (no string interpolation of user
input), and degrades to empty results if the ledger or table doesn't exist yet.
Pure data access — no Qt/scapy — so it's unit-testable against a temp DB and usable
headless from ``history.py``.
"""

import sqlite3

# Columns selected for an event row, in display order.
EVENT_COLUMNS = ("uuid", "timestamp", "src_ip", "dst_ip", "protocol", "port", "tcp_flags",
                 "ttl", "size_bytes", "country", "sni_domain", "mac_src", "mac_dst")

# Filter key -> (SQL fragment, value transform). All values are bound, never inlined.
_FILTERS = {
    "since": ("timestamp >= ?", float),
    "until": ("timestamp <= ?", float),
    "src": ("src_ip = ?", str),
    "dst": ("dst_ip = ?", str),
    "protocol": ("protocol = ?", lambda v: str(v).upper()),
    "port": ("port = ?", int),
    "country": ("country = ?", lambda v: str(v).upper()),
    "domain": ("sni_domain LIKE ?", lambda v: f"%{v}%"),
    "community_id": ("community_id = ?", str),
}


def timeline_series(rows, *, end_ts, bucket_sec=60, bucket_count=60):
    """Return a dense, fixed-width timeline ending at ``end_ts``.

    SQLite only returns buckets that contain events.  Charts need the missing
    buckets represented explicitly or quiet periods collapse and the time axis
    lies.  Unknown/out-of-window rows are ignored defensively.
    """
    width = max(1, int(bucket_count))
    bucket = max(1, int(bucket_sec))
    end_bucket = int(float(end_ts) // bucket) * bucket
    start_bucket = end_bucket - ((width - 1) * bucket)
    by_bucket = {}
    for row in rows or ():
        try:
            row_bucket = int(row["bucket"])
            if start_bucket <= row_bucket <= end_bucket:
                by_bucket[row_bucket] = {
                    "bucket": row_bucket,
                    "events": int(row.get("events") or 0),
                    "bytes": int(row.get("bytes") or 0),
                }
        except (KeyError, TypeError, ValueError):
            continue
    return [
        by_bucket.get(ts, {"bucket": ts, "events": 0, "bytes": 0})
        for ts in range(start_bucket, end_bucket + bucket, bucket)
    ]


class HistoryStore:
    """Read-only query interface over the telemetry ledger."""

    def __init__(self, db_path, *, read_only=True):
        import os
        if read_only and not os.path.exists(db_path):
            self.conn = sqlite3.connect(":memory:")
        elif read_only:
            # file: URI with mode=ro; immutable readers coexist with the WAL writer.
            self.conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        else:
            self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        from netwatch_db import EVENT_METADATA_COLUMNS
        available = {row[1] for row in self.conn.execute("PRAGMA table_info(network_events)")}
        self.has_packet_count = "packet_count" in available
        self.metadata_columns = tuple(name for name in EVENT_METADATA_COLUMNS if name in available)

    def close(self):
        self.conn.close()

    # --- helpers ---------------------------------------------------------
    def _where(self, filters):
        clauses, params = [], []
        for key, raw in (filters or {}).items():
            if raw is None:
                continue
            if key == "family":
                family = str(raw).lower().replace("ipv", "")
                if family == "4":
                    clauses.append("instr(src_ip, ':') = 0")
                elif family == "6":
                    clauses.append("instr(src_ip, ':') > 0")
                continue
            if key not in _FILTERS:
                continue
            frag, cast = _FILTERS[key]
            clauses.append(frag)
            params.append(cast(raw))
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    def _run(self, sql, params):
        try:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise  # locked/I/O failures must not read as "no traffic"
            return []  # table not created yet (no events persisted) -> empty

    # --- queries ---------------------------------------------------------
    def query(self, filters=None, limit=100, order="desc"):
        """Most recent matching events (or oldest-first with order='asc')."""
        where, params = self._where(filters)
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        columns = EVENT_COLUMNS + (("packet_count",) if self.has_packet_count else ()) + self.metadata_columns
        cols = ", ".join(columns)
        sql = f"SELECT {cols} FROM network_events{where} ORDER BY timestamp {direction} LIMIT ?"
        return self._run(sql, params + [int(limit)])

    def top_talkers(self, filters=None, by="bytes", limit=10, direction="src"):
        """Busiest hosts by total bytes or event count. ``direction`` = src or dst."""
        col = "dst_ip" if direction == "dst" else "src_ip"
        order_col = "bytes" if by == "bytes" else "events"
        where, params = self._where(filters)
        events = "SUM(packet_count)" if self.has_packet_count else "COUNT(*)"
        sql = (f"SELECT {col} AS host, {events} AS events, SUM(size_bytes) AS bytes "
               # +col: grouping by the bare column makes SQLite walk the whole host index
               # instead of the timestamp range (5 s vs 0.4 s for an hour of a 10 GB ledger).
               f"FROM network_events{where} GROUP BY +{col} ORDER BY {order_col} DESC LIMIT ?")
        return self._run(sql, params + [int(limit)])

    def top_domains(self, filters=None, limit=10):
        where, params = self._where(filters)
        joiner = " AND " if where else " WHERE "
        events = "SUM(packet_count)" if self.has_packet_count else "COUNT(*)"
        sql = (f"SELECT sni_domain AS domain, {events} AS events FROM network_events{where}"
               f"{joiner}sni_domain != 'encrypted-payload' GROUP BY sni_domain "
               f"ORDER BY events DESC LIMIT ?")
        return self._run(sql, params + [int(limit)])

    def top_countries(self, filters=None, limit=10):
        where, params = self._where(filters)
        joiner = " AND " if where else " WHERE "
        events = "SUM(packet_count)" if self.has_packet_count else "COUNT(*)"
        sql = (f"SELECT country, {events} AS events, SUM(size_bytes) AS bytes "
               f"FROM network_events{where}{joiner}country != '--' "
               f"GROUP BY country ORDER BY events DESC LIMIT ?")
        return self._run(sql, params + [int(limit)])

    def timeline(self, filters=None, bucket_sec=60):
        """Event + byte counts bucketed into ``bucket_sec`` windows, oldest first."""
        b = max(1, int(bucket_sec))
        where, params = self._where(filters)
        events = "SUM(packet_count)" if self.has_packet_count else "COUNT(*)"
        sql = (f"SELECT CAST(timestamp / {b} AS INT) * {b} AS bucket, {events} AS events, "
               f"SUM(size_bytes) AS bytes FROM network_events{where} "
               f"GROUP BY bucket ORDER BY bucket ASC")
        return self._run(sql, params)

    def summary(self, filters=None):
        where, params = self._where(filters)
        events = "COALESCE(SUM(packet_count), 0)" if self.has_packet_count else "COUNT(*)"
        sql = (f"SELECT {events} AS events, COUNT(DISTINCT src_ip) AS sources, "
               f"COUNT(DISTINCT dst_ip) AS destinations, SUM(size_bytes) AS bytes, "
               f"MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts "
               f"FROM network_events{where}")
        rows = self._run(sql, params)
        return rows[0] if rows else {"events": 0, "sources": 0, "destinations": 0,
                                     "bytes": None, "first_ts": None, "last_ts": None}
