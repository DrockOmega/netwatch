"""Daily off-host archive of packet history and finished Suricata EVE files (rclone remote, e.g. Google Drive).

    python netwatch_archive.py --base-dir <runtime-directory> --remote gdrive:NetWatch-Archive \\
        [--rclone rclone] [--rclone-config <rclone.conf>] [--keep-days 90]

Each complete UTC day of the packet ledger not yet archived becomes ``ledger/ledger-<day>.jsonl.gz``
(one JSON object per row). Every EVE file that is no longer Suricata's newest output becomes
``suricata/<name>.gz``. A file is recorded in ``archive/archive-state.json`` only after rclone returns
success (rclone verifies size and hash after each upload), so a failed night is retried by the next run,
as long as local retention has not removed the data first (packet history lasts 3-4 days, EVE 3 days).
The oldest ledger day may already be partly pruned when first archived; its row count is logged.
Each run also snapshots the case side of the security store (every table except the bulk native
payloads, which the EVE files above already carry) in one read transaction, checks it
(``integrity_check`` and row counts against the source snapshot), uploads it as
``cases/cases-<UTC stamp>.db.gz`` and keeps the newest ``CASE_SNAPSHOTS_KEPT`` locally in
``archive/cases``. Remote files older than ``--keep-days`` are deleted. Nothing else local is removed.
"""

import argparse
import datetime as dt
import gzip
import json
import logging
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from netwatch_config import build_config

log = logging.getLogger("netwatch.archive")  # setup_logging("archive") attaches the file handler here
EVE_SETTLE_SEC = 600  # a non-newest EVE file untouched this long is finished
# Raw native records: ~4 GB on the sensor, bounded by native retention, Suricata's already archived as EVE.
CASE_SNAPSHOT_SKIP = frozenset({"security_source_events", "security_source_order", "security_native_pruned"})
CASE_SNAPSHOTS_KEPT = 7


def snapshot_cases(db_path, out_path):
    """Copy every table but ``CASE_SNAPSHOT_SKIP`` (schema, indexes, triggers) into a new file.

    One read transaction on the live WAL store, so the copy is a consistent snapshot, never a file
    copy of a live database. Returns ``{table: rows}`` as read inside that transaction."""
    out_path = Path(out_path)
    out_path.unlink(missing_ok=True)
    conn = sqlite3.connect(out_path, uri=True, isolation_level=None)
    try:
        conn.execute("ATTACH ? AS src", (f"file:{Path(db_path).as_posix()}?mode=ro",))
        conn.execute("BEGIN")
        schema = conn.execute("SELECT type, name, tbl_name, sql FROM src.sqlite_master WHERE sql IS NOT NULL "
                              "AND name NOT LIKE 'sqlite_%' ORDER BY type='table' DESC, rowid").fetchall()
        counts = {}
        for kind, name, table, sql in schema:
            if table in CASE_SNAPSHOT_SKIP:
                continue
            if kind == "table":
                conn.execute(sql)
                conn.execute(f'INSERT INTO main."{name}" SELECT * FROM src."{name}"')
                counts[name] = conn.execute(f'SELECT COUNT(*) FROM src."{name}"').fetchone()[0]
            else:
                conn.execute(sql)
        if conn.execute("SELECT 1 FROM src.sqlite_master WHERE name='sqlite_sequence'").fetchone():
            conn.execute("DELETE FROM main.sqlite_sequence")
            conn.execute("INSERT INTO main.sqlite_sequence SELECT * FROM src.sqlite_sequence WHERE name NOT IN "
                         f"({','.join('?' * len(CASE_SNAPSHOT_SKIP))})", tuple(CASE_SNAPSHOT_SKIP))
        conn.execute("COMMIT")
        conn.execute("DETACH src")
    finally:
        conn.close()
    return counts


def verify_snapshot(path, counts):
    """Open read-only: ``integrity_check`` must be ok and every table hold exactly ``counts`` rows."""
    conn = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    try:
        check = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            raise sqlite3.DatabaseError(f"snapshot integrity_check: {check}")
        found = {name: conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] for name in counts}
    finally:
        conn.close()
    if found != counts:
        raise sqlite3.DatabaseError(f"snapshot row counts differ: {found} != {counts}")


def _json_value(value):
    return value.hex() if isinstance(value, bytes) else value


def export_ledger_day(db_path, day, out_path):
    """Write one UTC day of ``network_events`` as gzip JSON lines; returns the row count.

    Reads hour by hour on autocommit reads so no single snapshot pins the live WAL for the whole day."""
    start = dt.datetime.combine(day, dt.time(), dt.UTC).timestamp()
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    rows = 0
    try:
        with gzip.open(out_path, "wt", encoding="utf-8", compresslevel=6) as out:
            for hour in range(24):
                for row in conn.execute(
                        "SELECT * FROM network_events WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp",
                        (start + hour * 3600, start + (hour + 1) * 3600)):
                    out.write(json.dumps({k: _json_value(row[k]) for k in row.keys()}, separators=(",", ":")))
                    out.write("\n")
                    rows += 1
    finally:
        conn.close()
    return rows


def ledger_days_due(db_path, done, today):
    """Complete UTC days present in the ledger, oldest first, not yet archived."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    try:
        oldest = conn.execute("SELECT MIN(timestamp) FROM network_events").fetchone()[0]
    finally:
        conn.close()
    if oldest is None:
        return []
    day = dt.datetime.fromtimestamp(oldest, dt.UTC).date()
    due = []
    while day < today:
        if day.isoformat() not in done:
            due.append(day)
        day += dt.timedelta(days=1)
    return due


def finished_eve_files(eve_path, now):
    """EVE files beside ``eve_path`` (same name prefix) that Suricata no longer writes."""
    eve_path = Path(eve_path)
    files = [p for p in eve_path.parent.glob(eve_path.name + "*") if p.is_file() and not p.name.endswith(".gz")]
    if len(files) < 2:
        return []
    newest = max(files, key=lambda p: p.stat().st_mtime_ns)
    return sorted(p for p in files if p != newest and now - p.stat().st_mtime >= EVE_SETTLE_SEC)


def gzip_file(src, out_path):
    with open(src, "rb") as raw, gzip.open(out_path, "wb", compresslevel=6) as out:
        while chunk := raw.read(1 << 20):
            out.write(chunk)


def rclone_uploader(rclone, rclone_config):
    def upload(local, remote_path):
        cmd = [rclone, "copyto", str(local), remote_path]
        if rclone_config:
            cmd += ["--config", str(rclone_config)]
        subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
    return upload


def _why(exc):
    detail = getattr(exc, "stderr", None)
    detail = detail.decode(errors="replace").strip()[-500:] if isinstance(detail, bytes) else ""
    return f"{type(exc).__name__}: {exc}" + (f" ({detail})" if detail else "")


def run(config, remote, upload, *, keep_days=90, prune=None, now=None):
    """One archive pass; returns the number of failed items (0 = all done)."""
    now = time.time() if now is None else now
    base = Path(config["DB_NAME"]).parent / "archive"
    staging = base / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    state_path = base / "archive-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    state.setdefault("ledger_days", [])
    state.setdefault("eve_files", {})
    failures = 0

    def save():
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
        os.replace(tmp, state_path)

    today = dt.datetime.fromtimestamp(now, dt.UTC).date()
    for day in ledger_days_due(config["DB_NAME"], set(state["ledger_days"]), today):
        out = staging / f"ledger-{day.isoformat()}.jsonl.gz"
        try:
            rows = export_ledger_day(config["DB_NAME"], day, out)
            upload(out, f"{remote}/ledger/{out.name}")
        except (OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
            failures += 1
            log.error("ledger %s not archived: %s", day, _why(exc))
            continue
        finally:
            out.unlink(missing_ok=True)
        state["ledger_days"].append(day.isoformat())
        save()
        log.info("ledger %s archived: %d rows", day, rows)

    for src in finished_eve_files(config["SURICATA_EVE_PATH"], now):
        stat = src.stat()
        key = f"{stat.st_size}:{stat.st_mtime_ns}"
        if state["eve_files"].get(src.name) == key:
            continue
        out = staging / (src.name + ".gz")
        try:
            gzip_file(src, out)
            upload(out, f"{remote}/suricata/{out.name}")
        except (OSError, subprocess.SubprocessError) as exc:
            failures += 1
            log.error("EVE %s not archived: %s", src.name, _why(exc))
            continue
        finally:
            out.unlink(missing_ok=True)
        state["eve_files"][src.name] = key
        save()
        log.info("EVE %s archived: %d bytes", src.name, stat.st_size)

    if config.get("INCIDENT_DB") and Path(config["INCIDENT_DB"]).exists():
        stamp = dt.datetime.fromtimestamp(now, dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        kept = base / "cases"
        kept.mkdir(exist_ok=True)
        raw, packed = staging / f"cases-{stamp}.db", staging / f"cases-{stamp}.db.gz"
        try:
            counts = snapshot_cases(config["INCIDENT_DB"], raw)
            verify_snapshot(raw, counts)
            gzip_file(raw, packed)
            out = kept / packed.name
            os.replace(packed, out)  # a verified snapshot is kept locally even if the upload fails
            upload(out, f"{remote}/cases/{out.name}")
            log.info("cases snapshot %s archived: %d tables, %d rows", out.name, len(counts), sum(counts.values()))
        except (OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
            failures += 1
            log.error("cases snapshot not archived: %s", _why(exc))
        finally:
            raw.unlink(missing_ok=True)
            packed.unlink(missing_ok=True)
        for old in sorted(kept.glob("cases-*.db.gz"))[:-CASE_SNAPSHOTS_KEPT]:
            old.unlink()

    if prune is not None and keep_days > 0:
        try:
            prune(remote, keep_days)
        except (OSError, subprocess.SubprocessError) as exc:
            failures += 1
            log.error("remote retention failed: %s", _why(exc))
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-dir", required=True, type=Path)
    parser.add_argument("--remote", required=True, help="rclone destination, e.g. gdrive:NetWatch-Archive")
    parser.add_argument("--rclone", default="rclone")
    parser.add_argument("--rclone-config", type=Path)
    parser.add_argument("--keep-days", type=int, default=90)
    args = parser.parse_args(argv)
    config, _ = build_config(str(args.base_dir.resolve()), resource_dir=str(Path(__file__).resolve().parent))
    from netwatch_log import setup_logging

    setup_logging("archive", config)
    remote = args.remote.rstrip("/")

    def prune(remote, keep_days):
        cmd = [args.rclone, "delete", remote, "--min-age", f"{keep_days}d"]
        if args.rclone_config:
            cmd += ["--config", str(args.rclone_config)]
        subprocess.run(cmd, check=True, capture_output=True, timeout=3600)

    failures = run(config, remote, rclone_uploader(args.rclone, args.rclone_config),
                   keep_days=args.keep_days, prune=prune)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
