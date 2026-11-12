"""Operator CLI for querying the NetWatch telemetry ledger (roadmap #8).

Turns the write-only SQLite event ledger into something you can ask questions of:
recent events, top talkers/domains/countries, and an activity timeline. Read-only;
safe to run while the monitor is live (WAL).

Examples:
    python history.py summary
    python history.py query --since 1h --proto TCP --port 443 --limit 20
    python history.py query --domain example --src 10.0.0.5
    python history.py top talkers --by bytes
    python history.py top domains
    python history.py timeline --since 1h --bucket 60
"""

import argparse
import datetime as _dt
import os
import re
import sys
import time

from netwatch_history import HistoryStore

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telemetry_ledger.db")
_REL = re.compile(r"^(\d+)([smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_time(s, now):
    if not s:
        return None
    s = s.strip().lower()
    m = _REL.match(s)
    if m:
        return now - int(m.group(1)) * _UNIT[m.group(2)]
    try:
        return float(s)
    except ValueError:
        return None


def _human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def _hhmmss(ts):
    return _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _filters(args):
    now = time.time()
    f = {"since": _parse_time(getattr(args, "since", None), now),
         "until": _parse_time(getattr(args, "until", None), now),
         "src": args.src, "dst": args.dst, "protocol": args.proto,
         "port": args.port, "domain": args.domain, "country": args.country}
    return {k: v for k, v in f.items() if v is not None}


def cmd_summary(args):
    s = HistoryStore(args.db).summary(_filters(args))
    if not s["events"]:
        print("No events match. (Has the monitor run and persisted to the ledger?)")
        return
    span = ""
    if s["first_ts"] and s["last_ts"]:
        span = f"  span {_hhmmss(s['first_ts'])} -> {_hhmmss(s['last_ts'])}"
    print(f"events {s['events']}   sources {s['sources']}   destinations {s['destinations']}   "
          f"total {_human(s['bytes'])}{span}")


def cmd_query(args):
    rows = HistoryStore(args.db).query(_filters(args), limit=args.limit, order="asc" if args.asc else "desc")
    if not rows:
        print("No events match.")
        return
    print(f"{'TIME':<10}{'SRC':<16}{'DST':<16}{'PROTO':<6}{'PORT':>6}{'SIZE':>9}{'GEO':>5}  DOMAIN")
    print("-" * 96)
    for r in rows:
        dom = r["sni_domain"] if r["sni_domain"] != "encrypted-payload" else ""
        print(f"{_hhmmss(r['timestamp']):<10}{r['src_ip']:<16}{r['dst_ip']:<16}{r['protocol']:<6}"
              f"{r['port']:>6}{_human(r['size_bytes']):>9}{r['country']:>5}  {dom[:40]}")
    print(f"\n{len(rows)} event(s).")


def cmd_top(args):
    store = HistoryStore(args.db)
    f = _filters(args)
    if args.what == "talkers":
        rows = store.top_talkers(f, by=args.by, limit=args.limit, direction="dst" if args.dst_side else "src")
        side = "DST" if args.dst_side else "SRC"
        print(f"{side + ' HOST':<18}{'EVENTS':>8}{'BYTES':>11}")
        print("-" * 37)
        for r in rows:
            print(f"{r['host']:<18}{r['events']:>8}{_human(r['bytes']):>11}")
    elif args.what == "domains":
        rows = store.top_domains(f, limit=args.limit)
        print(f"{'DOMAIN':<46}{'EVENTS':>8}")
        print("-" * 54)
        for r in rows:
            print(f"{(r['domain'] or '')[:45]:<46}{r['events']:>8}")
    else:  # countries
        rows = store.top_countries(f, limit=args.limit)
        print(f"{'COUNTRY':<9}{'EVENTS':>8}{'BYTES':>11}")
        print("-" * 28)
        for r in rows:
            print(f"{r['country']:<9}{r['events']:>8}{_human(r['bytes']):>11}")
    if not rows:
        print("(no data)")


def cmd_timeline(args):
    rows = HistoryStore(args.db).timeline(_filters(args), bucket_sec=args.bucket)
    if not rows:
        print("No events match.")
        return
    peak = max(r["events"] for r in rows) or 1
    width = 48
    print(f"activity per {args.bucket}s bucket (peak {peak} events):")
    for r in rows:
        bar = "#" * max(1, round(r["events"] / peak * width))
        print(f"{_hhmmss(r['bucket'])}  {bar} {r['events']}  ({_human(r['bytes'])})")


def _add_filters(p):
    p.add_argument("--since", help="start time: relative (30s/15m/2h/7d) or epoch")
    p.add_argument("--until", help="end time: relative or epoch")
    p.add_argument("--src", help="exact source IP")
    p.add_argument("--dst", help="exact destination IP")
    p.add_argument("--proto", help="TCP/UDP/IP")
    p.add_argument("--port", type=int, help="exact destination port")
    p.add_argument("--domain", help="substring match on SNI/DNS name")
    p.add_argument("--country", help="ISO2 country code")


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch telemetry-ledger query CLI")
    p.add_argument("--db", default=DEFAULT_DB, help="path to telemetry_ledger.db")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("summary", help="overall stats for the (filtered) ledger")
    _add_filters(s)
    s.set_defaults(func=cmd_summary)

    q = sub.add_parser("query", help="list matching events")
    _add_filters(q)
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--asc", action="store_true", help="oldest first (default newest first)")
    q.set_defaults(func=cmd_query)

    t = sub.add_parser("top", help="aggregations")
    t.add_argument("what", choices=["talkers", "domains", "countries"])
    t.add_argument("--by", choices=["bytes", "count"], default="bytes", help="talkers ordering")
    t.add_argument("--dst-side", action="store_true", help="talkers: group by destination IP")
    t.add_argument("--limit", type=int, default=10)
    _add_filters(t)
    t.set_defaults(func=cmd_top)

    tl = sub.add_parser("timeline", help="ASCII activity timeline")
    tl.add_argument("--bucket", type=int, default=60, help="bucket size in seconds")
    _add_filters(tl)
    tl.set_defaults(func=cmd_timeline)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
