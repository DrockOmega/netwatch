"""Operator CLI for NetWatch DNS analytics.

Read-only view of the DNS analytics ledger (``telemetry_dns.json``): a per-host
summary of query volume and suspicious-signal counts, plus the most recent
flagged domains (DGA / tunneling). No admin, no live capture.

Examples:
    python dns.py list                  # per-host DNS summary (most suspicious first)
    python dns.py recent                # recently flagged domains (DGA / tunnel)
    python dns.py list --json
"""

import argparse
import json
import os
import sys
import time

from netwatch_core import ago
from netwatch_dns import DnsAnalyzer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER = os.path.join(BASE_DIR, "telemetry_dns.json")


def cmd_list(args):
    rows = DnsAnalyzer(ledger_path=args.ledger).snapshot()
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print(f"No DNS data in ledger ({args.ledger}). Run the monitor to populate it.")
        return
    now = time.time()
    print(f"{'HOST':<16}{'QUERIES':>9}{'NXDOMAIN':>10}{'DGA':>6}{'TUNNEL':>8}  LAST")
    print("-" * 70)
    for r in rows:
        print(f"{r['ip']:<16}{r['queries']:>9}{r['nxdomain']:>10}{r['dga_hits']:>6}{r['tunnel_hits']:>8}  "
              f"{ago(r['last_seen'], now)}")
    print(f"\n{len(rows)} host(s). DGA/TUNNEL/NXDOMAIN counts are cumulative flags.")


def cmd_recent(args):
    recent = DnsAnalyzer(ledger_path=args.ledger).recent_findings()
    if args.json:
        print(json.dumps(recent, indent=2))
        return
    if not recent:
        print("No flagged domains yet.")
        return
    now = time.time()
    recent = sorted(recent, key=lambda r: r["ts"], reverse=True)[: args.limit]
    print(f"{'WHEN':<11}{'KIND':<16}{'SRC':<16}{'SCORE':>6}  DOMAIN")
    print("-" * 78)
    for r in recent:
        print(f"{ago(r['ts'], now):<11}{r['kind']:<16}{r['src']:<16}{r['score']:>6.2f}  {r['domain'][:40]}")
    print(f"\n{len(recent)} recent flagged domain(s).")


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch DNS analytics CLI")
    p.add_argument("--ledger", default=DEFAULT_LEDGER, help="path to the DNS ledger JSON")
    sub = p.add_subparsers(dest="command", required=True)
    lst = sub.add_parser("list", help="per-host DNS summary")
    lst.add_argument("--json", action="store_true")
    lst.set_defaults(func=cmd_list)
    rec = sub.add_parser("recent", help="recently flagged domains")
    rec.add_argument("--limit", type=int, default=30)
    rec.add_argument("--json", action="store_true")
    rec.set_defaults(func=cmd_recent)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
