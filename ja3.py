"""Operator CLI for the NetWatch JA3/JA3S fingerprint inventory.

Read-only view of the TLS fingerprints the monitor has observed
(``telemetry_ja3.json``): which JA3 (client) / JA3S (server) fingerprints have been
seen, how often, with a sample SNI/peer, and whether any are blocklisted. No admin,
no live capture.

Examples:
    python ja3.py list                  # fingerprint inventory (most-seen first)
    python ja3.py list --blocklisted    # only blocklist hits
    python ja3.py list --json
"""

import argparse
import json
import os
import sys
import time

from netwatch_core import ago
from netwatch_ja3 import Ja3Watch, load_blocklist

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER = os.path.join(BASE_DIR, "telemetry_ja3.json")
DEFAULT_BLOCKLIST = os.path.join(BASE_DIR, "ja3_blocklist.json")


def cmd_list(args):
    w = Ja3Watch(blocklist=load_blocklist(args.blocklist), ledger_path=args.ledger)
    rows = w.snapshot()
    if args.blocklisted:
        rows = [r for r in rows if r["blocklisted"]]

    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print(f"No JA3 fingerprints in ledger ({args.ledger}). Run the monitor to populate it.")
        return

    now = time.time()
    print(f"{'FINGERPRINT (MD5)':<34}{'KIND':<6}{'FORMAT':<24}{'COUNT':>7}  {'SNI / PEER':<28}LAST")
    print("-" * 116)
    for r in rows:
        mark = " !BLOCK" if r["blocklisted"] else ""
        ctx = (r.get("sni") or r.get("peer") or "")[:27]
        print(f"{r['hash']:<34}{r['kind']:<6}{r['format']:<24}{r['count']:>7}  {ctx:<28}{ago(r['last_seen'], now)}{mark}")
    blocked = sum(1 for r in rows if r["blocklisted"])
    print(f"\n{len(rows)} fingerprint(s); {blocked} blocklisted.")


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch JA3/JA3S fingerprint CLI")
    p.add_argument("--ledger", default=DEFAULT_LEDGER, help="path to the JA3 ledger JSON")
    p.add_argument("--blocklist", default=DEFAULT_BLOCKLIST, help="path to the JA3 blocklist JSON")
    sub = p.add_subparsers(dest="command", required=True)
    lst = sub.add_parser("list", help="list observed TLS fingerprints")
    lst.add_argument("--blocklisted", action="store_true", help="show only blocklist hits")
    lst.add_argument("--json", action="store_true")
    lst.set_defaults(func=cmd_list)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
