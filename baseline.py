"""Operator CLI for the NetWatch per-device baselines.

Read-only view of the learned egress-volume model the monitor maintains per
device (``telemetry_baseline.json``). Joins vendor names from the device
inventory ledger when available. No admin, no live capture.

Examples:
    python baseline.py list                # learned baseline per device
    python baseline.py list --sort mean    # biggest talkers first
    python baseline.py list --json
"""

import argparse
import json
import os
import sys
import time

from netwatch_baseline import BaselineTracker
from netwatch_core import ago
from netwatch_inventory import DeviceInventory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER = os.path.join(BASE_DIR, "telemetry_baseline.json")
DEFAULT_DEVICES = os.path.join(BASE_DIR, "telemetry_devices.json")


def _human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def cmd_list(args):
    rows = BaselineTracker(ledger_path=args.ledger).snapshot()
    vendors = {m: e.get("vendor", "") for m, e in DeviceInventory(ledger_path=args.devices).devices.items()}

    if args.sort == "mean":
        rows.sort(key=lambda r: r["mean"], reverse=True)
    elif args.sort == "n":
        rows.sort(key=lambda r: r["n"], reverse=True)
    elif args.sort == "last":
        rows.sort(key=lambda r: r["last_seen"], reverse=True)

    if args.json:
        for r in rows:
            r["vendor"] = vendors.get(r["key"], "")
        print(json.dumps(rows, indent=2))
        return

    if not rows:
        print(f"No baselines in ledger ({args.ledger}). Run the monitor to learn them.")
        return

    now = time.time()
    print(f"{'DEVICE (MAC)':<19}{'VENDOR':<26}{'MEAN/win':>10}{'STD':>10}{'WIN':>6}  LAST")
    print("-" * 84)
    for r in rows:
        vendor = (vendors.get(r["key"], "") or "-")[:25]
        print(f"{r['key']:<19}{vendor:<26}{_human(r['mean']):>10}{_human(r['std']):>10}"
              f"{r['n']:>6}  {ago(r['last_seen'], now)}")
    print(f"\n{len(rows)} device baseline(s). Window aggregates egress bytes; "
          "anomalies fire when a window exceeds the device's learned norm.")


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch per-device baseline CLI")
    p.add_argument("--ledger", default=DEFAULT_LEDGER, help="path to the baseline ledger JSON")
    p.add_argument("--devices", default=DEFAULT_DEVICES, help="path to the device inventory ledger (for vendor names)")
    sub = p.add_subparsers(dest="command", required=True)
    lst = sub.add_parser("list", help="list learned device baselines")
    lst.add_argument("--sort", choices=["key", "mean", "n", "last"], default="mean")
    lst.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    lst.set_defaults(func=cmd_list)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
