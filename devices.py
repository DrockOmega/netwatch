"""Operator CLI for the NetWatch device inventory.

Read-only view of the passively-built MAC inventory ledger that the running
monitor maintains. Works headless, no admin, no live capture — it just reads
``telemetry_devices.json``.

Examples:
    python devices.py list                 # table of known devices
    python devices.py list --sort last     # most-recently-seen first
    python devices.py list --json          # machine-readable
"""

import argparse
import json
import os
import sys
import time

from netwatch_core import ago
from netwatch_inventory import DeviceInventory

DEFAULT_LEDGER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "telemetry_devices.json")


def cmd_list(args):
    inv = DeviceInventory(ledger_path=args.ledger)
    devices = inv.snapshot()
    if args.sort == "last":
        devices.sort(key=lambda d: d["last_seen"], reverse=True)
    elif args.sort == "first":
        devices.sort(key=lambda d: d["first_seen"])
    elif args.sort == "count":
        devices.sort(key=lambda d: d["count"], reverse=True)

    if args.json:
        print(json.dumps(devices, indent=2))
        return

    if not devices:
        print(f"No devices in ledger ({args.ledger}). Run the monitor to populate it.")
        return

    now = time.time()
    print(f"{'MAC':<19}{'VENDOR':<30}{'PKTS':>8}  {'LAST SEEN':<11}{'IPs'}")
    print("-" * 90)
    for d in devices:
        vendor = (d["vendor"] or "Unknown")[:29]
        ips = ", ".join(d["ips"][:3]) + (" ..." if len(d["ips"]) > 3 else "")
        print(f"{d['mac']:<19}{vendor:<30}{d['count']:>8}  {ago(d['last_seen'], now):<11}{ips}")
    print(f"\n{len(devices)} device(s).")


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch device inventory CLI")
    p.add_argument("--ledger", default=DEFAULT_LEDGER, help="path to the device ledger JSON")
    sub = p.add_subparsers(dest="command", required=True)
    lst = sub.add_parser("list", help="list known devices")
    lst.add_argument("--sort", choices=["mac", "last", "first", "count"], default="mac")
    lst.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    lst.set_defaults(func=cmd_list)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
