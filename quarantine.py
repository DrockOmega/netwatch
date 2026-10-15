"""Operator CLI for NetWatch LAN quarantine.

Isolate a misbehaving LAN device via ARP cache poisoning from this host — the
enforcement point that works behind a locked ISP gateway. Dry-run by default: it
resolves and prints the exact ARP frames it *would* send. Pass ``--apply`` to put
them on the wire (requires an elevated shell and the capture interface).

Examples:
    python quarantine.py list
    python quarantine.py hold 10.0.0.34 --gateway 10.0.0.1 --reason "rogue IoT" --apply   # stays in the foreground
    python quarantine.py release 10.0.0.34 --gateway 10.0.0.1 --apply
    python quarantine.py reconcile --gateway 10.0.0.1 --apply   # lift expired
"""

import argparse
import os
import sys
import time

from netwatch_config import DEFAULTS, build_config, detect_own_ipv4
from netwatch_quarantine import ArpQuarantineEffector, Quarantine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER = os.path.join(BASE_DIR, "telemetry_quarantine.json")


def _engine(args):
    cfg, _ = build_config(BASE_DIR)
    gateway = args.gateway or cfg.get("GATEWAY_IP", "")
    iface = args.iface or cfg.get("QUARANTINE_IFACE") or cfg.get("NIC_INTERFACE")
    effector = ArpQuarantineEffector(
        iface,
        sink_mac=cfg.get("QUARANTINE_SINK_MAC", DEFAULTS["QUARANTINE_SINK_MAC"]),
        dry_run=not args.apply,
    )
    return Quarantine(
        effector,
        gateway_ip=gateway,
        own_ip=detect_own_ipv4(),
        allowlist_ips=cfg.get("ALLOWLIST_IPS") or (),
        auto=True,  # an explicit CLI action is itself the approval
        ttl_sec=args.ttl,
        bidirectional=not args.egress_only,
        ledger_path=args.ledger,
    )


def cmd_list(args):
    eng = _engine(args)
    rows = eng.snapshot()
    if not rows:
        print("No devices quarantined.")
        return
    print(f"{'IP':<18}{'MAC':<20}{'REMAINING':<12}REASON")
    for r in rows:
        rem = f"{int(r['remaining'])}s" if r["remaining"] > 0 else "EXPIRED"
        print(f"{r['ip']:<18}{r['mac']:<20}{rem:<12}{str(r['reason'])[:40]}")


def cmd_hold(args):
    eng = _engine(args)
    if not eng.gateway_ip:
        print("No gateway IP (pass --gateway or set GATEWAY_IP); cannot quarantine.")
        return
    decision = eng.request(args.ip, args.reason, now=time.time())
    print(f"{args.ip}: {decision}   (gateway {eng.gateway_ip}, "
          f"{'BI-DIR' if eng.bidirectional else 'EGRESS'}, "
          f"{'DRY-RUN — use --apply' if eng.effector.dry_run else 'LIVE'})")
    if decision != "QUARANTINE" or eng.effector.dry_run:
        return
    # One poison lasts only until the victim re-ARPs, so keep re-asserting like the desktop engine.
    print("Holding: re-asserting until the TTL expires; Ctrl-C releases it now.")
    eng.start()
    try:
        while args.ip in eng.active:  # gone at TTL expiry or after a release elsewhere
            time.sleep(1)
    except KeyboardInterrupt:
        eng.release(args.ip)
    eng.stop()


def cmd_release(args):
    eng = _engine(args)
    ok = eng.release(args.ip)
    print(f"{args.ip}: {'RELEASED' if ok else 'NOT QUARANTINED'}")


def cmd_reconcile(args):
    eng = _engine(args)
    released = eng.reconcile(now=time.time())
    print(f"Released {len(released)} expired: {', '.join(released) or '(none)'}")


def build_parser():
    # Shared options live on a parent parser attached to every subcommand, so they
    # may be given AFTER the subcommand (e.g. `hold 10.0.0.34 --gateway 10.0.0.1`).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ledger", default=DEFAULT_LEDGER, help="path to the quarantine ledger JSON")
    common.add_argument("--gateway", default="", help="gateway IP to poison the route to (default: config)")
    common.add_argument("--iface", default="", help="capture interface (default: config NIC_INTERFACE)")
    common.add_argument("--apply", action="store_true", help="actually send ARP (needs admin); default is dry-run")
    common.add_argument("--egress-only", action="store_true", help="poison only the victim, not the gateway")
    common.add_argument("--ttl", type=int, default=1800, help="quarantine lifetime in seconds (default 1800)")

    p = argparse.ArgumentParser(description="NetWatch LAN quarantine operator CLI", parents=[common])
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", parents=[common], help="show quarantined devices").set_defaults(func=cmd_list)

    h = sub.add_parser("hold", parents=[common], help="quarantine a LAN device")
    h.add_argument("ip")
    h.add_argument("--reason", default="manual")
    h.set_defaults(func=cmd_hold)

    r = sub.add_parser("release", parents=[common], help="release a quarantined device")
    r.add_argument("ip")
    r.set_defaults(func=cmd_release)

    sub.add_parser("reconcile", parents=[common], help="release expired quarantines").set_defaults(func=cmd_reconcile)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
