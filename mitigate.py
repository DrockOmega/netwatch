"""Operator CLI for the NetWatch mitigation engine.

Manage firewall blocks from the command line, independent of the GUI. Dry-run by
default: it prints the exact ``netsh`` commands it would issue. Pass ``--apply``
to actually create/delete rules (requires an elevated shell).

--apply, --ttl and --ledger are top-level options: they go before the subcommand.

Examples:
    python mitigate.py list
    python mitigate.py --apply block 203.0.113.7 --reason "manual"
    python mitigate.py --apply reconcile        # lift expired blocks
    python mitigate.py --apply unblock 203.0.113.7
"""

import argparse
import os
import sys
import time

from netwatch_config import build_config
from netwatch_mitigation import Mitigator, WindowsFirewall

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LEDGER = os.path.join(BASE_DIR, "telemetry_blocks.json")


def _mitigator(args):
    fw = WindowsFirewall(dry_run=not args.apply)
    return Mitigator(
        effector=fw,
        auto=True,  # an explicit CLI action is itself the approval
        block_ttl_sec=args.ttl,
        allowlist_ips=build_config(BASE_DIR)[0].get("ALLOWLIST_IPS") or (),
        ledger_path=args.ledger,
    )


def _print_commands(fw, applied):
    verb = "EXECUTED" if applied else "DRY-RUN (use --apply to execute)"
    if not fw.commands:
        return
    print(f"\n[{verb}] netsh commands:")
    for c in fw.commands:
        print("  " + " ".join(c))


def cmd_list(args):
    m = _mitigator(args)
    if not m.active:
        print("No active blocks.")
        return
    now = time.time()
    print(f"{'IP':<18}{'REASON':<28}{'REMAINING':<12}RULE")
    for ip, e in sorted(m.active.items()):
        remaining = int(e["expires_ts"] - now)
        rem = f"{remaining}s" if remaining > 0 else "EXPIRED"
        print(f"{ip:<18}{e['reason'][:27]:<28}{rem:<12}{e['rule_name']}")


def cmd_block(args):
    m = _mitigator(args)
    decision = m.request(args.ip, args.reason, now=time.time())
    print(f"{args.ip}: {decision}")
    _print_commands(m.effector, args.apply)


def cmd_unblock(args):
    m = _mitigator(args)
    ok = m.unblock(args.ip)
    print(f"{args.ip}: {'UNBLOCKED' if ok else 'NOT ACTIVE'}")
    _print_commands(m.effector, args.apply)


def cmd_reconcile(args):
    m = _mitigator(args)
    expired = m.reconcile(now=time.time())
    print(f"Lifted {len(expired)} expired block(s): {', '.join(expired) or '(none)'}")
    _print_commands(m.effector, args.apply)


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch mitigation operator CLI")
    p.add_argument("--ledger", default=DEFAULT_LEDGER, help="path to the block ledger JSON")
    p.add_argument("--apply", action="store_true", help="actually run netsh (needs admin); default is dry-run")
    p.add_argument("--ttl", type=int, default=3600, help="block lifetime in seconds (default 3600)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show active blocks").set_defaults(func=cmd_list)

    b = sub.add_parser("block", help="block an IP")
    b.add_argument("ip")
    b.add_argument("--reason", default="manual")
    b.set_defaults(func=cmd_block)

    u = sub.add_parser("unblock", help="lift a block")
    u.add_argument("ip")
    u.set_defaults(func=cmd_unblock)

    sub.add_parser("reconcile", help="lift expired blocks").set_defaults(func=cmd_reconcile)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
