"""Triage open NetWatch cases by family through the console gateway.

    python tools/case_triage.py families [--node sensor1]
    python tools/case_triage.py close --action BEACON_ANOMALY [--match REGEX] --reason "..." [--apply]

``families`` groups open cases by detector action and message shape (addresses and numbers
folded), with severity and how long the family has been quiet. ``close`` dismisses one reviewed
family with a closure reason; without ``--apply`` it only prints what it would close. Reads the
gateway cache read-only; writes go through the gateway's ``/api/case`` like the console.
Closing is the last step of triage, never a substitute for tuning the source (docs/case-triage.md).
"""

import argparse
import collections
import json
import pathlib
import re
import sqlite3
import sys
import time
import urllib.request

CACHE = pathlib.Path.home() / ".local/share/netwatch-gateway/cache.db"
TOKEN = pathlib.Path.home() / ".config/netwatch-gateway/ui.token"
GATEWAY = "http://127.0.0.1:8766/api/case"
_FOLD = re.compile(r"[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}|\d+\.\d+\.\d+\.\d+|[0-9a-f]{2}(:[0-9a-f]{2}){5}|\d+(\.\d+)?")


def family(case):
    detail = str(case.get("detail") or "").replace("SURICATA ALLOWED: ", "")
    return case["action"], _FOLD.sub("#", detail).replace("#:#", "#")[:70]  # v4:port folds like v6


def open_cases(node, cache=CACHE):
    conn = sqlite3.connect(f"file:{cache}?mode=ro", uri=True)
    try:
        return [json.loads(body) for (body,) in conn.execute(
            "SELECT body FROM cases WHERE node=? AND status='Open'", (node,))]
    finally:
        conn.close()


def families(cases, now=None):
    now = time.time() if now is None else now
    groups = collections.defaultdict(list)
    for case in cases:
        groups[family(case)].append(case)
    return sorted(((len(v), key, v[0]["severity"], min(now - c["last_seen"] for c in v) / 86400)
                   for key, v in groups.items()), key=lambda row: -row[0])


def select(cases, action, match=None):
    pattern = re.compile(match) if match else None
    return [c for c in cases if c["action"] == action and (pattern is None or pattern.search(c.get("detail") or ""))]


def close(node, cases, reason, status="Dismissed"):
    token = TOKEN.read_text().strip()
    done = 0
    for case in cases:
        body = {"node": node, "body": {"case": case["incident_id"], "status": status, "closure_reason": reason}}
        request = urllib.request.Request(GATEWAY, json.dumps(body).encode(), {
            "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=15) as response:  # nosec B310
            done += response.status == 200
    return done


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("families", "close"))
    parser.add_argument("--node", default="sensor1")
    parser.add_argument("--action")
    parser.add_argument("--match", help="regex on the case detail")
    parser.add_argument("--reason")
    parser.add_argument("--status", default="Dismissed", choices=("Dismissed", "Resolved"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    cases = open_cases(args.node)
    if args.command == "families":
        print(f"{len(cases)} open cases on {args.node}")
        for count, (action, shape), severity, quiet in families(cases):
            print(f"{count:4d}  {action:24s} {severity:8s} quiet {quiet:4.1f}d  {shape}")
        return 0
    if not args.action or not (args.reason or "").strip():
        parser.error("close needs --action and a --reason")
    chosen = select(cases, args.action, args.match)
    print(f"{len(chosen)} open {args.action} cases match")
    if not args.apply:
        for case in chosen[:10]:
            print("  ", case["detail"][:110])
        print("dry run: add --apply to close them")
        return 0
    print(f"closed {close(args.node, chosen, args.reason.strip(), args.status)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
