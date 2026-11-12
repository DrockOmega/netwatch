#!/bin/sh
# Validate netwatch.service without installing it: static capability checks, then
# `systemd-analyze verify` when available. Installs nothing, needs no root.
set -eu
unit="$(dirname "$0")/netwatch.service"
fail() { echo "FAIL: $*" >&2; exit 1; }
grep -qx 'AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN' "$unit" || fail "ambient capabilities must be exactly NET_RAW/NET_ADMIN"
grep -qx 'CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN' "$unit" || fail "bounding set must be exactly NET_RAW/NET_ADMIN"
grep -qx 'KillMode=mixed' "$unit" || fail "KillMode=mixed missing"
grep -qx 'NoNewPrivileges=yes' "$unit" || fail "NoNewPrivileges missing"
grep -qE '^User=.+' "$unit" && ! grep -qx 'User=root' "$unit" || fail "must run as a non-root user"
if command -v systemd-analyze >/dev/null 2>&1; then
    # ExecStart points at the install path, which need not exist here; verify copies that use this python, /bin/true
    # for suricata and the repo's own scripts. Timers are verified beside their services.
    here=$(cd "$(dirname "$0")" && pwd)
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    for f in "$here"/netwatch*.service "$here"/netwatch*.timer; do
        case "$(basename "$f")" in netwatch-scan.*) continue;; esac
        sed -e "s#/opt/netwatch/.venv/bin/python#$(command -v python3)#" -e "s#/opt/netwatch/packaging/linux/#$here/#" \
            -e '/^Exec/s#/usr/bin/suricata#/bin/true#' -e '/^Exec/s#/opt/zeek/bin/zeek#/bin/true#' "$f" > "$tmp/$(basename "$f")"
    done
    for f in "$tmp"/*; do
        case "$f" in *.service) grep -qx 'NoNewPrivileges=yes' "$f" || fail "$(basename "$f"): NoNewPrivileges missing"
            grep -qx 'ProtectSystem=strict' "$f" || fail "$(basename "$f"): ProtectSystem=strict missing";; esac
    done
    (cd "$tmp" && systemd-analyze verify "$tmp"/*) || fail "systemd-analyze verify"
    echo "OK: static checks and systemd-analyze verify ($(ls "$tmp" | wc -l) units)"
else
    echo "OK: static checks (systemd-analyze unavailable, verify skipped)"
fi
