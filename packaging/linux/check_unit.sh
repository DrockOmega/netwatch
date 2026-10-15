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
    # ExecStart points at the install path, which need not exist here; verify a copy that uses this python.
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    sed "s#^ExecStart=/opt/netwatch/.venv/bin/python#ExecStart=$(command -v python3)#" "$unit" > "$tmp/netwatch.service"
    systemd-analyze verify "$tmp/netwatch.service" || fail "systemd-analyze verify"
    echo "OK: static checks and systemd-analyze verify"
else
    echo "OK: static checks (systemd-analyze unavailable, verify skipped)"
fi
