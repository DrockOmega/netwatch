#!/bin/sh
# Weekly polite connect scan of the owned scope from a LAN host, then ingest on a Windows sensor over SSH.
# The scan goes over as a file: a Windows OpenSSH shell running pwsh would read piped stdin as commands.
# Install: cp netwatch-scan.sh ~/.local/bin/ && cp netwatch-scan.service netwatch-scan.timer ~/.config/systemd/user/
#          systemctl --user daemon-reload && systemctl --user enable --now netwatch-scan.timer
# Override the defaults below in the unit with Environment= lines.
set -eu
SCOPE=${NETWATCH_SCAN_SCOPE:-10.0.0.0/24}            # must match EXPOSURE_OWNED_SCOPES; ingest refuses anything else
SENSOR=${NETWATCH_SENSOR:-sensor}                    # ssh host alias of the Windows sensor
RUNTIME=${NETWATCH_RUNTIME:-C:\\ProgramData\\NetWatch}
INSTALL=${NETWATCH_INSTALL:-C:\\NetWatch}
DIR=$HOME/.local/share/netmon/scans
NAME=lan-$(date +%F-%H%M).xml
OUT=$DIR/$NAME
mkdir -p "$DIR"
nmap -sV --top-ports 1000 -T3 -oX "$OUT" "$SCOPE"
scp -q -o BatchMode=yes "$OUT" "$SENSOR:$(printf '%s' "$RUNTIME" | tr '\\' '/')/$NAME"
ssh -o BatchMode=yes "$SENSOR" \
  "& '$INSTALL\\.venv\\Scripts\\python.exe' '$INSTALL\\netwatch_scan.py' '$RUNTIME\\$NAME' '$RUNTIME\\telemetry_security.db' $SCOPE; \$rc = \$LASTEXITCODE; Remove-Item '$RUNTIME\\$NAME'; exit \$rc"
