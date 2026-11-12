#!/bin/sh
# Weekly polite connect scan of the owned scope from the console host (a LAN vantage), then ingest on the sensor.
# Install: cp netwatch-scan.sh ~/.local/bin/ && cp netwatch-scan.service netwatch-scan.timer ~/.config/systemd/user/
#          systemctl --user daemon-reload && systemctl --user enable --now netwatch-scan.timer
set -eu
SENSOR=${NW_SENSOR_HOST:-sensor}   # ssh host alias of the sensor
SCOPE=10.0.0.0/24   # must match EXPOSURE_OWNED_SCOPES; ingest refuses anything else
DIR=$HOME/.local/share/netmon/scans
NAME=lan-$(date +%F-%H%M).xml
OUT=$DIR/$NAME
mkdir -p "$DIR"
nmap -sV --top-ports 1000 -T3 -oX "$OUT" "$SCOPE"
# Paths follow netwatch.service (code /opt/netwatch, data /var/lib/netwatch); needs the NOPASSWD sudo -u netwatch rule on the sensor.
scp -q -o BatchMode=yes "$OUT" "$SENSOR:/tmp/$NAME"
ssh -o BatchMode=yes "$SENSOR" \
  "sudo -n -u netwatch /opt/netwatch/.venv/bin/python /opt/netwatch/netwatch_scan.py /tmp/$NAME /var/lib/netwatch/telemetry_security.db $SCOPE; rc=\$?; rm -f /tmp/$NAME; exit \$rc"
