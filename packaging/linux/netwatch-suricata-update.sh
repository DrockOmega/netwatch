#!/bin/sh
# Daily ET Open refresh (netwatch-suricata-update.service, user suricata):
# fetch, Tailscale DERP relay list refresh, `suricata -T` gate, previous set kept in rules.prev, live reload. A failed test restores the old rules.
set -eu
dir=${NW_SURICATA_DIR:-/var/lib/suricata}
conf=${NW_SURICATA_CONF:-/etc/netwatch/suricata/suricata.yaml}
rules=$dir/rules
derp=$dir/tailscale-derp.yaml
rm -rf "$dir/rules.prev"
cp -a "$rules" "$dir/rules.prev"
[ -f "$derp" ] || cp "$(dirname "$0")/../suricata/tailscale-derp.yaml" "$derp"  # first run: the committed seed
cp -p "$derp" "$derp.prev"
restore() {
  echo "FAILED: restoring previous rules and relay list" >&2
  rm -rf "$rules"; cp -a "$dir/rules.prev" "$rules"; cp -p "$derp.prev" "$derp"; exit 1
}
# Tailscale DERP relay addresses for TAILSCALE_DERP (b791); on any fetch or parse error the previous file stays.
python3 - "$derp" <<'PY' || echo "DERP map refresh failed; keeping the previous relay list" >&2
import ipaddress, json, os, sys, urllib.request
with urllib.request.urlopen("https://login.tailscale.com/derpmap/default", timeout=30) as reply:
    nodes = [node for region in json.load(reply)["Regions"].values() for node in region["Nodes"]]
ips = sorted({str(ipaddress.ip_address(node[key])) for node in nodes for key in ("IPv4", "IPv6") if node.get(key)})
if not ips:
    sys.exit("DERP map lists no relay addresses")
with open(sys.argv[1] + ".tmp", "w") as out:
    out.write('%%YAML 1.1\n---\nTAILSCALE_DERP: "[%s]"\n' % ",".join(ips))
os.replace(sys.argv[1] + ".tmp", sys.argv[1])
PY
suricata-update --suricata /usr/bin/suricata --suricata-conf "$conf" --data-dir "$dir/update" --output "$rules" \
  --disable-conf "$(dirname "$conf")/disable.conf" --local "$(dirname "$conf")/local.rules" --no-reload --no-test || restore
out=$(suricata -T -v -c "$conf" -l "$dir" 2>&1) || { echo "$out" | tail -20 >&2; restore; }
echo "$out" | grep -q ' 0 rules failed' || { echo "$out" | tail -20 >&2; restore; }
echo "$out" | grep 'rules successfully loaded'
pid=$(systemctl show -p MainPID --value netwatch-suricata.service 2>/dev/null || echo 0)
if [ "${pid:-0}" -gt 0 ]; then kill -USR2 "$pid" && echo "reloaded pid $pid"; fi
