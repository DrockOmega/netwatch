#!/usr/bin/env bash
# NetWatch Linux sensor install (INSTALL.md steps 1-6, plus the console host's scan sudoers), as root on the sensor:
#   sudo <checkout>/packaging/linux/install-sensor.sh
# Inputs: this checkout (cloned to /opt/netwatch, owner $SUDO_USER, push-to-deploy from the console host), a SQLite >= 3.51.3
# shared library at $SQLITE_SO (build-sqlite.sh), the staged restore under $STAGE (nwbackup/, runtime/) and the
# secrets (service-api.secret, rclone.conf) under $SECRETS, all copied from a running sensor. Rerunnable: an existing /opt/netwatch or restored store is never overwritten.
set -euo pipefail
SRC=$(cd "$(dirname "$0")/../.." && pwd)
CODE=/opt/netwatch RT=/var/lib/netwatch
STAGE=${STAGE:-/root/restore/netwatch} SECRETS=${SECRETS:-/root/restore/netwatch/secrets}
SQLITE_SO=${SQLITE_SO:-$SRC/../libsqlite3.so.0}
MAC=${NW_MAC:?set NW_MAC to the mirror NIC MAC}
PREFIXES6=${NW_PREFIXES6:?set NW_PREFIXES6 to the LAN IPv6 /64s, comma-separated}
OWNER=${SUDO_USER:?run with sudo from the deploying user}
TIMERS=(netwatch-suricata-update netwatch-eve-cleanup netwatch-threatintel netwatch-archive)
log() { echo "install-sensor: $*"; }
die() { echo "install-sensor: $*" >&2; exit 1; }
((EUID == 0)) || die "run as root (sudo)"
IFACE=$(ip -br link | awk -v m="$MAC" 'tolower($3)==m{print $1}')
[[ -n $IFACE ]] || die "mirror NIC $MAC is not present"
log "mirror NIC $IFACE"

# 1. users and Suricata 8.0 (the distro unit stays off; ours is netwatch-suricata)
id -u netwatch >/dev/null 2>&1 || useradd --system --home "$RT" --shell /usr/sbin/nologin netwatch
id -u suricata >/dev/null 2>&1 || useradd --system --home /var/lib/suricata --shell /usr/sbin/nologin suricata
DEBIAN_FRONTEND=noninteractive apt-get install -y suricata jq rclone python3-venv
systemctl disable --now suricata.service 2>/dev/null || true
systemctl mask suricata.service; systemctl reset-failed suricata.service 2>/dev/null || true   # its first auto-start fails on the stock yaml
suricata -V | grep -q 'version 8\.0\.' || die "Suricata is not 8.0.x: $(suricata -V)"

# 2. code, venv, and SQLite: Ubuntu 26.04 ships 3.46.1, which has the WAL-reset corruption bug, and the security
# store refuses it. A .pth preloads the private library before _sqlite3 binds, for every venv python (units, sudo scan).
if [[ ! -d $CODE/.git ]]; then
  install -d -m 0755 -o "$OWNER" -g "$OWNER" "$CODE"
  sudo -u "$OWNER" git clone -q "$SRC" "$CODE"
  sudo -u "$OWNER" git -C "$CODE" config receive.denyCurrentBranch updateInstead
  log "code cloned to $CODE; deploy with git push from the console host"
fi
[[ -x $CODE/.venv/bin/python ]] || sudo -u "$OWNER" python3 -m venv "$CODE/.venv"
sudo -u "$OWNER" "$CODE/.venv/bin/pip" install -q -r "$CODE/requirements.txt"
if [[ -f $SQLITE_SO ]]; then
  install -d -m 0755 -o "$OWNER" -g "$OWNER" "$CODE/.venv/lib/netwatch-sqlite"
  install -m 0644 -o "$OWNER" -g "$OWNER" "$SQLITE_SO" "$CODE/.venv/lib/netwatch-sqlite/libsqlite3.so.0"
fi
sp=$(sudo -u "$OWNER" "$CODE/.venv/bin/python" -c 'import site; print(site.getsitepackages()[0])')
printf "import ctypes; ctypes.CDLL('%s', mode=ctypes.RTLD_GLOBAL)\n" "$CODE/.venv/lib/netwatch-sqlite/libsqlite3.so.0" >"$sp/00-netwatch-sqlite.pth"
chown "$OWNER:$OWNER" "$sp/00-netwatch-sqlite.pth"
(cd "$CODE" && sudo -u netwatch .venv/bin/python -c 'import sqlite3, netwatch_security_store as s; print("sqlite", sqlite3.sqlite_version); assert s.sqlite_wal_safe()') ||
  die "venv SQLite is not WAL-safe; build it with packaging/linux/build-sqlite.sh"

# 3. runtime restore, once: backup set, then the runtime set without overwriting it, then the secrets
if [[ ! -f $RT/telemetry_security.db ]]; then
  [[ -d $STAGE/nwbackup && -d $STAGE/runtime ]] || die "staged NetWatch data missing under $STAGE"
  "$CODE/.venv/bin/python" "$CODE/netwatch_backup.py" restore "$STAGE/nwbackup" "$RT"
  for f in "$STAGE"/runtime/telemetry_* "$STAGE/runtime/threatintel_cache.json" "$STAGE/runtime/GeoLite2-Country.mmdb" "$STAGE/runtime/GeoLite2-City.mmdb"; do
    [[ -e $f ]] && cp -n "$f" "$RT/"
  done
  cp -rn "$STAGE/runtime/archive" "$STAGE/runtime/evidence" "$RT/"
  mapfile -t sec < <(find "$SECRETS" -type f -name service-api.secret)
  ((${#sec[@]} == 1)) || die "expected one service-api.secret under $SECRETS, found ${#sec[@]}"
  install -m 0600 "${sec[0]}" "$RT/service-api.secret"
  mapfile -t rc < <(find "$SECRETS" -type f -name rclone.conf)
  if ((${#rc[@]} == 1)); then install -m 0600 "${rc[0]}" "$RT/archive/rclone.conf"; else log "WARNING: ${#rc[@]} NetWatch rclone.conf found; archive upload needs one"; fi
  chown -R netwatch:netwatch "$RT"; chmod 0700 "$RT"
  log "runtime restored to $RT"
fi

# 4. config: Suricata yaml + threshold, sensor.env, overlay merged with the Linux keys and pinned LAN /64s
install -d -m 0755 /etc/netwatch/suricata
install -m 0644 "$CODE/packaging/linux/suricata.yaml" "$CODE"/packaging/suricata/{threshold.config,disable.conf,local.rules} /etc/netwatch/suricata/
[[ -f /var/lib/suricata/tailscale-derp.yaml ]] || install -D -o suricata -g suricata -m 0644 "$CODE/packaging/suricata/tailscale-derp.yaml" /var/lib/suricata/tailscale-derp.yaml
printf 'NW_IFACE=%s\n' "$IFACE" >/etc/netwatch/sensor.env
ov=$RT/netwatch.$(hostname).json
[[ -f $ov ]] || die "no overlay $ov in the restored runtime"
if [[ $(jq -r .NIC_INTERFACE "$ov") != "$IFACE" ]]; then
  cp -p "$ov" "$ov.bak-iface"
  jq -s --arg i "$IFACE" --arg p "$PREFIXES6" \
    '.[0] * .[1] | .NIC_INTERFACE=$i | .LOCAL_PREFIXES6=($p|split(",")) | .LOCAL_PREFIXES6_AUTO=false' \
    "$ov" "$CODE/packaging/linux/netwatch.HOST.json.template" >"$ov.new"
  chown netwatch:netwatch "$ov.new"; chmod 0600 "$ov.new"; mv -f "$ov.new" "$ov"
  log "overlay set for $IFACE (backup $ov.bak-iface)"
fi

# 5. units (never netwatch-scan.*: the weekly scan runs from the console host), first rules fetch
for u in "$CODE"/packaging/linux/netwatch*.service; do [[ $u == *netwatch-scan* ]] || install -m 0644 "$u" /etc/systemd/system/; done
for t in "${TIMERS[@]}"; do install -m 0644 "$CODE/packaging/linux/$t.timer" /etc/systemd/system/; done
systemctl daemon-reload
systemctl start netwatch-suricata-update.service

# 6. start order: Suricata, its first EVE file, NetWatch, the timers
systemctl enable --now netwatch-suricata.service
for _ in $(seq 60); do compgen -G '/var/lib/suricata/eve.json.*' >/dev/null && break; sleep 2; done
compgen -G '/var/lib/suricata/eve.json.*' >/dev/null || die "Suricata wrote no EVE file in 120 s (journalctl -u netwatch-suricata)"
systemctl enable --now netwatch.service
systemctl enable --now "${TIMERS[@]/%/.timer}"

# the console host: restart and the weekly scan ingest, nothing else
rule="$OWNER ALL=(root) NOPASSWD: /usr/bin/systemctl restart netwatch
$OWNER ALL=(netwatch) NOPASSWD: $CODE/.venv/bin/python $CODE/netwatch_scan.py *"
printf '%s\n' "$rule" >/etc/sudoers.d/.netwatch-console.new; chmod 0440 /etc/sudoers.d/.netwatch-console.new
visudo -cf /etc/sudoers.d/.netwatch-console.new >/dev/null || { rm -f /etc/sudoers.d/.netwatch-console.new; die "visudo rejected the rule"; }
mv -f /etc/sudoers.d/.netwatch-console.new /etc/sudoers.d/netwatch-console
log "done: $(systemctl is-active netwatch-suricata netwatch | tr '\n' ' ')"
