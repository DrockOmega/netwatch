#!/usr/bin/env bash
# Zeek 8 LTS beside Suricata on the NetWatch Linux sensor, as root (after install-sensor.sh):
#   sudo /opt/netwatch/packaging/linux/install-zeek.sh
# Adds the security:zeek OBS repo (signing key pinned by fingerprint), user zeek, netwatch-zeek + cleanup units,
# a netwatch.service drop-in for read access to the logs, and the ZEEK_* overlay keys; then restarts netwatch.
# Rerunnable.
set -euo pipefail
CODE=/opt/netwatch RT=/var/lib/netwatch
REPO=https://download.opensuse.org/repositories/security:/zeek/xUbuntu_26.04
KEY_FPR=F9FA0223B56B116C363737EF5DA57BDD6DD785CA   # security:zeek OBS Project, checked 2026-10-16
KEYRING=/etc/apt/keyrings/zeek-obs.gpg
# Logs NetWatch ingests; dns/http/ssl/files/x509/weird stay on disk only (3 days) to bound store writes.
LOGS='["/var/lib/zeek/logs/conn*.log","/var/lib/zeek/logs/notice*.log","/var/lib/zeek/logs/dhcp*.log","/var/lib/zeek/logs/known_hosts*.log","/var/lib/zeek/logs/known_services*.log","/var/lib/zeek/logs/software*.log"]'
log() { echo "install-zeek: $*"; }
die() { echo "install-zeek: $*" >&2; exit 1; }
((EUID == 0)) || die "run as root (sudo)"
[[ -f /etc/netwatch/sensor.env ]] || die "run install-sensor.sh first"

# 1. repo with a pinned key, then the LTS engine (installs under /opt/zeek)
if [[ ! -f $KEYRING ]]; then
  tmp=$(mktemp)
  curl -fsSL "$REPO/Release.key" -o "$tmp"
  fpr=$(gpg --show-keys --with-colons "$tmp" | awk -F: '/^fpr/{print $10; exit}')
  [[ $fpr == "$KEY_FPR" ]] || { rm -f "$tmp"; die "Zeek repo key fingerprint $fpr is not $KEY_FPR"; }
  install -d -m 0755 /etc/apt/keyrings
  gpg --dearmor <"$tmp" >"$KEYRING"; chmod 0644 "$KEYRING"; rm -f "$tmp"
fi
echo "deb [signed-by=$KEYRING] $REPO/ /" >/etc/apt/sources.list.d/zeek-obs.list
apt-get update -q
# zeek-lts-core only: the zeek-lts metapackage brings zeekctl, whose Recommends: mail-transport-agent installs and
# starts a listening MTA (courier), and dev/btest packages a sensor does not need.
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zeek-lts-core
/opt/zeek/bin/zeek --version | grep -q 'version 8\.0\.' || die "Zeek is not 8.0.x: $(/opt/zeek/bin/zeek --version)"
systemctl disable --now zeek.service 2>/dev/null || true   # packaged zeekctl unit, if any; ours is netwatch-zeek

# 2. user, policy, units; netwatch reads the logs through the zeek group (drop-in, so hosts without Zeek are unaffected)
getent group zeek >/dev/null || groupadd --system zeek   # the package may create the group only
id -u zeek >/dev/null 2>&1 || useradd --system -g zeek --home /var/lib/zeek --shell /usr/sbin/nologin zeek
install -d -m 0755 /etc/netwatch/zeek
install -m 0644 "$CODE/packaging/linux/zeek/netwatch.zeek" /etc/netwatch/zeek/
install -m 0644 "$CODE"/packaging/linux/netwatch-zeek.service "$CODE"/packaging/linux/netwatch-zeek-cleanup.{service,timer} /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/netwatch.service.d
printf '[Service]\nSupplementaryGroups=zeek\n' >/etc/systemd/system/netwatch.service.d/zeek.conf
systemctl daemon-reload
systemctl enable --now netwatch-zeek.service netwatch-zeek-cleanup.timer
for _ in $(seq 60); do [[ -f /var/lib/zeek/logs/conn.log ]] && break; sleep 2; done
[[ -f /var/lib/zeek/logs/conn.log ]] || die "Zeek wrote no conn.log in 120 s (journalctl -u netwatch-zeek)"

# 3. overlay: enable the collector on the ingested logs (backup beside it)
ov=$RT/netwatch.$(hostname).json
[[ -f $ov ]] || die "no overlay $ov"
if [[ $(jq -r '.ZEEK_LOGS_ENABLED // false' "$ov") != true ]]; then
  cp -p "$ov" "$ov.bak-zeek"
  jq --argjson p "$LOGS" '.ZEEK_LOGS_ENABLED=true | .ZEEK_LOG_PATHS=$p' "$ov.bak-zeek" >"$ov.new"
  chown netwatch:netwatch "$ov.new"; chmod 0600 "$ov.new"; mv -f "$ov.new" "$ov"
  log "overlay: ZEEK_LOGS_ENABLED (backup $ov.bak-zeek)"
fi
systemctl restart netwatch.service
log "done: $(systemctl is-active netwatch-zeek netwatch | tr '\n' ' ')"
