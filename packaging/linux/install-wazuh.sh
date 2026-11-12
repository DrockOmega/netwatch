#!/usr/bin/env bash
# Wazuh manager beside NetWatch on the Linux sensor, as root (after install-sensor.sh):
#   sudo /opt/netwatch/packaging/linux/install-wazuh.sh
# Server only: no indexer, no dashboard. NetWatch reads /var/ossec/logs/alerts/alerts.json and is the console.
# Agents enroll by password on 1515 and report on 1514, from WAZUH_AGENT_FROM only (ufw). API on loopback.
# Active response stays off (NetWatch is recording-only). The manager also watches the sensor itself (agent 000).
# Rerunnable.
set -euo pipefail
RT=/var/lib/netwatch
VERSION=4.14.9-1   # agents must not be newer than the manager; held so upgrades move both together
REPO=https://packages.wazuh.com/4.x/apt/
KEY_FPR=0DCFCA5547B19D2A6099506096B3EE5F29111145   # Wazuh Signing Key, checked 2026-10-16
KEYRING=/etc/apt/keyrings/wazuh.gpg
AGENT_FROM=${WAZUH_AGENT_FROM:?set WAZUH_AGENT_FROM, comma-separated agent addresses}   # e.g. tailnet v4/v6 and LAN
AGENTS=${WAZUH_AGENT_ADDRESSES:?set WAZUH_AGENT_ADDRESSES, e.g. '{"console":"10.0.0.15"}'}
CONF=/var/ossec/etc/ossec.conf
log() { echo "install-wazuh: $*"; }
die() { echo "install-wazuh: $*" >&2; exit 1; }
((EUID == 0)) || die "run as root (sudo)"
[[ -f /etc/netwatch/sensor.env ]] || die "run install-sensor.sh first"

# 1. repo with a pinned key, then the manager at the pinned version
if [[ ! -f $KEYRING ]]; then
  tmp=$(mktemp)
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$tmp"
  fpr=$(gpg --show-keys --with-colons "$tmp" | awk -F: '/^fpr/{print $10; exit}')
  [[ $fpr == "$KEY_FPR" ]] || { rm -f "$tmp"; die "Wazuh repo key fingerprint $fpr is not $KEY_FPR"; }
  install -d -m 0755 /etc/apt/keyrings
  gpg --dearmor <"$tmp" >"$KEYRING"; chmod 0644 "$KEYRING"; rm -f "$tmp"
fi
echo "deb [signed-by=$KEYRING] $REPO stable main" >/etc/apt/sources.list.d/wazuh.list
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --allow-change-held-packages "wazuh-manager=$VERSION"
apt-mark hold wazuh-manager >/dev/null

# 2. config: no indexer here (so no vulnerability feed), password enrollment, API on loopback
[[ -f $CONF.netwatch-orig ]] || cp -p "$CONF" "$CONF.netwatch-orig"
perl -0pi -e 's#(<vulnerability-detection>\s*<enabled>)yes#${1}no#; s#(<indexer>\s*<enabled>)yes#${1}no#;
              s#<use_password>no</use_password>#<use_password>yes</use_password>#' "$CONF"
grep -q '<use_password>yes</use_password>' "$CONF" || die "enrollment password not enabled in $CONF"
if [[ ! -s /var/ossec/etc/authd.pass ]]; then
  (umask 027; head -c 32 /dev/urandom | base64 | tr -d '/+=' >/var/ossec/etc/authd.pass)
  chown root:wazuh /var/ossec/etc/authd.pass
  log "enrollment password written to /var/ossec/etc/authd.pass (copy it to each agent, never print it)"
fi
# Ubuntu 26.04 ships Rust uutils coreutils (one multicall binary): its strings hit every rootcheck trojan
# signature, so trojan checks only false-alarm there; dpkg -V and syscheck still cover those binaries.
if [[ $(ls --version 2>/dev/null) == *uutils* ]]; then
  perl -pi -e 's#<check_trojans>yes</check_trojans>#<check_trojans>no</check_trojans>#' "$CONF"
fi
# Listening-port watch (rule 533): network-reachable TCP only. UDP sockets and loopback listeners (agent
# sessions, dev servers) churn every few minutes and say nothing about exposure.
perl -pi -e 's#<command>netstat -tulpn #<command>netstat -tlpn #' "$CONF"
grep -q 'netstat -tlpn | grep -vE' "$CONF" ||
  perl -pi -e "s#<command>netstat -tlpn #<command>netstat -tlpn | grep -vE '(127\\\\.[0-9.]+|::1):[0-9]+ ' #" "$CONF"
api=/var/ossec/api/configuration/api.yaml
grep -q '^host:' "$api" || echo "host: ['127.0.0.1']" >>"$api"

# 3. archived alerts: Wazuh keeps them forever; NetWatch has its own copy, so 7 days is enough
cat >/etc/systemd/system/netwatch-wazuh-cleanup.service <<'EOF'
[Unit]
Description=Delete Wazuh alert archives older than 7 days

[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/ossec/logs/alerts /var/ossec/logs/archives -mindepth 2 -type f -mtime +7 -delete
EOF
cat >/etc/systemd/system/netwatch-wazuh-cleanup.timer <<'EOF'
[Unit]
Description=Daily Wazuh alert archive cleanup

[Timer]
OnCalendar=*-*-* 04:10
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 4. agents' ports from the named sources only; netwatch reads alerts.json through the wazuh group
for src in ${AGENT_FROM//,/ }; do
  for port in 1514 1515; do ufw allow proto tcp from "$src" to any port "$port" comment netwatch-wazuh >/dev/null; done
done
install -d -m 0755 /etc/systemd/system/netwatch.service.d
printf '[Service]\nSupplementaryGroups=wazuh\n' >/etc/systemd/system/netwatch.service.d/wazuh.conf
systemctl daemon-reload
systemctl enable --now wazuh-manager.service netwatch-wazuh-cleanup.timer
systemctl restart wazuh-manager.service
for _ in $(seq 60); do [[ -f /var/ossec/logs/alerts/alerts.json ]] && break; sleep 2; done
[[ -f /var/ossec/logs/alerts/alerts.json ]] || die "no alerts.json in 120 s (journalctl -u wazuh-manager)"

# 5. overlay: enable the collector (backup beside it)
ov=$RT/netwatch.$(hostname).json
[[ -f $ov ]] || die "no overlay $ov"
if [[ $(jq -r '.WAZUH_ALERTS_ENABLED // false' "$ov") != true ]]; then
  cp -p "$ov" "$ov.bak-wazuh"
  jq --argjson a "$AGENTS" '.WAZUH_ALERTS_ENABLED=true | .WAZUH_ALERTS_PATH="/var/ossec/logs/alerts/alerts.json"
     | .WAZUH_AGENT_ADDRESSES=$a' "$ov.bak-wazuh" >"$ov.new"
  chown netwatch:netwatch "$ov.new"; chmod 0600 "$ov.new"; mv -f "$ov.new" "$ov"
  log "overlay: WAZUH_ALERTS_ENABLED (backup $ov.bak-wazuh)"
fi
systemctl restart netwatch.service
log "done: $(systemctl is-active wazuh-manager netwatch | tr '\n' ' ')"
