#!/usr/bin/env bash
# Wazuh agent on a fleet machine (e.g. the console host), enrolled to the sensor's manager, as root:
#   sudo WAZUH_AGENT_NAME=console /opt/netwatch/packaging/linux/install-wazuh-agent.sh < authd.pass
# The enrollment password comes on stdin (piped from the manager's /var/ossec/etc/authd.pass, never printed).
# Version matches the manager (install-wazuh.sh) and is held. Active response off: NetWatch is recording-only.
# Rerunnable.
set -euo pipefail
VERSION=4.14.9-1
REPO=https://packages.wazuh.com/4.x/apt/
KEY_FPR=0DCFCA5547B19D2A6099506096B3EE5F29111145   # Wazuh Signing Key, checked 2026-10-16
KEYRING=/etc/apt/keyrings/wazuh.gpg
MANAGER=${WAZUH_MANAGER:?set WAZUH_MANAGER to the sensor address}
NAME=${WAZUH_AGENT_NAME:?set WAZUH_AGENT_NAME, its key in the sensor WAZUH_AGENT_ADDRESSES}
CONF=/var/ossec/etc/ossec.conf
die() { echo "install-wazuh-agent: $*" >&2; exit 1; }
((EUID == 0)) || die "run as root (sudo)"
pass=$(head -c 256)
[[ -n $pass ]] || die "no enrollment password on stdin"

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
WAZUH_MANAGER=$MANAGER WAZUH_AGENT_NAME=$NAME DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends --allow-change-held-packages "wazuh-agent=$VERSION"
apt-mark hold wazuh-agent >/dev/null

(umask 027; printf '%s\n' "$pass" >/var/ossec/etc/authd.pass); chown root:wazuh /var/ossec/etc/authd.pass
[[ -f $CONF.netwatch-orig ]] || cp -p "$CONF" "$CONF.netwatch-orig"
perl -0pi -e 's#(<active-response>\s*<disabled>)no#${1}yes#' "$CONF"
grep -Pzq '<active-response>\s*<disabled>yes' "$CONF" || die "active response not disabled in $CONF"
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
# an earlier install's kept conffile can name an old address; the postinst does not rewrite it
perl -0pi -e "s#(<server>\\s*<address>)[^<]*#\${1}$MANAGER#" "$CONF"
grep -q "<address>$MANAGER</address>" "$CONF" || die "manager address $MANAGER not in $CONF"
systemctl daemon-reload
systemctl enable wazuh-agent.service
since=$(stat -c %s /var/ossec/logs/ossec.log)   # older lines may hold a stale "Connected" from a past manager
systemctl restart wazuh-agent.service
connected() { tail -c +$((since + 1)) /var/ossec/logs/ossec.log | grep -q "Connected to the server"; }
for _ in $(seq 45); do connected && break; sleep 2; done
connected || die "agent not connected in 90 s (/var/ossec/logs/ossec.log; a stale client.keys blocks enrollment)"
echo "install-wazuh-agent: $NAME connected to $MANAGER"
