# NetWatch Linux sensor: cutover steps (Ubuntu 26.04)

Layout: code `/opt/netwatch` (+ `.venv`), runtime `/var/lib/netwatch` (user `netwatch`, 0700), Suricata data
`/var/lib/suricata` (user `suricata`, EVE group-readable by `netwatch`), config `/etc/netwatch/`.
`IFACE` = the mirror NIC (r8152 USB); find it with `ip -br link`.

1. Users and packages
   ```
   sudo useradd --system --home /var/lib/netwatch --shell /usr/sbin/nologin netwatch
   sudo useradd --system --home /var/lib/suricata --shell /usr/sbin/nologin suricata
   sudo apt install suricata rclone python3-venv    # Suricata must be 8.0.x (UNVERIFIED in 26.04 repo; else OISF PPA)
   sudo systemctl disable --now suricata            # the distro unit; ours is netwatch-suricata
   ```
2. Code: `git clone <repo> /opt/netwatch && cd /opt/netwatch && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
3. Restore runtime (a `netwatch_backup.py` backup of a running sensor, staged under `/root/restore/netwatch`):
   `netwatch_backup.py` restore into `/var/lib/netwatch`, then the runtime set (`telemetry_*`, `threatintel_cache.json`,
   `archive/` incl. `rclone.conf`, `evidence/`, GeoLite2). Skip `suricata/`; `chown -R netwatch:netwatch /var/lib/netwatch; chmod 600 /var/lib/netwatch/archive/rclone.conf`.
4. Config
   ```
   sudo install -d /etc/netwatch/suricata
   sudo cp packaging/linux/suricata.yaml packaging/suricata/threshold.config /etc/netwatch/suricata/
   echo "NW_IFACE=IFACE" | sudo tee /etc/netwatch/sensor.env
   cd /var/lib/netwatch && sudo -u netwatch jq -s '.[0]*.[1]' netwatch.<host>.json /opt/netwatch/packaging/linux/netwatch.HOST.json.template > o.json \
     && sudo -u netwatch jq '.NIC_INTERFACE="IFACE"' o.json > netwatch.<host>.json && rm o.json
   ```
   Also edit `HOME_NET` in `suricata.yaml` if the LAN changed. `NW_RCLONE_CONFIG` can be overridden in `sensor.env`.
5. Units
   ```
   sudo cp packaging/linux/netwatch*.service packaging/linux/netwatch-{suricata-update,eve-cleanup,threatintel,archive}.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl start netwatch-suricata-update.service    # first rules fetch (needs network); checks suricata -T
   ```
   Do not install `netwatch-scan.*` here.
6. Start order: `sudo systemctl enable --now netwatch-suricata.service`, wait for `eve.json.<today>` in `/var/lib/suricata`,
   then `sudo systemctl enable --now netwatch.service`, then the four timers
   (`netwatch-suricata-update` 03:30, `-eve-cleanup` 04:00, `-threatintel` 03:15, `-archive` 04:30).
7. Checks
   - `systemctl status netwatch-suricata netwatch` active; `journalctl -u netwatch-suricata -n 20` shows engine started on IFACE.
   - `tail -c 300 /var/lib/suricata/eve.json.*` has fresh `stats` lines (30 s); NetWatch Sources page shows Suricata FRESH.
   - `ip -s link show IFACE` and the stats `capture.kernel_drops`: drops stay near 0.
   - `systemctl list-timers 'netwatch-*'`; run `sudo systemctl start netwatch-archive.service` once and read its journal.
   - Response mode stays ids_only (no Linux firewall effector yet).

## Zeek (optional, 2026-10-16)

After step 6: `sudo /opt/netwatch/packaging/linux/install-zeek.sh`. It adds the `security:zeek` OBS repo (key pinned by
fingerprint), installs `zeek-lts-core` only, without recommends (8.0.x, `/opt/zeek`; the `zeek-lts` metapackage pulls in a listening mail server), user `zeek`, `/etc/netwatch/zeek/netwatch.zeek`,
`netwatch-zeek` (AF_PACKET on `NW_IFACE`, logs `/var/lib/zeek/logs`) and `netwatch-zeek-cleanup.timer` (04:05, 3 days),
a `netwatch.service.d/zeek.conf` drop-in (`SupplementaryGroups=zeek`), sets `ZEEK_LOGS_ENABLED` and `ZEEK_LOG_PATHS`
in the overlay (backup `.bak-zeek`) and restarts netwatch. Check: NetWatch Sources shows ZEEK FRESH;
`/var/lib/zeek/logs/capture_loss.log` stays low.
