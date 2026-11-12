# Suricata tuning for the mirror-port sensor VM (2026-10-08)

Historical: the `netwatch-sensor` VM was retired on 2026-10-09; a native Suricata for Windows install is now the sensor.
The tuning below is kept as reference for a future Linux sensor.

Applied on `netwatch-sensor`; backups sit next to each file with a `.bak-2026-10-08` suffix.

- `/etc/suricata/disable.conf`: add `re:^alert .*msg:"SURICATA STREAM ` then run `suricata-update`.
  A mirror port shows partial TCP conversations, so stream protocol-anomaly events (invalid ack,
  out of window, bad timestamp) fired ~90% of all alerts with no security value. Stream tracking
  itself stays on.
- `/etc/suricata/suricata.yaml`: `outputs: - fast: enabled: no` (EVE already carries every alert;
  fast.log had grown to 125 MB) and `stats: interval: 60` (was 8).

Measured after the change: alerts ~6 per 2 min (from thousands), VM CPU pressure ~28% -> ~19%.
