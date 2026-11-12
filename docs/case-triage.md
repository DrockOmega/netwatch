# Case triage: keeping the open list honest

The open list in the console means one thing: a case someone still has to look at. Everything
else is closed with a reason. The operator runs this; a case is never closed to make the list shorter.

## What files itself

- Info-severity findings (Suricata stream/decoder engine events, public-IP echo lookups,
  policy/app identification, "not suspicious") and a known device going quiet are filed
  `Resolved` with the reason "Informational finding". A repeat at info does not reopen them;
  a real alert on the same case does (`netwatch_incidents.info_only`).
- `ACCEPTED_EGRESS` matches (device-scoped, with a review date) are info and file `Resolved`.

## The loop (daily, light; weekly, full)

1. `python tools/case_triage.py families` lists open cases grouped by detector and message
   shape, with severity and how long each family has been quiet.
2. Take the largest family first. For each, decide from evidence, not from the label:
   - **Real**: keep it open, investigate, contain if needed (your response policy).
   - **False positive**: tune the source first, then close. Tuning goes where the noise is
     made: a narrow Suricata suppression (`packaging/suricata/threshold.config`, checked by
     `tests/test_suricata_tuning.py`), a detector exemption in the sensor overlay
     (`BEACON_IGNORE_*`, `DNS_TUNNEL_IGNORE_SUFFIXES`, `EXFIL_IGNORE_DEVICE_WINDOWS`,
     `UDP_FLOOD_IGNORE_DEVICE_ENDPOINTS`), a device-scoped `ACCEPTED_EGRESS` entry, or a
     code fix when the detector itself is wrong. Never mute a whole detector or a /0.
   - **Unattributable and quiet**: close `Resolved` saying so; a recurrence reopens it, and
     every detector now records enough (source MAC, sample names) to attribute it next time.
3. Close the reviewed family with its reason:
   `python tools/case_triage.py close --action <ACTION> [--match <regex>] --reason "..."`
   (dry run), then the same with `--apply`. The reason names the evidence and the tuning.
4. Back up the overlay before editing it (`netwatch.<host>.json.bak-<what>-<date>`), restart
   `netwatch` or reload `netwatch-suricata`, and check the next day's families for the same
   shape coming back.

## Evidence sources for a verdict

Zeek logs on the sensor (`/var/lib/zeek/logs`: dns answers, ssl SNI, conn history, dhcp names),
EVE (`/var/lib/suricata/eve.json.<date>`), the ledger (`telemetry_ledger.db`, read-only with
the service venv), the device inventory, `ip neigh`, RDAP for external owners, and the
public Tailscale DERP map for relay traffic.
