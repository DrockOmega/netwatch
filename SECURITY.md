# Security Model

NetWatch is a defensive network-monitoring tool for a network you own or
administer. Monitoring is passive; response is explicit and active. This document
states what privileges it needs, why, and the boundaries it enforces.

## Privilege requirements

- **Raw packet capture.** The sniffer uses Scapy/Npcap, which requires
  administrator rights (the packaged build sets `uac_admin=True`). Capture is
  confined to a single child process (`io_sniffer_process`) — the smallest
  surface that needs the privilege. The UI and database processes run with the
  same token today; isolating their privileges further is tracked work.
- **The monitor makes no outbound calls.** Outbound traffic comes only from
  separate operator-run or scheduled tools: `threatintel_update.py` (threat-intel
  feeds), `tools/refresh_oui_db.py` (IEEE OUI registry) and `netwatch_archive.py`
  (rclone upload, see Data handling). There is no telemetry or auto-update.

## Active mitigation

The mitigation engine (`netwatch_mitigation.py`) can create Windows Firewall
block rules via `netsh advfirewall`, which requires the elevated token the app
already holds. It is designed to fail safe:

- **Detection only by default** for fresh installations; response engines remain
  initialized to track existing state. An explicit `IDS + IPS READY` selection
  queues new eligible actions behind operator approval.
- **Immediate detection-only switch** suppresses new response actions without
  destroying active state or stopping watcher initialization.
- **Allowlist** prevents blocking local/loopback/multicast/broadcast ranges, so
  a malformed or spoofed source can't be used to cut off the LAN.
- **Manual-approval gate** in ready mode — an alert only queues a block; a human
  approves before any rule is created.
- **Reversible** — every block auto-expires (TTL) and is tracked in a persisted
  ledger so nothing is left dangling across restarts.

The blast radius of a false positive is therefore a single, time-boxed,
manually-approved, reversible firewall rule against a non-local IP.

## Runtime response staging

The top-right selector is the authoritative, persisted runtime control:

- `IDS ONLY` ignores new response intents while detection and audit continue.
- `IDS + IPS READY` queues new response intents for operator approval.
- `IPS AUTONOMOUS` immediately applies new eligible response intents except
  ARP-triggered quarantine, which always requires operator attribution and approval.

Existing blocks and quarantines remain visible and reversible after a shift to
`IDS ONLY`; the switch does not silently restore access that an incident may
still require. Pending requests are not retroactively executed when autonomy is
enabled.

## Ordered policy staging

The flow policy engine is first-match, versioned, and defaults to `manual` so
block intents always reach the runtime response plane. The selected response mode
then ignores, queues, or enforces the intent. The mitigation allowlist and capacity checks are
re-evaluated at enforcement time in every mode. An invalid hot reload retains the
last-known-good policy.

Policy is re-evaluated when a flow changes observed direction, obtains late TLS
identity, or sees a new policy digest. Block commands use a dedicated bounded,
non-evicting control queue; presentation telemetry remains independently lossy.
Packet MAC addresses may narrow alert/block rules but cannot authorize `allow`.

This is host-level response rather than an inline packet verdict: the triggering
packet may already have reached the Windows stack. The planned WinDivert and WFP
stages therefore remain separate trust boundaries with explicit watchdog and
bypass requirements.

## Packet evidence

Capture-on-alert retains raw frames only in a size/time-bounded memory ring,
coalesces and caps pending incidents, and writes through a bounded background
worker so disk latency cannot block packet ingestion. It retains a bounded number
of local PCAP files after configured alert actions. PCAPs
contain payload data and must be protected as sensitive evidence. The recorder
does not transmit them or invoke an external analyzer.

## Suricata integration

The optional adapter reads a local EVE JSON file. Alert, anomaly and drop records
create findings; every other EVE family is retained as evidence only. Endpoint locality determines the response target; ambiguous
records are not containment-eligible. EVE fields remain untrusted correlation data;
they do not execute commands. Suricata inline disposition, exception policy, and
ruleset provenance remain owned by the Suricata deployment.

## Active LAN quarantine

The quarantine engine (`netwatch_quarantine.py`) can isolate a local device by
**ARP cache poisoning** — sending forged ARP so the device's route to the gateway
points at a black-hole MAC. This is **active emission on the LAN**, and the
enforcement point that remains when the gateway is a locked ISP box with no
firewall/VLAN surface. It targets **your own network**; using it against a network
you do not administer is out of scope and likely unlawful. It fails safe:

- **Detection only by default** for new response intents; ready mode never transmits
  until an operator approves a pending quarantine.
- **Manual-approval gate** — an ARP-spoof alert is suppressed in detection-only
  mode and queues a pending quarantine in ready or autonomous mode; a human approves
  before any frame goes out.
- **Self-response suppression** — the detector ignores the configured quarantine
  sink MAC and requires time-separated rebind confirmation before replacing a
  trusted IP-to-MAC binding.
- **Protected set** is the inverse of the firewall allowlist: the gateway, this
  host, and broadcast/multicast/structural addresses can never be quarantined, so
  a spoofed or malformed target cannot be used to poison the gateway itself.
- **Reversible** — every quarantine auto-expires (TTL) and **release sends
  corrective ARP** so the device's cache heals immediately rather than waiting to
  time out; the active set is persisted and reconciled on boot.
- **No accidental MITM** — the default sink is a locally-administered black-hole
  MAC, so the victim's traffic is dropped by the switch, not routed through this
  host.
- **Sensor gateway fail-safe** — containment aborts or releases if the local ARP
  cache resolves the gateway to the sink MAC, then corrective ARP is emitted.

The blast radius of a false positive is a single, time-boxed, manually-approved,
self-healing loss of connectivity for one LAN device.

## Trust boundaries

- **IPC contract.** Every message crossing a process boundary is built with
  `make_message` and re-validated with `is_message_payload` on receipt
  (`netwatch_core.py`). Receivers check `action` before unpacking and never
  assume schema. Telemetry may drop oldest under pressure; policy response uses
  a separate non-evicting queue.
- **UI rendering.** The active Qt model/view and audit widgets render packet-
  influenced fields as plain text and do not bind them to URL openers.
- **Service API.** `netwatch_api.py` listens on loopback (`127.0.0.1:8765`) and
  refuses a non-loopback bind unless explicitly allowed (no TLS then). Every
  request except `GET /v1/hello` needs the bearer token from `service-api.secret`
  (random 32 bytes, constant-time compare). On Windows the secret's ACL is
  restricted with `icacls` and the file is refused if any principal other than
  SYSTEM and Administrators can read it; on POSIX it must be mode 0600. Each
  request has a 5 s whole-request deadline.
- **Console gateway.** `netwatch_gateway.py` reaches each sensor over an SSH tunnel
  to the sensor's loopback API, holding a 0600 copy of that sensor's secret. The
  console talks only to the gateway on `127.0.0.1:8766`, authenticated by the
  bearer token in `ui.token`, and never sees a sensor secret. The service-side
  response actions only record an intent; they do not enforce.
- **Untrusted input** is the packet stream itself. The TLS ClientHello parser
  (`netwatch_ja3.py`) does bounds-checked reads and catches parse errors;
  malformed packets degrade to "encrypted-payload" rather than crashing.

## Data handling

- Captured metadata (IPs, MACs, domains, sizes) is written to a local SQLite
  ledger (`telemetry_ledger.db`) and security store. Both are git-ignored. It
  leaves the host only through the optional Google Drive archive
  (`netwatch_archive.py`, via rclone): complete days of ledger history and
  finished Suricata EVE files, from a scheduled task whose rclone config is
  readable by SYSTEM and Administrators only. Local data is never deleted by it.
  Case data also crosses the SSH tunnel to the console gateway cache. Backups
  (`netwatch_backup.py`) stay local and exclude `service-api.secret`.
- Outbound fetches (threat-intel feeds, OUI registry) send only a plain HTTPS
  GET; no captured data is included.
- The MaxMind GeoLite2 database is **not** redistributed with this repo; users
  supply their own (see README). Treat any local copy under its MaxMind EULA.

## Reporting

This is a personal/portfolio project. If you find a security issue, open a
GitHub issue describing the impact and reproduction. Do not include captured
traffic that identifies real hosts.
