# NetWatch — Home Network Monitoring & Mitigation

A Windows desktop tool that captures live network traffic, runs real-time
anomaly detection, and presents it through an incident-first detection and
response console.
Built as a study in defensive security engineering: process isolation, a strict
IPC contract, allocation-free hot paths, and a hardened UI boundary.

> **Status:** active development. Detection engine, active mitigation (firewall
> response), device inventory, and per-device baselining are functional and
> tested; further monitoring depth is on the roadmap below.

<!-- TODO: add screenshot of the dashboard here -->

## What it does

- **Live capture** of Ethernet traffic via Scapy/Npcap, with SNI (TLS ClientHello) and
  DNS query-name extraction.
- **Real-time detectors**, all running per-source/per-destination over a
  pre-allocated memory arena:
  - UDP flood (sliding-window packet rate)
  - Port sweep (distinct-destination-port bitmap)
  - Volumetric exfiltration (windowed byte volume)
- **Signature matching** against a hot-reloaded threat list (domains, ISO
  country codes, ports) — egress to flagged geographies/domains/ports alerts.
- **Context enrichment**: GeoIP country lookup, TTL-based OS fingerprint guess,
  LAN-vs-external classification.
- **Persistence** to a local SQLite WAL ledger.
- **Device inventory**: passive MAC-keyed inventory with OUI vendor lookup (from
  the public IEEE registry) and **new-device alerts** the first time an unseen
  device appears on the LAN. See [Device inventory](#device-inventory).
- **Per-device baselining**: learns each device's normal egress volume online and
  flags windows that deviate far above *its own* norm — adaptive anomaly detection
  that complements the fixed-threshold detectors. See
  [Baselining](#per-device-baselining).
- **ARP-spoof / MITM detection**: tracks IP↔MAC bindings from captured ARP and
  flags rebinds (a gateway MAC change is the classic man-in-the-middle) and
  one-MAC-claims-many-IPs subnet poisoning. See [ARP/MITM](#arp-spoof--mitm-detection).
- **DNS analytics**: DGA scoring (randomness heuristic over query names),
  NXDOMAIN-burst detection (the DGA/C2 footprint), and tunneling detection
  (long/high-entropy subdomains, TXT/NULL records). See [DNS](#dns-analytics).
- **JA3/JA3S TLS fingerprinting**: fingerprints the TLS ClientHello/ServerHello to
  identify client/server software (and malware families) even on encrypted
  connections, with a known-bad-fingerprint blocklist. See [JA3](#ja3ja3s-tls-fingerprinting).
- **Threat-intel feeds**: ingests public blocklists (abuse.ch, FireHOL, Spamhaus
  DROP) and matches every connection's IP/domain/JA3 against them. Bad-IP hits are
  mitigation-eligible. See [Threat intel](#threat-intel-feeds).
- **Historical query / timeline**: query the event ledger — filtered event lists,
  top talkers/domains/countries, and an activity timeline. The dashboard HISTORY
  tab charts the latest 60 minutes without blocking live capture. See
  [History](#historical-query--timeline).
- **Human-web observation**: reduces outbound TCP 80/443 and QUIC 443 to one
  explainable row per session, then separates probable human signal from web
  noise using hostname context, destination novelty, multi-host fan-out, and
  recurrence cadence. The Traffic page exposes `OUTBOUND WEB`, `HUMAN SIGNAL`,
  and `WEB NOISE` filters; classifications are probabilistic because passive
  capture cannot see the originating desktop process. Derived sessions bypass
  packet-tail load shedding, persist in SQLite, and reconcile back into the UI
  after restart or IPC loss.
- **Secure-node exclusion**: an on-demand Traffic filter hides operator-defined
  source nodes by IP or MAC while retaining traffic they send to trusted systems.
  A separate endpoint-wide mode is available when both sides should disappear.
- **Active mitigation**: turn an alert into a reversible Windows
  Firewall block on a bad external IP, with an allowlist, auto-expiry, a capacity
  cap, and a manual-approval gate. See [Mitigation](#mitigation).
- **Active LAN quarantine**: sever a misbehaving *local* device via ARP
  isolation from this host — enforcement that works behind a locked ISP gateway,
  with dry-run, auto-expiry, heal-on-release, and a manual-approval gate. See
  [LAN quarantine](#lan-quarantine).
- **Liveness monitoring**: every worker emits heartbeats; the UI surfaces a
  "fatality" banner if the sniffer, core, or DB pipeline stalls.
- **Capture-integrity accounting**: NetWatch owns the pcap handle and polls
  `pcap_stats`, so packets the driver dropped *before* Scapy are reported
  instead of silently reading as a quiet network.
- **Layered configuration**: defaults, a shared JSON overlay, a per-host
  overlay, and `$NETWATCH_CONFIG` — one checkout runs on several machines.
  See [Configuration](#configuration).
- **Rotating logs** per process, and **ledger retention** so the SQLite event
  store stays bounded instead of growing until the disk does.

## Architecture

Four processes communicate through bounded `multiprocessing.Queue`s using a
strict, re-validated message envelope. Scapy is confined to one process so a
parser crash there cannot take down the UI or the database.

```
io_sniffer_process ──ingestion_queue──▶ dod_core_process ──render_queue──▶ UI (OperationsDashboard)
                                              │           ──alert_queue───▶ UI
                                              │           ──policy_queue──▶ UI response
                                              └──db_queue────────────────▶ db_persistence_worker ──db_status_queue──▶ UI
```

- **`io_sniffer_process`** — owns the Npcap handle (`full` captures every Ethernet
  frame; optional `balanced` excludes small bare TCP ACKs),
  applies a 256 MiB kernel buffer (`PCAP_BUFFER_BYTES`), and parses raw Ethernet frames without building
  a Scapy object graph per packet. It extracts SNI / DNS metadata / JA3-JA3S and
  ships events in **batches** (one `INGEST_PACKET` carries up to
  `INGEST_BATCH_MAX` events). ARP analysis replays the native control ledger.
  Kernel drop counters remain readable. Heartbeats track read-loop progress;
  quiet traffic is idle, while unavailable counters leave capture unverified.
  IP telemetry can drop on IPC backpressure; accepted control records are durable.
- **`dod_core_process`** — analytics core. Pre-allocates a single NumPy
  structured arena of **time-bucketed** per-endpoint counters (~8 KB per
  endpoint, ~17 MiB total at 2048 slots), with an O(1) free-list slot
  allocator and a periodic GC that reclaims idle slots. No allocation on the
  hot path. Flow policy re-evaluates on direction, TLS identity, and policy
  version changes. The bounded human-web classifier scores one observation per
  outbound web session instead of presenting every packet; block commands do
  not share the lossy alert queue. Detectors
  live in [`netwatch_core.py`](netwatch_core.py).
- **`db_persistence_worker`** — SQLite in WAL mode (`synchronous=FULL`),
  batched inserts, indexed for the history queries, with age- and row-count
  retention. Large trims are split into bounded commits and interleaved with
  queued telemetry so maintenance cannot starve ingestion or its watchdog.
- **UI** — an incident-first PyQt6 model/view console with virtualized incident,
  traffic, asset, and enforcement tables. Overview posture cards drill into
  filtered incident triage, pending response controls, or the live flow tail.
  A drain thread reads batched render IPC, keeps raw activity and derived web
  sessions in separate bounded stores, and reconciles both durable paths from
  SQLite every five seconds; charts repaint only when a new snapshot arrives.

The Traffic page is exposure-first: `ALL CAPTURED`, `ANY OUTBOUND`, and
`UNCLASSIFIED OUTBOUND` operate on raw durable activity, while `OUTBOUND WEB`,
`HUMAN SIGNAL`, and `WEB NOISE` narrow the independent classified-session path.
Unclassified rows remain visible with factual activity labels instead of a blank
signal column. Active filters are applied in SQLite before the row ceiling, so a
busy trusted source cannot evict older matching evidence from the filtered view.
Security findings have a separate `INCIDENT_DB` ledger. Collectors commit detections
and correlated cases before notifying the dashboard, so the presentation queue
and dashboard restart cannot erase accepted findings. The Incidents page exposes
assignment, acknowledgment, notes, closure reasons, audit history and supporting
source records. Confidence is independent of severity and defaults to Observed
without an explicit source assessment. Local audit records remain editable by a
host administrator; remote authentication, central storage and retention are
still deployment work.

The durable filtered view covers `UI_TRAFFIC_LOOKBACK_SEC` (24 hours by default).
New ledger records retain source ports, VLAN IDs, sensor identity, capture interface
and fragment/ICMP metadata. Historical records keep missing fields unknown.
Compaction preserves distinct connections and capture sources.
TTL is shown only as low, mid, or high; it is not presented as a device OS.

The Traffic page reports capture topology and observed-source coverage separately
from sensor and packet-loss health. The default `CAPTURE_TOPOLOGY=endpoint` is
explicitly marked **COVERAGE PARTIAL**:
promiscuous mode cannot observe switched or Wi-Fi frames that never reach the
sensor NIC. Whole-LAN claims require a real `mirror`, `bridge`, or `gateway`
capture point and an explicitly validated `CAPTURE_COVERAGE_ASSERTION=complete`;
otherwise coverage remains unverified or partial.

The IPC contract and the detectors are the parts most likely to harbour bugs, so
they're isolated in `netwatch_core.py` (no Qt/GL/Scapy imports) and covered by
the test suite.

## Visibility caveat (read this)

On a **switched** network, passive capture on one NIC sees only this host's
traffic plus broadcast/multicast — *not* every device's traffic. For
whole-network visibility you need a **SPAN/mirror port** on a managed switch (or
a tap) feeding the capture NIC. This is a property of switched Ethernet, not a
bug. Plan placement accordingly.

## Setup

Requires Windows, Python ≥ 3.12, and **[Npcap](https://npcap.com/)** installed
(for raw capture). Must be run **elevated** (raw sockets need admin).

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### GeoIP data (not bundled)

The MaxMind GeoLite2 license prohibits redistribution, so the `.mmdb` is not in
this repo. Download `GeoLite2-Country.mmdb` from your (free) MaxMind account and
place it in the project root. Without it the app still runs; every packet just
gets country `--`.

### Configure

Copy [`netwatch.config.example.json`](netwatch.config.example.json) to
`netwatch.config.json` and set at minimum `NIC_INTERFACE` to your adapter's
name as Npcap reports it. See [Configuration](#configuration) for the full
layering model — you should not need to edit source to configure a host.

```powershell
copy netwatch.config.example.json netwatch.config.json
# list adapter names/descriptions Npcap will accept:
python -c "from scapy.arch.windows import get_windows_if_list; [print(i['name'],'|',i['description']) for i in get_windows_if_list()]"
```

### Run

```powershell
# from an elevated shell
.venv\Scripts\python.exe main.py
```

### Build a standalone exe

```powershell
pyinstaller main.spec   # one-dir build, UAC-elevated, bundles data files
```

## Configuration

Configuration is data, not source. Layers, lowest precedence first:

```
netwatch_config.DEFAULTS  ->  netwatch.config.json  ->  netwatch.<hostname>.json  ->  $NETWATCH_CONFIG
```

Each layer is a shallow JSON overlay naming only the keys it changes. Unknown
keys are reported at boot and ignored (a typo cannot silently do nothing); keys
starting with `_` are treated as annotations, since JSON has no comments.
Relative paths resolve next to `main.py` (or the frozen exe); absolute paths are
used verbatim. Overlays are gitignored — they name one machine's NIC and paths.

Two values are discovered automatically when you do not set them:

| Key | Discovery |
| :-- | :-- |
| `GATEWAY_IP` | parsed from `route print`, and re-checked every `GATEWAY_REFRESH_SEC` so a DHCP or network change re-anchors gateway-rebind escalation |
| `LOCAL_PREFIXES6` | the delegated /64 derived from this host's own global IPv6 address |

### IPv6 locality — set this if you have IPv6

Your ISP delegates a **globally-routable** prefix to your LAN, so nothing
structural distinguishes your own devices from the internet. NetWatch treats
`::1`, `fe80::/10`, `fc00::/7`, and `ff00::/8` as local automatically, but a
`2600:…` address on your own network is only local if its prefix is in
`LOCAL_PREFIXES6`.

If that list is wrong, every internal IPv6 flow is classified as external:
baselining mis-attributes LAN egress, threat-intel matching runs against your own
hosts, the `EXTERNAL (HIDE LOCAL)` filter stops working — and, with mitigation
enabled, **your own devices become block-eligible**. Auto-detection covers the
usual case; pin it explicitly if your delegation is stable:

```json
{
  "LOCAL_PREFIXES6": ["2600:1700:abcd:1200::/64"],
  "LOCAL_PREFIXES6_AUTO": false
}
```

The mitigation allowlist is fed from the same list, so monitoring and mitigation
always agree on what counts as local.

### Ledger retention

The event ledger compacts packets into one-second directional flow summaries;
`packet_count` and `size_bytes` preserve exact event and byte totals. Rows older
than `DB_RETENTION_DAYS` (default 7) are pruned every `DB_PRUNE_INTERVAL_SEC`,
and the table is trimmed to `DB_MAX_ROWS` (default 20M). Set either to `0` to
disable that bound. The three indexes the history queries use (`timestamp`,
`(src_ip, timestamp)`, `(dst_ip, timestamp)`) are created at startup.

### Logs

Each process writes a rotating log to `LOG_DIR` (default `logs/`):
`netwatch-boot.log`, `-sniffer`, `-core`, `-db`, `-ui`, and `-alerts`. The alerts
log is the durable copy of every line shown in the Anomaly Detection Ledger. Tune with `LOG_LEVEL`,
`LOG_MAX_BYTES`, `LOG_BACKUPS`, and `LOG_TO_CONSOLE`. Watch the sniffer log for
`CAPTURE LOSS` — if the driver is dropping packets, every other count in the app
is a floor rather than a measurement. Every loss interval remains in the rotating
sniffer log; the UI emits the first degraded transition, one reminder per minute,
and one recovery transition instead of scrolling identical warnings continuously.
Sustained detector conditions use the same incident model: one alert per
detector/source during `DETECTOR_ALERT_COOLDOWN_SEC` instead of one line per
threshold reset.

## Device inventory

A passive, MAC-keyed inventory ([`netwatch_inventory.py`](netwatch_inventory.py))
builds itself from captured traffic — the inventory adds no traffic of its own
(active response lives in [Mitigation](#mitigation) and
[LAN quarantine](#lan-quarantine)). For every packet it records both endpoints' MAC
addresses (attaching an IP only when that IP is local), resolves a vendor from
the MAC's OUI, and raises a **new-device** notice the first time it sees a MAC.

- **Vendor resolution** uses `oui_db.json`, generated from the public, freely
  redistributable IEEE OUI registry. Refresh it any time:
  ```powershell
  python tools/refresh_oui_db.py     # ~40k vendors; falls back to a curated seed offline
  ```
- **Randomized MACs** (modern phones with MAC privacy) are detected via the
  locally-administered bit and labelled accordingly rather than mis-resolved.
- **Persisted** to a JSON ledger so "new" is meaningful across restarts. The
  logic is pure and unit-tested; the ledger is a deliberate seam for a future
  cloud-sync backend.

New-device notices appear in the dashboard's anomaly ledger (styled distinctly —
they are informational, never a mitigation trigger).

### Inventory CLI

```powershell
python devices.py list                 # table: MAC, vendor, packet count, last seen, IPs
python devices.py list --sort count    # busiest devices first (also: last, first, mac)
python devices.py list --json          # machine-readable
```

## Per-device baselining

The fixed-threshold detectors above ask "is this above an absolute line?"
Baselining ([`netwatch_baseline.py`](netwatch_baseline.py)) asks the complementary
question — "is this abnormal *for this device*?" Each device's normal egress
volume is learned **online** (an exponentially-weighted mean and variance), and a
window that spikes far above that learned norm is flagged, even if it never crosses
a global threshold.

- **Adaptive, per-device** — a smart bulb that suddenly uploads 50× its usual
  volume trips on its own history; a NAS that always moves gigabytes does not.
- **Robust** — a warmup period, a regularity floor (so a hyper-steady device
  doesn't trip on trivial jitter), and one-sided scoring (spikes, not quiet
  periods). A *sustained* level change is absorbed into the baseline within a few
  windows and stops alerting, instead of becoming a permanent false positive.
- **A lead, not a trigger** — anomalies surface as notices (styled distinctly);
  they are intentionally **not** wired to auto-mitigation.
- **Pure + persisted + unit-tested** — the model serializes to JSON (again, a
  cloud-sync seam); the online statistics are covered by deterministic tests.

### Baseline CLI

```powershell
python baseline.py list                 # learned per-device baseline (mean/std/windows)
python baseline.py list --sort mean      # biggest talkers first
python baseline.py list --json
```

## ARP-spoof / MITM detection

Every ARP packet asserts a claim — "IP X is at MAC Y." On a healthy LAN each IP
maps to one stable MAC; ARP spoofing breaks that to put an attacker in the middle.
[`netwatch_arp.py`](netwatch_arp.py) watches the binding table passively (no active
probing) and raises two signals:

- **Rebinding** — an IP repeatedly claimed by a *different* MAC across a minimum
  observation interval. One probe burst remains an unconfirmed candidate and
  cannot replace the trusted binding. A confirmed rebind of the **gateway**
  (auto-detected at startup) is escalated to a critical alert.
- **MAC fan-out** — a single MAC claiming many distinct IPs at once, which is what
  full-duplex subnet poisoning looks like from a passive vantage point.

The default `CAPTURE_PROFILE=full` installs no kernel filter, retaining IPv6
control traffic, ICMP, VLAN frames and non-IP Ethernet traffic. `balanced` uses
`not (tcp and len < 80 and tcp[13] == 0x10)` and omits small bare TCP ACKs; its
traffic totals are therefore sampled. An explicit `BPF_FILTER` overrides the
profile. The native control collector retains ARP, LLDP, EAPOL and spanning-tree
frames. ARP analysis replays committed records in a stable database sequence.
Bindings, pending confirmations, findings and replay position commit together,
scoped by sensor, interface and VLAN. Alerts by default — and the offending LAN device can be isolated on
approval via [LAN quarantine](#lan-quarantine). Claims using NetWatch's configured
quarantine sink MAC are suppressed before correlation.

## DNS analytics

DNS is a favorite covert channel — malware uses it to find C2 (domain-generation
algorithms) and to exfiltrate data (tunneling). [`netwatch_dns.py`](netwatch_dns.py)
analyzes the query names and response codes already on the wire:

- **DGA scoring** — algorithmically-generated domains look random (high entropy,
  long, digit-heavy, unpronounceable). A transparent heuristic scores each
  registrable label 0–1 and flags the suspicious ones.
- **NXDOMAIN bursts** — a host getting many "no such domain" answers in a short
  window is the classic DGA/C2 footprint (most generated domains don't resolve).
- **Tunneling** — long, high-entropy subdomain labels and TXT/NULL query types
  carry encoded payload rather than a real lookup.

Findings are rate-limited so a noisy host can't flood the log, and persisted as a
per-host summary plus recent flagged domains. Alerts only — never auto-blocked.
The DGA heuristic is intentionally simple and transparent; a production system
would pair it with a public-suffix list and a threat-intel feed (roadmap).

### DNS CLI

```powershell
python dns.py list       # per-host summary: queries, NXDOMAIN, DGA, tunnel counts
python dns.py recent     # recently flagged domains (DGA / tunnel) with scores
```

## JA3/JA3S TLS fingerprinting

A TLS ClientHello is sent in the clear even when everything after it is encrypted.
JA3 ([`netwatch_ja3.py`](netwatch_ja3.py)) hashes the structural fields of that
handshake — version, cipher suites, extensions, supported groups, point formats —
into a fingerprint that identifies the **client software**. The same application
yields the same JA3, and many malware families have well-known JA3s, so you can
spot known-bad TLS clients without decrypting anything. JA3S does the same for the
server side.

- **Canonical JA3 hashes** (GREASE excluded) so they line up with published JA3
  threat-intel databases.
- **Versioned inventory** — new JA3 observations are `ja3-canonical-v1`.
  Pre-correction entries retain their original hashes and are labeled
  `ja3-legacy-grease-v1`; reobserving the same hash labels its combined count
  `ja3-mixed-v1`. Legacy-only entries are not marked as canonical blocklist hits.
  Raw ClientHello fields and JA3S server-extension order remain unchanged.
- **Inventory + blocklist** — every fingerprint is counted with a sample SNI/peer;
  any match against `ja3_blocklist.json` (empty by default, seedable from a JA3
  feed) raises a critical alert.
- The binary TLS parser is fully bounds-checked and unit-tested against hand-built
  handshakes with independently-computed reference hashes.

### JA3 CLI

```powershell
python ja3.py list                  # fingerprint inventory (JA3 + JA3S), most-seen first
python ja3.py list --blocklisted    # only blocklist hits
```

## Threat-intel feeds

NetWatch can match traffic against public indicators of compromise — bad IPs,
domains, and JA3 fingerprints from abuse.ch (Feodo / SSLBL / URLhaus), FireHOL, and
Spamhaus DROP.

**Passive by design.** The monitor itself never reaches out — it only reads a local
cache (`threatintel_cache.json`). A separate operator step does the fetching, like
updating antivirus signatures:

```powershell
python threatintel_update.py update     # fetch feeds -> rebuild the local cache
python threatintel_update.py status      # show what's cached (per-source counts)
```

Schedule `update` with Windows Task Scheduler (or cron) to keep it fresh. A feed
that fails to fetch is skipped, and the cache is only overwritten when at least one
feed yields indicators, so an outage can't wipe your protection.

The running monitor hot-reloads the cache (no network) and matches each packet's
external IP (via a fast bisect over merged CIDR ranges — microsecond cost even with
thousands of ranges), SNI/domain, and TLS fingerprint. A **bad-IP hit is emitted as
a regular alert and is mitigation-eligible** — unlike the other monitoring signals,
the offender here is a known-bad *external* host, so it's a legitimate block target.

## Historical query / timeline

The monitor persists every event to a SQLite ledger; `history.py`
([`netwatch_history.py`](netwatch_history.py)) is the read path over it — opened
**read-only**, so it's safe to run while the monitor is live (WAL).

The dashboard's **HISTORY** tab refreshes that read path on a background thread,
shows a gap-preserving 60-minute activity chart and top sources, and can isolate
IPv4 or IPv6. The live stream has the same address-family filter and renders full
compressed IPv6 source addresses instead of forcing them into an IPv4-width column.

```powershell
python history.py summary                                  # totals, sources, span
python history.py query --since 1h --proto TCP --port 443  # filtered event list
python history.py query --domain anthropic --src 10.0.0.5
python history.py top talkers --by bytes                   # busiest hosts
python history.py top domains                              # most-contacted names
python history.py top countries
python history.py timeline --since 2h --bucket 1800        # ASCII activity timeline
```

Filters (`--since`/`--until` accept `30s`/`15m`/`2h`/`7d` or an epoch; plus `--src`,
`--dst`, `--proto`, `--port`, `--domain`, `--country`) combine across every command.
All queries are parameterized — filter values are bound, never interpolated.

## Mitigation

The mitigation engine ([`netwatch_mitigation.py`](netwatch_mitigation.py)) turns
a detection into an action. Its watcher is initialized by default and built so
it cannot "auto-footgun":

- **Allowlist** — RFC1918/loopback/link-local/multicast/broadcast ranges are
  never blockable; an explicit IP allowlist is honored.
- **Reversible + auto-expiring** — every block carries a TTL and is lifted
  automatically; the active set is persisted to a JSON ledger so blocks survive a
  restart and stale ones are cleaned up on the next boot.
- **Manual-approval gate** — in the default `IDS + IPS READY` mode an alert only *queues*
  a block; nothing happens until you approve it. Auto mode blocks immediately.
- **Live by default** — approval creates the real rule; `MITIGATION_DRY_RUN=true`
  remains available for simulation.

The policy/ledger logic is pure and unit-tested; the `netsh` effector is injected
(tests use a fake and never touch the real firewall).

### Operator CLI

```powershell
python mitigate.py list                                   # active blocks
python mitigate.py block 203.0.113.7 --reason scan        # dry-run preview
python mitigate.py --apply block 203.0.113.7 --reason scan # actually block (admin)
python mitigate.py --apply reconcile                      # lift expired blocks
python mitigate.py --apply unblock 203.0.113.7
```

### In-dashboard control panel

The **Enforcement** view shows the firewall response panel:

- a status line (mode · dry-run/live · pending/active counts);
- **PENDING APPROVAL** list with **APPROVE / DENY / APPROVE ALL** — in manual
  mode an alert queues a block here and nothing happens until you act;
- **ACTIVE BLOCKS** list with a live TTL countdown and **UNBLOCK**.

The top-right selector changes the persisted operating mode without restarting:

- **IDS ONLY** keeps both response engines initialized but suppresses new containment.
- **IDS + IPS READY** queues eligible firewall and quarantine actions for approval.
- **IPS AUTONOMOUS** enforces new eligible findings immediately; ARP-triggered
  quarantine remains approval-gated because ownership conflicts require attribution.

### Enabling in-app

Use the top-right operating-mode selector. `RESPONSE_MODE=ids_only` is the
fresh-install default. Explicit configuration and persisted operator selections
remain authoritative.

## LAN quarantine

Firewall mitigation blocks a bad **external** IP on this host. Quarantine does the
opposite end of the problem: it severs a **local** device — the enforcement point
that survives a locked-down ISP gateway (Xfinity xFi and friends expose no
firewall, VLAN, or ACL to automate).

Mechanism ([`netwatch_quarantine.py`](netwatch_quarantine.py)): **ARP cache
poisoning from this host**. On a switched LAN, NetWatch sends the target a forged
ARP reply — "the gateway is at `<sink MAC>`" — so the device's internet-bound
frames go to a MAC that isn't the gateway and its path dies. With
`QUARANTINE_BIDIRECTIONAL` it poisons the gateway's cache too, for the return
path. The poison is re-asserted every `QUARANTINE_REASSERT_SEC` (caches expire and
the real gateway broadcasts gratuitous ARP); **releasing** sends *corrective* ARP
so the device recovers immediately instead of waiting for its cache to time out.

Guardrails mirror mitigation, plus the ones that matter for active emission:

- **Live watcher by default** — `IDS + IPS READY` queues rather than emits;
  `QUARANTINE_DRY_RUN=true` remains available for frame-level simulation.
- **Manual-approve by default**: an ARP-spoof alert
  queues a pending quarantine in every runtime mode; nothing goes on the wire
  until you approve.
- **Never quarantinable**: the gateway, this host, and broadcast/multicast — the
  protected set is the *inverse* of the firewall allowlist, since an ordinary LAN
  device is a valid target here.
- **Auto-expiry** (`QUARANTINE_TTL_SEC`), a capacity cap, and a persisted ledger so
  a quarantine survives a restart and is re-asserted (and still expires) on boot.
- The **sink MAC** defaults to a locally-administered black hole
  (`02:00:00:00:de:ad`) so the target's traffic is dropped by the switch rather
  than pulled to this host — no accidental man-in-the-middle.
- **Sensor fail-safe** aborts or releases containment if the sensor's own gateway
  neighbor entry ever resolves to the sink MAC.

> **This is active emission.** It is the deliberate lift of NetWatch's former
> passive-only convention. It disrupts a device on purpose; keep dry-run on until
> you have confirmed the target and gateway are what you expect. It needs an
> elevated shell and the capture interface.

### In-dashboard panel

The **MITIGATION CONTROL** panel gains a **LAN QUARANTINE** section:

- a status line (mode · dry-run/live · bi-dir/egress · pending/active counts);
- **QUARANTINE PENDING** with **QUARANTINE / DISMISS** — ARP-spoof alerts land
  here in manual mode;
- **QUARANTINED DEVICES** with MAC, live TTL countdown, and **RELEASE**.

### Operator CLI

```powershell
python quarantine.py list
python quarantine.py hold 10.0.0.34 --gateway 10.0.0.1 --reason "rogue IoT"   # dry-run
python quarantine.py hold 10.0.0.34 --gateway 10.0.0.1 --apply                # elevated: on the wire
python quarantine.py release 10.0.0.34 --gateway 10.0.0.1 --apply
python quarantine.py reconcile --gateway 10.0.0.1 --apply                     # lift expired
```

Dry-run is the default; `--apply` transmits. The gateway defaults to the detected
`GATEWAY_IP` when omitted.

## Native source records

The **Sources** page reads persisted native protocol evidence, with an exact event-type
filter and a normalized-record/native-record drill-down. Suricata alerts, anomalies
and drops create findings; other EVE records remain evidence without generating
incidents merely because traffic exists. Native fields and provided Community ID
are retained. NetWatch does not infer an unknown asset, network zone or ruleset.

Enable `SURICATA_EVE_ENABLED` and point `SURICATA_EVE_PATH` at the sensor's JSON
output. A pattern such as `/var/log/suricata/eve*.json` also collects threaded or
timestamp-named output. Related rename-rotation files are scanned; complete records
are committed with their binary file offsets. Restart, copy-truncate/regrow and
partial-line handling use persisted file identity, generations and boundary hashes.
`SURICATA_EVE_START_AT_END=false` collects existing history by default. An explicit
initial-history skip generates a collection-gap record. Malformed or oversized
records generate visible error records; individual native records are bounded to
one MiB. SURICATA native payloads are pruned under `NATIVE_RETENTION_DAYS`,
`NATIVE_MAX_ROWS` and `NATIVE_MAX_BYTES`.

Source health distinguishes the reader heartbeat from fresh timestamped engine
statistics. Enable EVE stats output; without it engine freshness remains unverified.
`SURICATA_SOURCE_TIMEOUT_SEC` defaults to 60 seconds. Old/undated statistics, partial
writes, clock skew, increased kernel-drop counters and collection failures never
receive a fresh-engine status. System and Sources expose this state. Configure
producer retention long enough to keep rotated files until collection completes;
already deleted, unobserved files cannot be recovered. [Suricata EVE output](https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-output.html)

## Development

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
python -m pytest        # unit tests for detectors + IPC contract
ruff check .            # lint
pip-audit -r requirements.txt   # dependency vulnerability scan
```

CI runs lint, tests, and the dependency audit on every push
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Roadmap

The staged commercial-IPS architecture, rollout gates, and inline-driver boundary
are maintained in [`docs/IPS_IMPLEMENTATION.md`](docs/IPS_IMPLEMENTATION.md).

**Monitoring (deeper):**
- ✅ MAC-keyed device inventory with OUI vendor lookup and **new-device alerts**
  (engine + CLI shipped; see [Device inventory](#device-inventory))
- ✅ Per-device baselining (anomaly = deviation from learned normal; engine + CLI
  shipped, see [Baselining](#per-device-baselining))
- ✅ ARP-spoof / MITM detection (MAC↔IP rebinding; engine shipped, see
  [ARP/MITM](#arp-spoof--mitm-detection))
- ✅ DNS analytics (DGA scoring, NXDOMAIN bursts, tunneling; engine + CLI shipped,
  see [DNS](#dns-analytics))
- ✅ JA3/JA3S TLS fingerprinting from the ClientHello (engine + CLI + blocklist
  shipped, see [JA3](#ja3ja3s-tls-fingerprinting))
- ✅ Live threat-intel feed ingestion (abuse.ch / FireHOL / Spamhaus DROP; updater
  + matching shipped, see [Threat intel](#threat-intel-feeds))
- ✅ Historical query / timeline over the ledger (CLI shipped, see
  [History](#historical-query--timeline))
- ✅ IPv6 locality: delegated-prefix detection so LAN IPv6 is classified as
  local by both the detectors and the mitigation allowlist
  (see [Configuration](#configuration))
- ✅ Flow/session model (bidirectional 5-tuple, duration, state, bytes up/down)
- ✅ Beaconing / C2 periodicity detection over first-observed outbound sessions
- ✅ Explainable outbound human-web signal/noise observation filter
- ✅ Ordered per-device egress policy with monitor/manual/enforce stages
- ✅ JA4 TLS-client fingerprinting alongside JA3/JA3S
- Notification path (webhook / ntfy / toast) and incident correlation
- ✅ Coalesced bounded pre/post-event PCAP capture with asynchronous disk writes
- ✅ Optional durable Suricata native EVE ingestion, direction-aware findings and engine freshness
- WinDivert shadow/inline laboratory enforcement with fail-open watchdog
- Signed WFP callout driver for production-grade Windows inline enforcement

**Mitigation (engine + UI shipped; see [Mitigation](#mitigation)):**
- ✅ Block-on-alert via Windows Firewall with auto-expiry, allowlist, capacity
  cap, manual-approval gate, dry-run, and a persisted ledger + operator CLI
- ✅ In-dashboard approve/deny/unblock panel with live TTL countdown
- ✅ Device quarantine workflow: ARP-poison isolation of a LAN device from this
  host — enforcement that works behind a locked ISP gateway (engine + CLI +
  in-dashboard panel; see [LAN quarantine](#lan-quarantine))

## Security

See [SECURITY.md](SECURITY.md) for the privilege model and trust boundaries.

## License

MIT — see [LICENSE](LICENSE). GeoLite2 data is governed separately by MaxMind's
EULA and is not included.

## Packet evidence integrity and retention

The **Evidence** page lists retained PCAPs and their lifecycle status. Select a
capture to see its provenance, every coalesced detector trigger, and its local
audit. **Verify** checks both packet bytes and the manifest against the catalog.
Enter a reason to **Hold** evidence for an investigation or **Release hold** when
that investigation ends. Holds survive restarts and prevent automatic retention.
**Export** writes a private ZIP containing the capture, its manifest and a bounded
audit snapshot, then verifies it. Existing destination files are never replaced.
Hashing and exports run outside the GUI thread. Exports currently serialize security
ledger writers while copying; benchmark this limit before production load testing.

Capture success is reported after the PCAP and manifest are flushed and the
catalog commit succeeds. SHA-256, sensor/interface identity, packet time bounds,
observed versus saved byte counts, snap length and trigger references are recorded.
The evidence ring is bounded by time **and** memory: a configured lookback does not
promise that much history under heavy traffic. Same-AP traffic and radio frames
remain outside the current gateway mirror's visibility.

`EVIDENCE_MAX_FILES=100`, `EVIDENCE_MAX_BYTES=2147483648` and
`EVIDENCE_RETENTION_DAYS=7` bound retained packet payloads. These limits exclude the
SQLite ledger and small sidecars. Held captures and unfinished or unregistered
payloads count toward admission; they are never silently removed to make room.
When no space remains, the recorder produces a durable capture failure. Retention
records a deletion intent before removing an unheld registered capture; startup
finishes interrupted deletions and recovers completed, valid capture/manifest pairs
left before catalog commit. Incomplete or invalid artifacts remain for investigation.

The catalog shares `INCIDENT_DB` in the application. A standalone recorder uses
`catalog.db` in its evidence directory. Local hashes and local audit records do not
prove that a host administrator has not replaced both evidence and its baseline.
Off-host anchors, encryption and central backup remain deployment work.

## Passive Ethernet and IPv6 control records

`CONTROL_CAPTURE_ENABLED=true` adds native records for ARP, DHCP, DHCPv6, LLDP,
STP, EAPOL/link authentication, link aggregation and ICMP, including IPv6 router
and neighbor messages. The **Sources** page exposes the observed frame bytes,
checksum, sensor/interface, VLANs, message fields and nested DHCPv6 leases/delegated
prefixes. Scapy's installed protocol decoders run in a separate bounded worker;
the high-volume IP parser stays on the capture path. No frames are transmitted by
this collector. [Scapy protocol layers](https://scapy.readthedocs.io/en/stable/api/scapy.layers.html)

Decoded fields are previews. Large arrays, nested fields or undecoded protocols
are explicitly partial; the complete observed frame stays in the native record.
Router/neighbor checks cover hop limit, code, selected source/target requirements,
checksum, option bounds and forbidden fragment headers. They are a subset of
protocol validation; checksum offload can affect captured checksums. Findings are
review leads with Observed confidence and no containment target. [Neighbor Discovery
requirements](https://www.rfc-editor.org/rfc/rfc4861.html), [fragmentation restrictions](https://www.rfc-editor.org/rfc/rfc6980.html)

Configure `CONTROL_TRUSTED_DHCP_SERVERS` with expected advertised IPv4 server
identities, `CONTROL_TRUSTED_RA_MACS` with expected router MACs, and
`CONTROL_TRUSTED_DHCPV6_DUIDS` with expected server DUID hex strings. Empty lists
mean **unconfigured**, not that every observed server is trusted. Matching an
identity is not authentication: all of these fields can be spoofed. These policies
flag identities outside the configured lists without granting response authority.
Build that baseline from observed, reviewed RA/DHCPv6 traffic on your own network;
do not invent those identities from the Wi-Fi name.

`CONTROL_CAPTURE_MAX_PENDING=1024` bounds the pre-commit buffer. A queued frame is
not yet durable. Native records and any review finding commit together before
presentation. Storage failures retain and retry the current candidate. Overflow
creates a counted collection gap; restart after an unclean drain creates a gap
whose missing-frame count is explicitly unknown. The Sources status distinguishes
collector liveness, committed records, backlog and drops; a running collector does
not establish complete network visibility. Graceful shutdown attempts a bounded
drain. Native control payload retention runs in bounded transactions with targets
of seven receipt-time days, 200,000 records and 256 MiB of native/normalized JSON.
Configure `CONTROL_RETENTION_DAYS`, `CONTROL_MAX_ROWS`, `CONTROL_MAX_BYTES`,
`CONTROL_PRUNE_INTERVAL_SEC` and `CONTROL_PRUNE_BATCH_ROWS`; zero disables an
individual quota/age target. Sources supports attributed native-record holds and
releases. Unprocessed ARP, active binding/candidate references, collection gaps,
case-linked records and finding support remain pinned. Pruning commits a hash,
metadata tombstone and audit with deletion (SURICATA only; CONTROL ids are random
per frame, so CONTROL prunes write no tombstone and only the batch's prune audit).
Protected records can exceed the targets and degrade collection health; these are
payload targets, not a hard disk ceiling. SQLite reuses freed pages rather than
shrinking immediately. Tombstones, ordering, holds and audit remain retained;
central metadata retention and production flood/load validation remain pending.

ARP analytics now replay durable native records instead of a lossy claim queue.
An analysis failure rolls back the batch and exposes degraded replay health.
Historical replay uses the original observation time for evidence requests; it
cannot recover packets missing from the capture ring. Existing native rows receive
a stable receipt-time backfill because their original commit order was not recorded. Switch port state, RF traffic,
same-AP traffic, MAC movement, router/neighbor binding correlation and complete
prefix-lifecycle detections require further collection or analysis. The gateway
mirror only supplies frames that actually cross its capture point.


## Headless monitoring service

Capture and analytics workers now live in `netwatch_workers.py`, which imports no
Qt or OpenGL. The desktop and headless entry points share spawn-based process
orchestration. Run the service using the existing Python environment:

```sh
python -m netwatch_service --base-dir /absolute/path/to/runtime-data
```

A new service environment can install `requirements-headless.txt`; its pinned
dependencies exclude Qt and OpenGL. Capture still requires host capture privileges
and Npcap/libpcap.

The directory uses the same configuration overlays and resource-path rules as the
desktop. Start with the desktop profile stopped; a process-lifetime ledger lock
prevents both profiles from collecting into the same runtime concurrently.
Interrupt or terminate the service for bounded shutdown. On the Windows sensor it runs as the
boot task `NetWatchService`; an ordered stop is the file
`C:\ProgramData\NetWatch\netwatch.stop`. The task runs at normal priority
(`Settings.Priority` 4); the scheduler default of 7 is below normal and starves capture under load.

The supervisor replaces a crashed or stalled worker generation with fresh queues,
records a collection-gap incident for potentially missing queued telemetry, and
retries with bounded backoff. Ordered shutdown pauses acquisition and drains
analytics and persistence before closing capture/evidence, so late evidence
requests still have a consumer. Sticky pipe signals avoid shared waiter locks
left by killed workers; forced or unverified drains produce durable gaps.
Accepted detections, native frames and ARP replay
state survive independently of the console. Driver measurements remain separately
unverified until observed. Service response requests (`block_ip`, `quarantine_mac`)
are durable action rows driven by the response mode (`ids_only`, `ready`,
`autonomous`); undecided requests expire as denied. The only wired effector records
the intent and does not enforce, so readback stays unverified. The existing local
GUI response profile is still available when the service is stopped.

The JSON API is bearer-authenticated on loopback (`127.0.0.1:8765`) with a 5 s
whole-request deadline; on Windows `service-api.secret` is restricted with `icacls`.
A separate console host reaches it through an SSH-tunnelled gateway. Central
API/storage (PostgreSQL) was removed. Windows load, soak and live enforcement
remain unverified.
