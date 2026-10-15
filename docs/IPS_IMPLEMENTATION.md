# NetWatch IPS implementation plan

## Architectural position

NetWatch separates the packet fast path from its policy and operator control
planes. The Python application remains a sensor, correlation engine, response
orchestrator, and UI. Inline packet disposition belongs behind an explicit
enforcement adapter so monitoring failures cannot silently become network
outages.

## Delivery stages

| Stage | Capability | Enforcement boundary | Acceptance gate | Status |
|---|---|---|---|---|
| 1 | Bidirectional flow/session model, beaconing, JA4, ordered policy, durable decision audit, capture-on-alert | Existing reversible Windows Firewall and LAN quarantine | Unit tests, policy monitor mode, bounded storage, no packet-path regression | Implemented |
| 2 | Suricata signatures, stream reassembly, application parsers, file metadata through EVE JSON | Suricata sensor or inline bridge | EVE replay corpus, rule provenance, alert deduplication, sensor health | Adapter implemented; sensor deployment optional |
| 3 | Windows inline laboratory mode | WinDivert user-mode drop/reinject adapter | Shadow-versus-inline verdict parity, watchdog fail-open, latency and loss budgets | Planned |
| 4 | Production Windows inline mode | Signed WFP callout driver plus least-privileged policy service | Driver signing, crash isolation, bypass policy, soak/load/fuzz testing | Planned |
| 5 | Distributed commercial control plane | Multiple sensors with signed policy bundles and HA | RBAC, immutable audit, policy rollout/rollback, sensor failover | Planned |

## Implemented control-plane contract

- `netwatch_flow.py` owns bounded five-tuple sessions, bidirectional counters,
  TCP lifecycle, and low-jitter beacon detection.
- `netwatch_policy.py` owns versioned first-match rules, CIDR/device/domain/port
  selectors, expiring exceptions, monitor/manual/enforce stages, a policy
  digest, and a rotating decision ledger. Late identity, direction transitions,
  and policy reloads invalidate prior verdicts; unverified MACs cannot grant allow.
- `netwatch_evidence.py` owns the bounded raw-frame ring and pre/post-trigger
  PCAP evidence files through coalesced bounded jobs and an asynchronous writer.
- `netwatch_suricata.py` converts Suricata alert, anomaly, and drop EVE records
  into the existing IPC and incident model.
- `netwatch_ja3.py` now emits the open JA4 TLS-client fingerprint alongside JA3.
- The Enforcement view exposes active policy mode and recent decisions.
- Security-control commands use a dedicated non-evicting queue separate from
  lossy presentation telemetry; lateral policy blocks route to LAN quarantine.

## Policy rollout

1. Add or enable rules in `policy_rules.json` with `POLICY_MODE=monitor`.
2. Replay representative traffic and inspect `telemetry_policy_decisions.jsonl`
   plus generated evidence PCAPs.
3. Set `POLICY_MODE=manual` and enable mitigation to validate approval routing.
4. Set `POLICY_MODE=enforce` only for rules whose targets, exceptions, and
   rollback behavior passed replay and dry-run review.
5. Keep the default action `allow` until an inline enforcement point has
   deterministic health, bypass, and latency behavior.

## Remaining inline requirements

- A WinDivert prototype must expose one explicit shadow/monitor/enforce state
  machine and automatically bypass when its policy service or watchdog fails.
- A WFP implementation must move packet verdicts into a signed callout driver;
  the GUI must never sit in the kernel decision loop.
- TCP reassembly, IP normalization, application parsing, signature evaluation,
  and file metadata should come from Suricata rather than bespoke Python.
- Every ruleset update requires provenance, validation, staged activation,
  atomic rollback, and replay against a retained benign/malicious corpus.
- Production readiness requires measured throughput, p50/p95/p99 latency,
  overload semantics, crash recovery, tamper-evident audit, and HA behavior.
