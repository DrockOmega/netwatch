"""The shard hot path's outputs are pinned: speed work on it must not change one record.

A fixed seeded stream (the bench's elephant upload, then its mixed home LAN) runs through the real
``dod_core_process`` as shard 0. Everything it emits is canonicalised and hashed: every SHARD_BATCH
record the merge analyses (detector inputs, policy, beacon, DNS, JA3, intel and signature items),
every render row and web observation, and the ledger rows (recompacted as one batch, since the
one-second DB flush cuts batches by wall clock). The digest was taken from the code before the
2026-10-17 hot-path work; update it only for an intended output change.
"""

import hashlib
import json

from netwatch_core import is_message_payload
from netwatch_db import compact_event_rows
from tools.bench_core_shard import elephant, mixed, run_shard

POLICY = {"version": 1, "default_action": "allow", "rules": [
    {"id": "lan-dns", "action": "alert", "direction": "lateral", "protocol": "UDP", "destination_ports": [53]},
    {"id": "rdp-out", "action": "block", "direction": "egress", "destination_ports": [3389]},
    {"id": "udp-in", "action": "alert", "direction": "ingress", "protocol": "UDP"},
    {"id": "web-out", "action": "alert", "direction": "egress", "destination_ports": [443]},
]}
EXPECTED = "df456ee425432dc5d52e3e379a7dca21ac64c83d857e08a5d4a5977210adacf6"  # b936: events carry payload_bytes; beacon samples wait for payload


def _scrub(value):
    """Embedded messages (policy responses) carry a random correlation id."""
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if not (k == "correlation_id" and is_message_payload(value))}
    if isinstance(value, list | tuple):
        return type(value)(_scrub(v) for v in value)
    return value


def _canonical(outputs):
    merge = [(m["action"], m["target_id"], _scrub(m["data"])) for m in outputs["merge"]]
    render = []
    for message in outputs["render"]:
        data = dict(message["data"])
        data["events"] = [{k: v for k, v in event.items() if k != "time_str"} for event in data["events"]]
        data["observations"] = [{k: v for k, v in event.items() if k != "time_str"} for event in data["observations"]]
        render.append((message["correlation_id"], data))  # time_str is local time: the host's zone
    rows = compact_event_rows([row for m in outputs["db"] for row in m["data"]["rows"]])
    observations = [obs for m in outputs["db"] for obs in m["data"]["observations"]]
    return merge, render, rows, observations


def test_shard_outputs_match_the_pinned_digest(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps(POLICY))
    events = elephant(3000) + mixed(6000, t0=1_800_000_010.0)
    outputs, _, _ = run_shard(events, tmp_path, POLICY_FILE=str(tmp_path / "policy.json"), POLICY_MODE="manual")
    merge, render, rows, observations = _canonical(outputs)
    assert sum(len(m[2]["records"]) for m in merge if m[0] == "SHARD_BATCH") == len(events)
    assert sum(len(r[1]["events"]) for r in render) == len(events)
    assert sum(row[13] for row in rows) == len(events)
    assert any(m[0] == "SHARD_BATCH" and any(r[-1] for r in m[2]["records"]) for m in merge)  # analyser items present
    assert observations
    digest = hashlib.sha256(repr((merge, render, rows, observations)).encode()).hexdigest()
    assert digest == EXPECTED, digest


def test_headless_shard_sends_no_render_rows_and_the_same_analysis(tmp_path):
    """``_RENDER_ROWS`` False (the headless service) drops only the render queue: every merge record,
    ledger row and web observation is what the rendering shard emits."""
    (tmp_path / "policy.json").write_text(json.dumps(POLICY))
    events = elephant(3000) + mixed(6000, t0=1_800_000_010.0)
    runs = []
    for render_rows in (True, False):
        (tmp_path / str(render_rows)).mkdir()
        outputs, _, _ = run_shard(events, tmp_path / str(render_rows), POLICY_FILE=str(tmp_path / "policy.json"),
                                  POLICY_MODE="manual", _RENDER_ROWS=render_rows)
        runs.append(_canonical(outputs))
    (merge, render, rows, observations), (merge2, render2, rows2, observations2) = runs
    assert render and not render2
    assert (merge, rows, observations) == (merge2, rows2, observations2)


def test_shard_reports_a_rate_when_the_cpu_clock_does_not_tick(tmp_path, monkeypatch):
    """A coarse thread CPU clock can measure zero elapsed for a tiny shard (b232)."""
    monkeypatch.setattr("tools.bench_core_shard.time.thread_time", lambda: 1.0)
    _, rate, _ = run_shard(mixed(3), tmp_path)
    assert rate == float("inf")
