"""CORE_SHARDS parity: shard processes plus the merge must detect exactly what the single core does.

The same parsed packet stream (``packet_mix.pcap.gz`` with its detector tail, ``replay.pcap``, and an
external scan and flood spread over 40 LAN devices) runs through the real ``dod_core_process`` once as
the single core and once as four shards and the merge, split by the sniffer's own ``shard_chunk``.
Detections, ledger totals, web observations, policy output, evidence requests and every analytics ledger
must match as multisets; only ids (event, correlation, flow) and the render row's arena alert flag may differ.
"""

import json
import logging
import queue
import threading
import time
from collections import Counter

import netwatch_workers
from netwatch_capture import parse_ethernet_frame
from netwatch_core import compile_v4_prefixes, compile_v6_prefixes, core_shard, ip_pack, make_message
from netwatch_ja3 import fingerprint as ja3_fingerprint
from tests.test_capture import ipv4, tcp, udp
from tests.test_core_publish import worker_config
from tests.test_packet_path_equivalence import GW_MAC, _canonical, _drain, _eth, frames
from tests.test_replay import FIXTURE, read_pcap

SCANNER, FLOODER = "198.51.100.200", "198.51.100.201"
SHARDS = 4


def _spread_attack(t):
    """Two ports and four UDP packets per device: no single device sees a scan or a flood."""
    out = []
    for n in range(40):
        ip, mac = f"192.168.1.{100 + n}", bytes.fromhex(f"02cc0000{n:04x}")
        for k in range(2):
            out.append((t + n * 0.005 + k * 0.001, _eth(ipv4(tcp(sport=51000, dport=2000 + 2 * n + k, flags=0x02),
                                                             6, SCANNER, ip), src=GW_MAC, dst=mac)))
        for k in range(4):
            out.append((t + 1 + n * 0.005 + k * 0.001, _eth(ipv4(udp(b"x" * 32, 41000, 7000 + n), 17, FLOODER, ip),
                                                            src=GW_MAC, dst=mac)))
    return sorted(out, key=lambda item: item[0])


def _events():
    records = frames()
    t = records[-1][0] + 10
    replay = read_pcap(FIXTURE.read_bytes())
    records += [(t + stamp - replay[0][0], frame) for stamp, frame in replay]
    records += _spread_attack(t + 20)
    events = []
    for stamp, frame in records:  # exactly what process_frame ships to the core
        result = parse_ethernet_frame(frame, stamp, ja3_fingerprint)
        if result is None or result[0] != "packet":
            continue
        data = result[1]
        data["sensor_id"], data["interface"] = "parity", "eq0"
        data.pop("control_payload", None)
        events.append(data)
    return events


POLICY = {"version": 1, "default_action": "allow", "rules": [  # one rule per flow direction, one that blocks
    {"id": "lan-dns", "action": "alert", "direction": "lateral", "protocol": "UDP", "destination_ports": [53]},
    {"id": "rdp-out", "action": "block", "direction": "egress", "destination_ports": [3389]},
    {"id": "udp-in", "action": "alert", "direction": "ingress", "protocol": "UDP"},
    {"id": "web-out", "action": "alert", "direction": "egress", "destination_ports": [443]},
]}


def _run(tmp_path, shards):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "policy.json").write_text(json.dumps(POLICY))
    config = dict(worker_config(tmp_path), GC_INTERVAL_SEC=10**9, DEVICE_SAVE_INTERVAL_SEC=10**9,
                  BASELINE_WINDOW_SEC=0, EXFIL_THRESHOLD_BYTES=300_000, UDP_FLOOD_THRESHOLD=100,
                  SENSOR_ID="parity", CORE_SHARDS=shards, LOCAL_PREFIXES=("192.168.1.0/24",),
                  POLICY_FILE=str(tmp_path / "policy.json"), POLICY_MODE="manual")
    qs = {name: queue.Queue() for name in ("render", "alert", "policy", "db", "evidence", "status", "inventory")}
    ingest = [queue.Queue() for _ in range(shards)]
    merge = [queue.Queue() for _ in range(shards)]
    started = []

    def counted(q):
        real_get = q.get

        def get(*args, **kwargs):
            if q not in started:
                started.append(q)
            return real_get(*args, **kwargs)
        q.get = get
        return q

    def worker(*args):
        return threading.Thread(target=netwatch_workers.dod_core_process, daemon=True, args=args)

    shard_threads, shard_stops = [], []
    if shards == 1:
        core_stop = threading.Event()
        core = worker(counted(ingest[0]), qs["render"], qs["alert"], qs["policy"], qs["db"], qs["evidence"], config,
                      qs["status"], qs["inventory"], core_stop)
    else:
        for index in range(shards):
            shard_stops.append(threading.Event())
            shard_threads.append(worker(counted(ingest[index]), qs["render"], merge[index], None, qs["db"], None,
                                        dict(config, _CORE_SHARD=index), qs["status"], None, shard_stops[-1]))
        core_stop = threading.Event()
        core = worker(tuple(merge), None, qs["alert"], qs["policy"], None, qs["evidence"],
                      dict(config, _CORE_SHARD="merge"), qs["status"], qs["inventory"], core_stop)
    for thread in (*shard_threads, core):
        thread.start()
    deadline = time.time() + 20
    while len(started) < shards and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)  # every signature loader has read its file before the first packet

    events = _events()
    prefixes = compile_v4_prefixes(config["LOCAL_PREFIXES"]), compile_v6_prefixes(()), {}  # as the sniffer holds them
    for start in range(0, len(events), 512):
        chunk = events[start:start + 512]
        if shards == 1:
            ingest[0].put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": chunk}))
        else:
            parts = netwatch_workers.shard_chunk(chunk, shards, *prefixes, start // 512 + 1)
            for q, message in zip(ingest, parts, strict=True):
                q.put(message)
    deadline = time.time() + 60
    while time.time() < deadline and not all(q.empty() for q in (*ingest, *merge)):
        time.sleep(0.05)
    time.sleep(1.5)  # one more DB commit tick after the last batch
    for stop in shard_stops:  # the runtime's order: shards drain into the merge, then the merge stops
        stop.set()
    for thread in shard_threads:
        thread.join(20)
    core_stop.set()
    core.join(20)
    assert not any(thread.is_alive() for thread in (*shard_threads, core))
    return config, qs, events


def _without(value, *keys):
    return {k: v for k, v in value.items() if k not in keys}


def _multiset(items):
    return Counter(json.dumps(_canonical(item), sort_keys=True) for item in items)


def _outputs(tmp_path, shards):
    config, qs, events = _run(tmp_path, shards)
    render, observations = [], []
    for message in _drain(qs["render"]):
        for event in message["data"]["events"]:
            observation = event["web_observation"]
            render.append(dict(_without(event, "event_id", "flow_id", "time_str", "alert"),
                               web_observation=observation and _without(observation, "flow_id")))
        observations.extend(_without(event, "event_id", "flow_id", "time_str", "alert", "web_observation")
                            for event in message["data"]["observations"])
    ledger, db_observations = {}, []
    for message in _drain(qs["db"]):
        for row in message["data"]["rows"]:  # DB batch boundaries follow the wall clock: per-key totals
            key = json.dumps(_canonical([int(row[1]), *row[2:8], row[9], row[11], row[12], *row[14:]]))
            flags, size, count = ledger.get(key, ("", 0, 0))
            ledger[key] = ("".join(sorted(set(flags + row[8]))), size + row[10], count + row[13])
        db_observations.extend(row[1:] for row in message["data"]["observations"])

    def ledger_file(name):
        path = config[name]
        with open(path, encoding="utf-8") as f:
            return json.load(f) if not path.endswith(".jsonl") else [json.loads(line) for line in f]

    baseline = ledger_file("BASELINE_LEDGER")
    return {
        "events": len(events),
        "alerts": _multiset([m["action"], m["source"], m["target_id"], _without(m["data"], "flow_id")]
                            for m in _drain(qs["alert"])),
        "policy": _multiset([m["target_id"], _without(m["data"], "flow_id")] for m in _drain(qs["policy"])),
        "evidence": _multiset([m["data"]["action"], m["data"]["message"], m["data"]["source"]]
                              for m in _drain(qs["evidence"])),
        "render": _multiset(render),
        "observations": _multiset(observations),
        "db_observations": _multiset(db_observations),
        "ledger": sorted(ledger.items()),
        "devices": ledger_file("DEVICE_LEDGER"),
        "dns": ledger_file("DNS_LEDGER"),
        "ja3": ledger_file("JA3_LEDGER"),
        "baseline": {k: v for k, v in baseline.items() if k != "last_seen"},
        "decisions": _multiset(_without(d, "flow_id") for d in ledger_file("POLICY_DECISION_LEDGER")),
    }


def test_spread_attack_needs_the_merge():
    prefixes = compile_v4_prefixes(("192.168.1.0/24",)), compile_v6_prefixes(())
    per_shard = {}
    for stamp, frame in _spread_attack(0.0)[:80]:
        event = parse_ethernet_frame(frame, stamp, ja3_fingerprint)[1]
        per_shard.setdefault(core_shard(event, SHARDS, *prefixes), set()).add(event["port"])
    assert len(per_shard) == SHARDS  # the scan reaches every shard...
    assert max(map(len, per_shard.values())) < 50  # ...and none sees SWEEP_THRESHOLD_PORTS on its own


def test_sharded_core_matches_single_core(tmp_path):
    single = _outputs(tmp_path / "single", 1)
    sharded = _outputs(tmp_path / "sharded", SHARDS)
    alerts = [json.loads(alert) for alert in single["alerts"]]
    scans = {(a[3]["message"].split(":")[0], a[2]["$bytes"]) for a in alerts if a[0] == "ALERT"
             and isinstance(a[2], dict)}
    assert ("PORT SCAN ALERT", ip_pack(SCANNER).hex()) in scans and ("UDP FLOOD ALERT", ip_pack(FLOODER).hex()) in scans
    assert {a[0] for a in alerts} >= {"ALERT", "BEACON_ANOMALY", "DNS_ANOMALY", "DEVICE_NEW", "POLICY_DECISION"}
    assert sum(a[0] == "DEVICE_NEW" for a in alerts) == 20  # the flood guard caps notices sensor-wide
    assert single["devices"]["devices"] and single["observations"] and single["decisions"] and single["policy"]
    for key in single:
        assert sharded[key] == single[key], key


def test_merge_fails_the_generation_when_shard_batches_fall_out_of_step(tmp_path):
    config = dict(worker_config(tmp_path), CORE_SHARDS=2, _CORE_SHARD="merge")
    merge = [queue.Queue(), queue.Queue()]
    for q, chunks in zip(merge, ((1, 2), (1, 3)), strict=True):  # shard 1 lost chunk 2's part
        for chunk in chunks:
            q.put(make_message("DOD_CORE", "SHARD_BATCH", "DOD_CORE", {"records": [], "seq": chunk}))
    qs = {name: queue.Queue() for name in ("alert", "policy", "evidence", "status", "inventory")}
    stop = threading.Event()
    try:
        netwatch_workers.dod_core_process(tuple(merge), None, qs["alert"], qs["policy"], None, qs["evidence"],
                                          config, qs["status"], qs["inventory"], stop)
    except SystemExit as exc:
        assert exc.code == 1  # the supervisor replaces the generation and files the gap, as for a dead shard
    else:
        raise AssertionError("the merge mixed chunks 2 and 3")
    finally:
        stop.set()


def test_shard_logs_stalled_merge_without_dropping(tmp_path, monkeypatch):
    monkeypatch.setattr(netwatch_workers, "MERGE_STALL_WARN_SEC", 1)
    warnings = []  # the component logger does not propagate to caplog, and its file may be another test's
    handler = logging.Handler(logging.WARNING)
    handler.emit = lambda record: warnings.append(record.getMessage())
    logging.getLogger("netwatch.core-1").addHandler(handler)
    config = dict(worker_config(tmp_path), CORE_SHARDS=2, LOCAL_PREFIXES=("192.168.1.0/24",))
    ingest, merge, stop = queue.Queue(), queue.Queue(maxsize=1), threading.Event()
    merge.put(make_message("DOD_CORE", "SHARD_METRICS", "DOD_CORE", {}))  # a merge that has stopped reading
    qs = {name: queue.Queue() for name in ("render", "db", "status")}
    shard = threading.Thread(target=netwatch_workers.dod_core_process, daemon=True,
                             args=(ingest, qs["render"], merge, None, qs["db"], None, dict(config, _CORE_SHARD=1),
                                   qs["status"], None, stop))
    shard.start()
    prefixes = compile_v4_prefixes(config["LOCAL_PREFIXES"]), compile_v6_prefixes(()), {}
    ingest.put(netwatch_workers.shard_chunk(_events()[:20], 2, *prefixes, 1)[1])
    deadline = time.time() + 10
    while time.time() < deadline and not any("merge not reading" in m for m in warnings):
        time.sleep(0.05)
    assert any("merge not reading" in m for m in warnings) and shard.is_alive()
    merge.get()  # the merge reads again: the held batch arrives whole
    batch = merge.get(timeout=5)
    stop.set()
    shard.join(20)
    logging.getLogger("netwatch.core-1").removeHandler(handler)
    assert batch["action"] == "SHARD_BATCH" and batch["data"]["seq"] == 1


def test_new_endpoint_never_evicts_the_other_endpoint_of_its_own_event(tmp_path):
    from tests.test_capture import ethernet

    faults = []  # the component logger does not propagate to caplog
    handler = logging.Handler(logging.ERROR)
    handler.emit = lambda record: faults.append(record.getMessage())
    logging.getLogger("netwatch.core").addHandler(handler)
    config = dict(worker_config(tmp_path), CORE_SHARDS=1, MAX_ENTITIES=4, LOCAL_PREFIXES=("192.168.1.0/24",))
    # A, X1, B, C fill the arena; then A (present, least recently used) talks to new X2: X2's slot
    # must not be A's, or A's own lookup in that event fails.
    pairs = (("192.168.1.10", "8.8.8.1"), ("192.168.1.11", "8.8.8.1"), ("192.168.1.12", "8.8.8.1"),
             ("192.168.1.10", "8.8.8.2"))
    events = []
    for stamp, (src, dst) in enumerate(pairs, start=1):
        data = parse_ethernet_frame(ethernet(ipv4(tcp(b"x", dport=443), 6, src=src, dst=dst)), float(stamp))[1]
        data["sensor_id"], data["interface"] = "parity", "eq0"
        events.append(data)
    qs = {name: queue.Queue() for name in ("render", "alert", "policy", "db", "evidence", "status", "inventory")}
    ingest, stop = queue.Queue(), threading.Event()
    core = threading.Thread(target=netwatch_workers.dod_core_process, daemon=True,
                            args=(ingest, qs["render"], qs["alert"], qs["policy"], qs["db"], qs["evidence"], config,
                                  qs["status"], qs["inventory"], stop))
    core.start()
    for event in events:
        ingest.put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": [event]}))
    deadline = time.time() + 10
    while time.time() < deadline and not ingest.empty():
        time.sleep(0.05)
    time.sleep(0.5)
    stop.set()
    core.join(20)
    logging.getLogger("netwatch.core").removeHandler(handler)
    assert not [m for m in faults if "event fault" in m]
