"""Single-host burst through real processes: capture stand-in -> CORE_SHARDS shards -> merge.

The stand-in parses the bench's elephant frames (one LAN device uploading, as a nightly off-site backup) as fast as the shards accept them, splits each 512-event chunk with ``shard_chunk`` and holds
like ``io_sniffer_process``. Shards and merge are the real ``dod_core_process`` on spawned processes
and bounded queues sized as ``MonitoringRuntime`` sizes them. Reports events per second delivered and
each process's CPU share: the stage at ~100% with a full input queue is the ceiling.

``--render`` keeps render rows (drained 256 per 0.2 s, as the headless service did) and ``--narrow``
keeps the default 64 KiB pipes: both together are the pipeline before 2026-10-19.

    .venv/bin/python tools/bench_pipeline.py [seconds] [--render] [--narrow]
"""

import argparse
import multiprocessing as mp
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tools")]

SHARDS, CHUNK, HOLD = 4, 512, 64  # CORE_SHARDS on the sensor, INGEST_BATCH_MAX, INGEST_HOLD_BATCHES


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def core(role, ingest, render, out, policy, db, evidence, status, inventory, stop, workdir, render_rows):
    import bench_core_shard

    import netwatch_workers

    config = bench_core_shard.shard_config(workdir, CORE_SHARDS=SHARDS, _CORE_SHARD=role, _RENDER_ROWS=render_rows)
    netwatch_workers.dod_core_process(ingest, render, out, policy, db, evidence, config, status, inventory, stop)


def capture(ingest, stop, delivered):
    import bench_core_shard as bench

    import netwatch_workers
    from netwatch_capture import parse_ethernet_frame
    from netwatch_core import compile_v4_prefixes, compile_v6_prefixes, try_put_no_drop
    from netwatch_ja3 import fingerprint

    keep, bench._event = bench._event, lambda frame, stamp: frame
    frames = bench.elephant(60_000)
    bench._event = keep
    prefixes = (compile_v4_prefixes(("192.168.1.0/24",)), compile_v6_prefixes(bench.LOCAL_PREFIXES6), {})
    n, seq, pending, head = 0, 0, [], []
    while not stop.is_set():
        if len(pending) < HOLD * CHUNK:
            for _ in range(256):  # one PCAP_DRAIN_BATCH; stamps advance at 75k packets/s
                _, data = parse_ethernet_frame(frames[n % len(frames)], 1_800_000_000.0 + n / 75_000, fingerprint)
                data["sensor_id"], data["interface"] = "bench", "eq0"
                data.pop("control_payload", None)
                pending.append(data)
                n += 1
        while len(pending) >= CHUNK:
            if not head:
                seq += 1
                head = list(zip(ingest, netwatch_workers.shard_chunk(pending[:CHUNK], SHARDS, *prefixes, seq),
                                strict=True))
            while head and try_put_no_drop(*head[0]):
                del head[0]
            if head:
                if len(pending) >= HOLD * CHUNK:
                    time.sleep(0.01)  # held: capture reads paused
                break
            del pending[:CHUNK]
            delivered.value += CHUNK


def drain(queues, stop, render_paced):
    while not stop.is_set():
        for name, q in queues.items():
            for _ in range(256 if render_paced and name == "render" else 100_000):
                try:
                    q.get_nowait()
                except queue.Empty:
                    break
        time.sleep(0.2 if render_paced else 0.01)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("seconds", type=float, nargs="?", default=15.0)
    parser.add_argument("--render", action="store_true", help="shards send render rows (the old headless path)")
    parser.add_argument("--narrow", action="store_true", help="keep 64 KiB queue pipes")
    args = parser.parse_args()
    from netwatch_runtime import INGESTION_QUEUE_BATCHES, widen_pipe

    ctx = mp.get_context("spawn")
    ingest = [ctx.Queue(INGESTION_QUEUE_BATCHES) for _ in range(SHARDS)]
    merge = [ctx.Queue(INGESTION_QUEUE_BATCHES) for _ in range(SHARDS)]
    if not args.narrow:
        for q in ingest + merge:
            widen_pipe(q)
    render, db, alert, policy, status, evidence, inventory = (ctx.Queue(n) for n in (1000, 128, 500, 500, 100, 100, 1))
    stops = [ctx.Event() for _ in range(SHARDS + 2)]
    delivered = ctx.Value("q", 0, lock=False)
    workdir = tempfile.mkdtemp(prefix="bench-pipeline-")
    for name in [*map(str, range(SHARDS)), "merge"]:
        os.mkdir(f"{workdir}/{name}")
    workers = {f"core-{i}": ctx.Process(target=core, args=(i, ingest[i], render, merge[i], None, db, None, status, None,
                                                            stops[i], f"{workdir}/{i}", args.render))
               for i in range(SHARDS)}
    workers["merge"] = ctx.Process(target=core, args=("merge", tuple(merge), render, alert, policy, db, evidence, status,
                                                      inventory, stops[SHARDS], f"{workdir}/merge", args.render))
    workers["capture"] = ctx.Process(target=capture, args=(ingest, stops[-1], delivered))
    done = threading.Event()
    threading.Thread(target=drain, args=({"render": render}, done, True), daemon=True).start()
    threading.Thread(target=drain, args=({"db": db, "alert": alert, "policy": policy, "status": status,
                                          "evidence": evidence, "inventory": inventory}, done, False), daemon=True).start()
    for name, worker in workers.items():
        worker.start()
        if name == "merge":
            time.sleep(3)  # cores load rules before the burst
    time.sleep(5)  # warm-up
    before, events, start = {k: cpu_seconds(w.pid) for k, w in workers.items()}, delivered.value, time.monotonic()
    time.sleep(args.seconds)
    after, span = {k: cpu_seconds(w.pid) for k, w in workers.items()}, time.monotonic() - start
    rate = (delivered.value - events) / span
    print(f"single-host burst ({'render' if args.render else 'no render'}, {'64 KiB' if args.narrow else 'wide'} "
          f"pipes): {rate:,.0f} events/s; cpu% " + " ".join(f"{k}={100 * (after[k] - before[k]) / span:.0f}"
                                                         for k in workers))
    stops[-1].set()
    workers["capture"].join(10)
    for stop in stops[:SHARDS]:
        stop.set()
    time.sleep(2)
    stops[SHARDS].set()
    for worker in workers.values():
        worker.join(15)
        if worker.is_alive():
            worker.kill()
    done.set()
    shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
