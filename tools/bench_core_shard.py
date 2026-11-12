"""Benchmark one analytics shard's per-event path: ``dod_core_process`` as ``_CORE_SHARD=0``.

Feeds parser-shaped events (``parse_ethernet_frame`` output, as ``process_frame`` ships them) in
512-event INGEST_PACKET parts, through queues that pickle on put and unpickle on get the way the
process queues do, and reports events per CPU-second of the shard thread (startup excluded).

Workloads: ``elephant`` is one LAN device in five TCP/443 flows to one global IPv6 address at
30k packets/s (a nightly off-site backup); ``mixed`` is a home LAN of 24 devices.

    .venv/bin/python tools/bench_core_shard.py elephant 60000 [--profile]
"""

import argparse
import cProfile
import ipaddress
import json
import os
import pickle
import pstats
import queue
import random
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import netwatch_workers  # noqa: E402
from netwatch_capture import parse_ethernet_frame  # noqa: E402
from netwatch_config import DEFAULTS, PATH_KEYS  # noqa: E402
from netwatch_core import make_message  # noqa: E402
from netwatch_ja3 import fingerprint  # noqa: E402

CHUNK = 512
HOST_MAC, GW_MAC = bytes.fromhex("02aa00000001"), bytes.fromhex("02aa000000fe")
HOST6, GOOGLE6 = "2601:db8:1::10", "2607:f8b0:4004:c1b::5f"
LOCAL_PREFIXES6 = ("2601:db8:1::/64",)


def _eth(payload, src, dst, ether_type=0x0800):
    return dst + src + struct.pack("!H", ether_type) + payload


def _ip4(payload, proto, src, dst, ttl=64):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0,
                       ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + payload


def _ip6(payload, proto, src, dst, hops=64):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, hops,
                       ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed) + payload


def _tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 0, 0, 0) + payload


def _udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns(name, response=False):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 7, 0x8180 if response else 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def _event(frame, stamp):
    kind, data = parse_ethernet_frame(frame, stamp, fingerprint)
    assert kind == "packet"
    data["sensor_id"], data["interface"] = "bench", "eq0"
    data.pop("control_payload", None)
    return data


def elephant(count, seed=7, t0=1_800_000_000.0, pps=30_000):
    """Five upload flows, two data segments out per ACK in; handshakes first."""
    rng, out = random.Random(seed), []
    ports = range(50001, 50006)
    for n, port in enumerate(ports):
        out.append(_event(_eth(_ip6(_tcp(port, 443, 0x02), 6, HOST6, GOOGLE6), HOST_MAC, GW_MAC, 0x86DD), t0 + n * 1e-4))
        out.append(_event(_eth(_ip6(_tcp(443, port, 0x12), 6, GOOGLE6, HOST6, 120), GW_MAC, HOST_MAC, 0x86DD),
                          t0 + n * 1e-4 + 5e-5))
    data = _tcp(0, 443, 0x18, b"\x17" * 1420)
    for i in range(len(out), count):
        port, stamp = rng.choice(ports), t0 + 0.001 + i / pps
        if i % 3:
            frame = _eth(_ip6(_tcp(port, 443, 0x18) + data[20:], 6, HOST6, GOOGLE6), HOST_MAC, GW_MAC, 0x86DD)
        else:
            frame = _eth(_ip6(_tcp(443, port, 0x10), 6, GOOGLE6, HOST6, 120), GW_MAC, HOST_MAC, 0x86DD)
        out.append(_event(frame, stamp))
    return out


def mixed(count, seed=11, t0=1_800_000_000.0, pps=5_000):
    """24 devices over a pool of live sessions: HTTPS both ways, QUIC, LAN casting, IPv6; one-packet DNS and probes."""
    rng, out, sessions = random.Random(seed), [], []
    devices = [(f"192.168.1.{20 + n}", bytes.fromhex(f"02bb0000{n:04x}"), f"2601:db8:1::{0x20 + n:x}") for n in range(24)]
    remotes = [f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(150)] + ["203.0.113.9"]
    remotes6 = [f"2606:4700:{rng.randint(1, 0xffff):x}::{rng.randint(1, 0xffff):x}" for _ in range(40)]
    names = ["www.example.com", "api.github.com", "telemetry.data.nvidia.com", "update.roku.com", "news.ycombinator.com",
             "x7fq2kz9.biz", "time.google.com", "ring.amazon.dev", "cdn.evil.example"]
    for i in range(count):
        stamp, roll = t0 + i / pps, rng.random()
        if roll < 0.10:  # DNS: a query or its answer, a fresh source port each time
            ip, mac, _ = rng.choice(devices)
            sport, name = rng.randint(40000, 60000), rng.choice(names)
            frame = (_eth(_ip4(_udp(sport, 53, _dns(name)), 17, ip, "192.168.1.1"), mac, GW_MAC) if roll < 0.06 else
                     _eth(_ip4(_udp(53, sport, _dns(name, True)), 17, "192.168.1.1", ip), GW_MAC, mac))
        elif roll < 0.12:  # a probe to an odd port
            ip, mac, _ = rng.choice(devices)
            frame = _eth(_ip4(_tcp(rng.randint(40000, 60000), rng.choice((22, 3389, 8080, 23)), 0x02), 6, ip,
                              rng.choice(remotes)), mac, GW_MAC)
        else:
            if len(sessions) < 300 or rng.random() < 0.03:
                ip, mac, ip6 = rng.choice(devices)
                session = (rng.choice(("tcp", "tcp", "tcp", "quic", "lan", "v6")), ip, mac, ip6, rng.randint(40000, 60000),
                           rng.choice(remotes), rng.choice(remotes6), rng.choice(devices))
                if len(sessions) < 300:
                    sessions.append(session)
                else:
                    sessions[rng.randrange(300)] = session
            kind, ip, mac, ip6, sport, remote, remote6, peer = rng.choice(sessions)
            outbound = rng.random() < 0.55
            if kind == "tcp":
                frame = (_eth(_ip4(_tcp(sport, 443, rng.choice((0x10, 0x18, 0x18))), 6, ip, remote), mac, GW_MAC) if outbound
                         else _eth(_ip4(_tcp(443, sport, rng.choice((0x10, 0x18)), b"d" * 1200), 6, remote, ip, 52), GW_MAC, mac))
            elif kind == "quic":
                frame = (_eth(_ip4(_udp(sport, 443, b"\x40" * rng.randint(30, 1200)), 17, ip, remote), mac, GW_MAC) if outbound
                         else _eth(_ip4(_udp(443, sport, b"\x40" * 1200), 17, remote, ip, 55), GW_MAC, mac))
            elif kind == "lan":
                frame = _eth(_ip4(_tcp(sport, 8009, 0x18, b"c" * 80), 6, ip, peer[0]), mac, peer[1])
            else:
                frame = _eth(_ip6(_tcp(sport, 443, 0x18, b"q" * 200), 6, ip6, remote6), mac, GW_MAC, 0x86DD)
        out.append(_event(frame, stamp))
    return out


class PickleQueue(queue.Queue):
    """queue.Queue that serialises like multiprocessing.Queue, so IPC encode/decode is in the measurement."""

    def _put(self, item):
        super()._put(pickle.dumps(item, pickle.HIGHEST_PROTOCOL))

    def _get(self):
        return pickle.loads(super()._get())


def shard_config(workdir, **overrides):
    config = dict(DEFAULTS, SURICATA_EVE_ENABLED=False, LOG_TO_CONSOLE=False, ARP_DETECTION_ENABLED=False,
                  LOCAL_PREFIXES6=LOCAL_PREFIXES6, GC_INTERVAL_SEC=10**9, CORE_SHARDS=1, _CORE_SHARD=0)
    config.update(overrides)
    for name in PATH_KEYS:
        if config.get(name):
            config[name] = str(Path(workdir) / Path(config[name]).name)
    for name in ("SIG_FILE", "POLICY_FILE", "JA3_BLOCKLIST", "OUI_DB"):
        config[name] = overrides.get(name) or str(ROOT / Path(DEFAULTS[name]).name)
    intel = {"ranges": [[int(ipaddress.ip_address("203.0.113.0")), int(ipaddress.ip_address("203.0.113.255")), "bench"]],
             "ranges6": [], "domains": {"evil.example": "bench"}, "ja3": {}, "meta": {}}
    Path(config["THREATINTEL_CACHE"]).write_text(json.dumps(intel))
    return config


def run_shard(events, workdir, profile=False, **overrides):
    """Run the shard over ``events``; return (outputs, events per CPU-second, profiler or None)."""
    config = shard_config(workdir, **overrides)
    ingest, render, merge, db, status = (PickleQueue() for _ in range(5))
    stop, clock, prof = threading.Event(), {}, cProfile.Profile() if profile else None
    real_get = ingest._get

    def first_get():
        clock.setdefault("start", time.thread_time())
        return real_get()

    ingest._get = first_get

    def target():
        if prof is not None:
            prof.enable()
        netwatch_workers.dod_core_process(ingest, render, merge, None, db, None, config, status, None, stop)
        if prof is not None:
            prof.disable()
        clock["end"] = time.thread_time()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    time.sleep(0.4)  # signature loader has read its file before the first packet
    for seq, start in enumerate(range(0, len(events), CHUNK), 1):
        part = events[start:start + CHUNK]
        ingest.put(make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": part, "index": list(range(len(part))),
                                                                   "seq": seq}, correlation_id=f"bench-{seq:06d}"))
    stop.set()
    thread.join(600)
    assert not thread.is_alive()
    outputs = {name: drain(q) for name, q in (("render", render), ("merge", merge), ("db", db))}
    cpu = clock["end"] - clock["start"]  # 0 when a tiny run fits in one tick of a coarse thread clock
    return outputs, len(events) / cpu if cpu else float("inf"), prof


def drain(q):
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            return items


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("workload", choices=("elephant", "mixed"))
    parser.add_argument("events", type=int, nargs="?", default=60_000)
    parser.add_argument("--profile", action="store_true", help="print the top cProfile entries")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    events = (elephant if args.workload == "elephant" else mixed)(args.events)
    rates = []
    for _ in range(args.repeat):
        with tempfile.TemporaryDirectory() as workdir:
            _, rate, prof = run_shard(events, workdir, profile=args.profile)
        rates.append(rate)
        if prof is not None:
            pstats.Stats(prof).sort_stats("tottime").print_stats(30)
            break
    print(f"{args.workload}: {len(events)} events; events per CPU-second: best {max(rates):,.0f} "
          f"median {sorted(rates)[len(rates) // 2]:,.0f} (pid {os.getpid()})")


if __name__ == "__main__":
    main()
