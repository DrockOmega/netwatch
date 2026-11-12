"""Capture and analytics workers, independent of Qt and OpenGL."""

import faulthandler
import ipaddress
import json
import math
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime
from operator import itemgetter

import numpy as np

from netwatch_config import detect_default_gateway
from netwatch_core import (
    DISK_MIN_FREE_BYTES,
    AlertGate,
    analyze_port_sweep,
    analyze_udp_flood,
    analyze_volumetric_exfil,
    arena_dtype,
    community_id_v1,
    compile_v4_prefixes,
    compile_v6_prefixes,
    core_shard,
    ip_pack,
    ip_str,
    is_global_ip,
    is_local_ip,
    is_message_payload,
    make_db_batch_message,
    make_message,
    start_parent_watchdog,
    track_sweep_target,
    try_put_drop_oldest,
    try_put_drop_oldest_with_eviction,
    try_put_no_drop,
    ttl_profile,
)
from netwatch_db import compact_event_rows, encode_packet_rows, packet_row_key
from netwatch_log import setup_logging
from netwatch_security_store import _event_time, publish_detection, security_db_path, security_store_from_config

SNIFFER_STALL_DUMP_SEC = 20  # well past one select (1 s) and a 256-frame dispatch
INGEST_HOLD_BATCHES = 64  # full batches the sniffer holds for a busy core (~32k events) before it pauses reads
GEO_CACHE_MAX = 65536  # distinct destinations remembered before the country cache starts over
ALERT_BUSY_TIMEOUT_MS = 250  # packet-path alert commits; a busier store defers them to the analysis thread
EVIDENCE_REQUESTS_PER_PASS = 100  # evidence_queue maxsize: one pass still empties a full queue, a flood waits a pass
MERGE_STALL_WARN_SEC = 30  # a shard warns (and every minute after) while the merge reads none of its records
MERGE_STOP_WAIT_SEC = 5  # a stopping shard gives up on a merge that has read nothing for this long
NO_EXTRA = (None, None, None, None, None, ())  # an event record's policy/beacon/DNS/JA3/intel/signature items
# A shard's own IPC drops, reported by the merge (alerts here are the shard's notices to the merge).
SHARD_DROP_COUNTERS = ("dropped_alerts", "dropped_db_batches", "dropped_db_rows", "dropped_core_heartbeats",
                       "dropped_web_observations")


def worker_entrypoint(target, args, shutdown_event, transient_queues=(), drop_privs=False):
    """Run a worker with fail-closed shutdown when its supervisor parent is killed."""
    start_parent_watchdog(shutdown_event)
    for ipc in transient_queues:
        ipc.cancel_join_thread()  # Durable records precede presentation; orphaned readers must not stall exit.
    if drop_privs:  # Every worker but capture; fails closed (worker exits) if the drop fails.
        from netwatch_privilege import drop_privileges

        drop_privileges()
    target(*args)


_clock_second = (float("-inf"), "")  # the last whole second rendered, and its text


def clock_text(timestamp):
    """``HH:MM:SS`` local time of a packet; strftime once per second, not per packet."""
    global _clock_second
    second, text = _clock_second
    if 0.0 <= timestamp - second < 0.999999:
        return text
    text = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
    second = math.floor(timestamp)
    if 0.0 <= timestamp - second < 0.999999:  # within a microsecond of the next second fromtimestamp may round up
        _clock_second = (second, text)
    return text


def detection_community_id(evt_data, src, dst):
    """Community ID for a flow-scoped TCP/UDP detection, as the ledger derives it; else None."""
    try:
        if evt_data.get("ip_protocol") in (6, 17) and evt_data.get("source_port") is not None \
                and evt_data.get("non_initial_fragment") is False:
            return community_id_v1(evt_data["ip_protocol"], src, int(evt_data["source_port"]),
                                   dst, int(evt_data.get("port")))
    except (TypeError, ValueError, OverflowError):
        pass
    return None


def _human_bytes(n):
    """Compact byte size for alert text. Auto-scales the unit so low-volume values
    stay legible (a baseline notice must not render small egress as ``0.00MB``)."""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def publish_or_defer(store, status_queue, message, deferred, log, limit=256):
    """A busy store must not kill capture: keep the record and retry next loop (bounded).
    Returns False when the record is lost (overflow or a permanent error), else the publish result."""
    try:
        if not deferred:  # behind a backlog, queue without trying: do not wait on the busy store again
            return publish_detection(store, status_queue, message)
        exc = "store busy, backlog waiting"
    except sqlite3.OperationalError as busy:
        exc = busy
    except (sqlite3.Error, ValueError, TypeError) as bad:  # retrying a permanent error would block the backlog forever
        log.error("detection dropped, not retryable: %s: %s", type(bad).__name__, bad)
        return False
    if len(deferred) >= limit:
        log.error("detection dropped, %d already waiting on a busy store: %s", len(deferred), exc)
        return False
    deferred.append(message)
    return None


def retry_deferred(store, status_queue, deferred, log):
    """Republish the backlog in order; stop at the first busy store so a pass costs one busy wait."""
    while deferred:
        try:
            publish_detection(store, status_queue, deferred[0])
        except sqlite3.OperationalError:
            return
        except (sqlite3.Error, ValueError, TypeError) as exc:
            log.error("deferred detection dropped, not retryable: %s: %s", type(exc).__name__, exc)
        del deferred[0]


THROUGHPUT_LOG_SEC = 10.0


def shard_chunk(events, shards, v4_prefix_pairs, v6_prefix_pairs, sender_macs, seq):
    """One INGEST_PACKET per shard (``core_shard``) for capture chunk number ``seq``, empty ones included;
    ``index`` is each event's position in the chunk, the order the merge restores."""
    parts = [([], []) for _ in range(shards)]
    for position, event in enumerate(events):
        try:
            owner = core_shard(event, shards, v4_prefix_pairs, v6_prefix_pairs, sender_macs)
        except Exception:  # a malformed event still reaches a core, which counts the fault
            owner = 0
        parts[owner][0].append(event)
        parts[owner][1].append(position)
    return [make_message("IO_WORKER", "INGEST_PACKET", 0, {"events": part, "index": index, "seq": seq})
            for part, index in parts]


def io_sniffer_process(ingestion_queue, evidence_queue, config, worker_status_queue, shutdown_event=None,
                       capture_stop=None, capture_drained=None, progress=None):
    """Physically isolated process for live packet ingestion.

    ``ingestion_queue`` may be a tuple, one queue per analytics shard: each shipped chunk is then split
    by ``core_shard`` and every shard gets its part (possibly empty), in order, so the merge can pair
    them up again."""
    from netwatch_capture import (
        CaptureHealth,
        CaptureProgress,
        DropTracker,
        make_capture_dispatcher,
        open_capture_socket,
        parse_ethernet_frame,
        pcap_stats,
        set_capture_buffer,
    )
    from netwatch_ja3 import fingerprint as ja3_fingerprint  # pure TLS-hello fingerprinter

    log = setup_logging("sniffer", config)
    security_store = security_store_from_config(config)
    interface = config["NIC_INTERFACE"]
    bpf_filter = config.get("BPF_FILTER")
    batch_max = int(config.get("INGEST_BATCH_MAX", 64))
    batch_sec = float(config.get("INGEST_BATCH_SEC", 0.1))
    capture_progress = CaptureProgress()
    capture_stats = [{"available": False, "timestamp": None}]
    evidence = None
    init_failure = None  # published once the detection-publisher thread runs
    if config.get("EVIDENCE_CAPTURE_ENABLED", True):
        try:
            from netwatch_evidence import EvidenceRecorder

            evidence = EvidenceRecorder(
                config.get("EVIDENCE_DIR", "evidence"),
                pre_sec=config.get("EVIDENCE_PRE_SEC", 15),
                post_sec=config.get("EVIDENCE_POST_SEC", 5),
                max_ring_bytes=config.get("EVIDENCE_RING_MAX_BYTES", 67_108_864),
                max_files=config.get("EVIDENCE_MAX_FILES", 100),
                max_pending=config.get("EVIDENCE_MAX_PENDING", 32),
                max_write_jobs=config.get("EVIDENCE_MAX_WRITE_JOBS", 8),
                coalesce_sec=config.get("EVIDENCE_COALESCE_SEC", 2.0),
                catalog_path=security_db_path(config),
                max_bytes=config.get("EVIDENCE_MAX_BYTES", 2_147_483_648),
                retention_days=config.get("EVIDENCE_RETENTION_DAYS", 7),
                sensor_id=config.get("SENSOR_ID", "unknown"),
                capture_interface=interface,
                min_free_bytes=config.get("DISK_MIN_FREE_BYTES", DISK_MIN_FREE_BYTES),
            )
        except Exception as exc:
            log.error("evidence capture disabled — init failed: %s: %s", type(exc).__name__, exc)
            init_failure = make_message(
                "IO_WORKER",
                "EVIDENCE_FAILED",
                "UI_SHELL",
                {"message": "Evidence recorder could not start", "error": str(exc)},
            )

    deferred_evidence = []  # detections the busy store refused; retried before new work

    # The capture thread only queues; this thread owns the store writes, so a busy store never stalls capture.
    publish_q = queue.Queue(256)
    publish_stop = object()

    def publish_evidence(message):
        try:
            publish_q.put_nowait(message)
        except queue.Full:
            log.error("detection dropped, publisher queue full")

    def publisher():
        try:
            while True:
                try:
                    message = publish_q.get(timeout=1.0)
                except queue.Empty:
                    message = None  # idle tick: retry the backlog
                retry_deferred(security_store, worker_status_queue, deferred_evidence, log)
                if message is publish_stop:
                    return
                if message is not None:
                    publish_or_defer(security_store, worker_status_queue, message, deferred_evidence, log)
        except Exception as exc:
            log.error("detection publisher died: %s: %s", type(exc).__name__, exc)

    publisher_thread = threading.Thread(target=publisher, name="detection-publisher", daemon=True)
    publisher_thread.start()
    if init_failure is not None:
        publish_evidence(init_failure)

    def report_evidence_result(result):
        action = "EVIDENCE_SAVED" if result["ok"] else "EVIDENCE_FAILED"
        message = (
            f"Evidence saved: {result['path']} ({result['frames']} frames)"
            if result["ok"]
            else f"Evidence capture failed: {result.get('error', 'unknown')}"
        )
        msg = make_message("IO_WORKER", action, "UI_SHELL", {**result, "message": message})
        if result["ok"]:  # a receipt, not a finding: the capture is catalogued and linked to its triggering case
            try_put_drop_oldest(worker_status_queue, msg)
        else:
            publish_evidence(msg)

    if evidence is not None:
        for error in evidence.recovery["errors"]:
            report_evidence_result({"ok": False, "error": f"Evidence recovery failed: {error}"})

    control_worker = control_store = None
    if config.get("CONTROL_CAPTURE_ENABLED", True):
        try:
            from netwatch_control import ControlCaptureWorker, ControlCollector

            control_store = security_store_from_config(config)
            control_worker = ControlCaptureWorker(
                ControlCollector(
                    control_store, config, notify=lambda finding: try_put_drop_oldest(worker_status_queue, finding)
                ),
                max_pending=config.get("CONTROL_CAPTURE_MAX_PENDING", 1024),
                heartbeat_sec=config.get("CONTROL_HEARTBEAT_SEC", 5),
            )
        except Exception as exc:
            if control_store is not None:
                control_store.close()
                control_store = None
            log.error("control collector could not start: %s", exc)
            publish_evidence(
                make_message(
                    "IO_WORKER",
                    "CONTROL_COLLECTION_GAP",
                    "UI_SHELL",
                    {
                        "message": "Passive control collector could not start",
                        "error": str(exc),
                        "containment_eligible": False,
                    },
                ),
            )

    # Events are shipped in batches: one mp.Queue message per packet made pickle +
    # pipe overhead the throughput ceiling, not detection. The lock is held only
    # for the list swap, never across the enqueue.
    ingestion_queues = tuple(ingestion_queue) if isinstance(ingestion_queue, list | tuple) else (ingestion_queue,)
    shard_prefixes = None  # sharded: the locality the split routes by, and each LAN sender's MAC
    if len(ingestion_queues) > 1:
        shard_prefixes = (compile_v4_prefixes(config["LOCAL_PREFIXES"]),
                          compile_v6_prefixes(config.get("LOCAL_PREFIXES6", ())), {})
    chunk_seq = [0]  # sharded: numbers each split chunk, so the merge can tell a lost or mixed part
    head = []  # sharded: the head chunk's event count, then its shard messages not yet accepted
    pending = []
    pending_lock = threading.Lock()
    flush_lock = threading.Lock()  # one shipper at a time: a held backlog is shipped from its head
    last_flush = [time.time()]
    # A full ingestion queue holds events here; at hold_max the read loop stops draining Npcap, so a
    # burst waits in the kernel buffer (PCAP_BUFFER_BYTES) instead of being dropped. Only one dispatch
    # can land past hold_max, so the hard cap (twice it) is reached only if that bound is broken.
    hold_max = INGEST_HOLD_BATCHES * batch_max

    class IOMetrics:
        dropped_packets = 0
        dropped_heartbeats = 0
        last_log_time = time.time()
        total_dropped = 0  # reported in the heartbeat, so RUNTIME:IO_WORKER health carries it
        gap_packets = 0  # dropped since the last CAPTURE_INGEST_GAP finding
        last_gap_time = 0.0
        parse_errors = 0
        last_parse_log = 0.0
        last_hold_log = 0.0

    log.info("starting packet capture on %s (filter: %s)", interface, bpf_filter)

    def flush_batch(force=False):
        """Ship the accumulated events as INGEST_PACKET messages of at most ``batch_max`` events.

        A full queue leaves them pending (in order) for the next call; only a forced final flush that
        still cannot enter analytics drops, and counts, the remainder."""
        now = time.time()
        accepted = True
        with flush_lock:
            with pending_lock:
                ship = bool(pending) and (force or len(pending) >= batch_max or now - last_flush[0] >= batch_sec)
                if ship:
                    last_flush[0] = now
            while ship:
                if not head:
                    with pending_lock:
                        events = pending[:batch_max]
                    if not events:
                        break
                    head.append(len(events))
                    if shard_prefixes is None:
                        head.append((ingestion_queues[0], make_message("IO_WORKER", "INGEST_PACKET", 0,
                                                                       {"events": events})))
                    else:
                        chunk_seq[0] += 1
                        head.extend(zip(ingestion_queues, shard_chunk(events, len(ingestion_queues), *shard_prefixes,
                                                                      chunk_seq[0]), strict=True))
                # A part a shard accepted is never re-sent: each shard sees each chunk exactly once, in order.
                while len(head) > 1:
                    accepted = try_put_no_drop(*head[1], timeout=1 if force else 0)
                    if not accepted:
                        break
                    del head[1]
                if not accepted:
                    if shard_prefixes is None:
                        head.clear()  # nothing went out: the next try ships the head of a longer backlog
                    break
                with pending_lock:
                    del pending[:head.pop()]  # appends only extend the tail
            if not accepted and force:
                unshipped = sum(len(msg["data"]["events"]) for _, msg in head[1:])
                shipped = head[0] - unshipped if head else 0  # parts some shards already took are not lost
                head.clear()
                with pending_lock:
                    lost, pending[:] = len(pending) - max(0, shipped), []
                IOMetrics.dropped_packets += lost
                IOMetrics.gap_packets += lost
        # The final (forced) flush reports any remainder so no drop goes unlogged at shutdown.
        if IOMetrics.dropped_packets and (force or now - IOMetrics.last_log_time > 1.0):
            log.warning(
                "backpressure: dropped %d packets in the last %.1fs",
                IOMetrics.dropped_packets,
                now - IOMetrics.last_log_time,
            )
            IOMetrics.total_dropped += IOMetrics.dropped_packets
            IOMetrics.dropped_packets = 0
            IOMetrics.last_log_time = now
        # Sustained backpressure is a collection gap, not only a log line: at most one finding a minute.
        if IOMetrics.gap_packets and (force or now - IOMetrics.last_gap_time >= 60.0):
            count, IOMetrics.gap_packets, IOMetrics.last_gap_time = IOMetrics.gap_packets, 0, now
            publish_evidence(make_message(
                "IO_WORKER", "CAPTURE_INGEST_GAP", "SYSTEM",
                {"message": f"Analytics fell behind: {count} captured packet(s) dropped before analysis",
                 "count": count, "severity": "anomaly", "containment_eligible": False}))
        return accepted

    batch_stop = threading.Event()

    def batch_flusher():
        """Age out a partial batch when traffic goes quiet — without this, the last
        few packets before a lull would sit unsent until the next packet arrives."""
        while not batch_stop.is_set() and (shutdown_event is None or not shutdown_event.is_set()):
            if batch_stop.wait(batch_sec):
                break
            try:
                flush_batch()
            except Exception as exc:  # a flusher fault must never kill capture
                log.error("batch flush failed: %s: %s", type(exc).__name__, exc)

    batch_thread = threading.Thread(target=batch_flusher, daemon=True)
    batch_thread.start()

    from netwatch_privilege import get_privilege_state

    privilege_state = get_privilege_state()

    captured = [0]  # packets seen by process_frame; a bare increment is the only per-packet cost

    def heartbeat_emitter():
        mark = (time.monotonic(), time.process_time(), 0)
        while shutdown_event is None or not shutdown_event.is_set():
            time.sleep(5)
            wall = time.monotonic()
            if wall - mark[0] >= THROUGHPUT_LOG_SEC:
                cpu, seen = time.process_time(), captured[0]
                span = wall - mark[0]
                log.info("throughput: packets_per_sec=%.1f cpu_pct=%.1f",
                         (seen - mark[2]) / span, 100.0 * (cpu - mark[1]) / span)
                mark = (wall, cpu, seen)
            msg = make_message(
                "IO_WORKER",
                "WORKER_HEARTBEAT",
                "UI_SHELL",
                {
                    "timestamp": time.time(),
                    **capture_progress.report(timeout=float(config.get("RUNTIME_HEARTBEAT_TIMEOUT_SEC", 10)), start_timeout=float(config.get("RUNTIME_START_GRACE_SEC", 120))),
                    "capture_stats": capture_stats[0],
                    "ingest_dropped_packets": IOMetrics.total_dropped,
                    "privilege": privilege_state,
                },
            )
            if not try_put_drop_oldest(worker_status_queue, msg):
                IOMetrics.dropped_heartbeats += 1

    threading.Thread(target=heartbeat_emitter, daemon=True).start()

    def process_frame(raw_frame, capture_ts=None):
        # Liveness first: update the heartbeat watchdog BEFORE any parsing so a
        # malformed frame can never starve the deadlock detector.
        capture_progress.packet_seen()
        captured[0] += 1
        try:
            if evidence is not None:
                evidence.add(capture_ts, raw_frame)
            parsed = parse_ethernet_frame(raw_frame, capture_ts, ja3_fingerprint)
            if parsed is None:
                return
            kind, data = parsed
            data["sensor_id"] = config.get("SENSOR_ID") or "unknown"
            data["interface"] = interface
            if control_worker is not None and (kind in {"arp", "control"} or data.get("control_type")):
                control_worker.submit(raw_frame, data)
            if kind == "control":
                return
            if kind == "arp":
                return

            data.pop("control_payload", None)  # Native collector owns this copy; keep packet IPC metadata-only.
            with pending_lock:
                if len(pending) >= 2 * hold_max:
                    IOMetrics.dropped_packets += 1
                    IOMetrics.gap_packets += 1
                    return
                pending.append(data)
                ready = len(pending) >= batch_max
            if ready:
                flush_batch()
        except Exception as e:
            # A single malformed/unexpected packet must NEVER kill the capture loop —
            # that is the whole reason scapy is isolated in this process. Count and
            # rate-limit a diagnostic instead of letting the exception reach sniff().
            IOMetrics.parse_errors += 1
            if time.time() - IOMetrics.last_parse_log > 2.0:
                log.warning("frame parse error (skipped %d): %s: %s", IOMetrics.parse_errors, type(e).__name__, e)
                IOMetrics.parse_errors = 0
                IOMetrics.last_parse_log = time.time()

    # Own the pcap handle so kernel-level drops are observable. Opening and tuning
    # are separate failure domains: a rejected buffer size keeps direct capture
    # with the driver's default instead of falsely claiming the socket failed.
    try:
        buffer_bytes = int(config.get("PCAP_BUFFER_BYTES", 64 * 1024 * 1024))
    except (TypeError, ValueError, OverflowError):
        buffer_bytes = 64 * 1024 * 1024
        log.warning("invalid PCAP_BUFFER_BYTES; using %s", _human_bytes(buffer_bytes))

    def open_direct_socket():
        capture_stats[0] = {"available": False, "timestamp": None}
        try:
            direct_sock = open_capture_socket(interface, bpf_filter, buffer_bytes)
        except Exception as exc:
            log.warning(
                "could not open capture socket directly (%s: %s); using sniff(iface=...) without drop accounting",
                type(exc).__name__,
                exc,
            )
            return None
        try:
            tuned = set_capture_buffer(direct_sock, buffer_bytes)
        except Exception as exc:
            tuned = False
            log.warning("capture buffer tuning failed (%s: %s); keeping driver default", type(exc).__name__, exc)
        try:
            # Required with the Windows pcap event: select establishes readiness,
            # nonblocking recv makes a stale event a normal empty read.
            direct_sock.pcap_fd.setnonblock(True)
        except Exception as exc:
            log.warning(
                "direct capture cannot enter nonblocking mode (%s: %s); using compatibility listener",
                type(exc).__name__,
                exc,
            )
            try:
                direct_sock.close()
            except Exception:
                pass
            return None
        try:
            direct_sock.dispatch = make_capture_dispatcher(direct_sock, process_frame)
        except Exception as exc:
            log.warning(
                "direct capture batch dispatcher unavailable (%s: %s); using compatibility listener",
                type(exc).__name__,
                exc,
            )
            try:
                direct_sock.close()
            except Exception:
                pass
            return None
        log.info(
            "capture socket opened; kernel drop accounting active; buffer=%s (%s)",
            _human_bytes(buffer_bytes),
            "accepted" if tuned else "driver default",
        )
        return direct_sock

    sock = open_direct_socket()
    next_direct_retry = time.time() + 30.0

    drops = DropTracker()
    capture_health = CaptureHealth(
        min_loss_pct=float(config.get("PCAP_ALERT_MIN_LOSS_PCT", 0.1)),
        reminder_sec=float(config.get("PCAP_UI_ALERT_INTERVAL_SEC", 60)),
        recovery_samples=int(config.get("PCAP_RECOVERY_SAMPLES", 2)),
    )
    last_stats = time.time()
    stats_interval = float(config.get("PCAP_STATS_INTERVAL_SEC", 10))
    drain_batch = max(1, int(config.get("PCAP_DRAIN_BATCH", 256)))
    try:
        idle_backoff = max(0.0005, float(config.get("PCAP_IDLE_BACKOFF_SEC", 0.001)))
    except (TypeError, ValueError, OverflowError):
        idle_backoff = 0.001
        log.warning("invalid PCAP_IDLE_BACKOFF_SEC; using %.4fs", idle_backoff)

    def service_evidence(now):
        for _ in range(EVIDENCE_REQUESTS_PER_PASS):
            try:
                request = evidence_queue.get_nowait()
            except queue.Empty:
                break
            if is_message_payload(request) and request["action"] == "EVIDENCE_CAPTURE":
                accepted = evidence is not None and evidence.request(request["data"], now)
                if not accepted:
                    publish_evidence(make_message(
                        "IO_WORKER", "EVIDENCE_FAILED", "UI_SHELL", {
                            "message": "Evidence recorder unavailable or request exceeds bounded limits",
                            "correlation_id": request["data"].get("correlation_id"),
                            "source_event_id": request["data"].get("source_event_id") or request["correlation_id"],
                        }, correlation_id=request["correlation_id"]))
        if evidence is not None:
            for result in evidence.poll(now):
                report_evidence_result(result)

    paused = False

    # The loop has stalled ~32 s at a time on the sensor (2026-10-11/12) with nothing logged: past
    # SNIFFER_STALL_DUMP_SEC every thread's stack goes to logs/sniffer-stall.txt, so the next
    # stall names its blocking call. A dedicated file: a rotated log stream would be closed.
    stall_file = None
    try:
        stall_file = open(os.path.join(config.get("LOG_DIR", "logs"), "sniffer-stall.txt"), "a", encoding="utf-8")
    except OSError as exc:
        log.warning("stall dumps unavailable: %s", exc)

    # Self-healing capture: a dead direct handle is closed and re-opened; the Scapy
    # compatibility listener keeps packets flowing while a direct re-open fails.
    last_arm = float("-inf")
    while shutdown_event is None or not shutdown_event.is_set():
        # Re-arming joins the old watchdog thread and starts a new one (~22 us CPU on Linux, more on
        # Windows), so it happens once a second, not once per wake; a stall still dumps within 20 s.
        if stall_file is not None and time.monotonic() - last_arm >= 1.0:
            last_arm = time.monotonic()
            faulthandler.dump_traceback_later(SNIFFER_STALL_DUMP_SEC, file=stall_file)  # re-arming cancels the last
        if capture_stop is not None and capture_stop.is_set():
            if not paused:
                batch_stop.set()
                batch_thread.join()
                flush_batch(force=True)
                if control_worker is not None:
                    if control_worker.close():
                        control_store.close()
                        control_worker = None
                    else:
                        # Not a packet-drain failure: the uncommitted stop marker makes the next
                        # start record the control gap, so core/db still get their drain budget.
                        log.warning("control collector did not drain cleanly; next startup records a collection gap")
                # Stop this producer's feeder only after all its input is written.
                # The core remains a consumer throughout this handshake.
                for ipc in ingestion_queues:
                    ipc.close()
                    ipc.join_thread()
                paused = True
                capture_stats[0] = {"available": False, "timestamp": None}
                capture_progress.read_failed("capture paused for ordered shutdown")
                if capture_drained is not None:
                    capture_drained.set()
            service_evidence(time.time())
            if shutdown_event is not None:
                shutdown_event.wait(0.05)
            else:
                time.sleep(0.05)
            continue
        try:
            if sock is not None:
                if len(pending) >= hold_max:
                    flush_batch()
                if len(pending) >= hold_max:
                    # Analytics is behind: leave the burst in the kernel buffer; the driver's drop counters
                    # (CAPTURE LOSS) report it if that overflows too.
                    if time.monotonic() - IOMetrics.last_hold_log >= 10:
                        IOMetrics.last_hold_log = time.monotonic()
                        log.warning("ingest held: %d events waiting for analytics; capture reads paused",
                                    len(pending))
                    if shutdown_event is not None:
                        shutdown_event.wait(0.01)
                    else:
                        time.sleep(0.01)
                elif sock in type(sock).select([sock], 1.0):
                    dispatched = sock.dispatch(drain_batch)
                    if dispatched == 0:
                        if shutdown_event is not None:
                            shutdown_event.wait(idle_backoff)
                        else:
                            time.sleep(idle_backoff)
            else:
                # Compatibility path only. Direct Npcap ownership is the production
                # path; if unavailable, Scapy can still deliver raw frame bytes.
                from scapy.layers.inet import IP, TCP, UDP  # noqa: F401
                from scapy.layers.inet6 import IPv6  # noqa: F401
                from scapy.layers.l2 import ARP, Ether  # noqa: F401
                from scapy.sendrecv import sniff

                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=lambda pkt: process_frame(bytes(pkt), getattr(pkt, "time", None)),
                    store=False,
                    timeout=1.0,
                )
            capture_progress.read_complete()
            if progress is not None:
                progress.value = time.monotonic()
        except Exception as e:
            capture_progress.read_failed(e)
            capture_stats[0] = {"available": False, "timestamp": None}
            log.error("capture read error: %s: %s; reopening in 2s...", type(e).__name__, e)
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
                sock = None
            next_direct_retry = time.time() + 2.0
            time.sleep(2)
            continue

        now = time.time()
        service_evidence(now)
        if sock is None and now >= next_direct_retry:
            sock = open_direct_socket()
            next_direct_retry = now + 30.0
        if sock is not None and now - last_stats >= stats_interval:
            last_stats = now
            counters = pcap_stats(sock)
            capture_stats[0] = {"available": counters is not None, "timestamp": now, "counters": counters}
            report = drops.update(counters)
            if report and report["dropped"] + report["ifdropped"] > 0:
                log.warning(
                    "CAPTURE LOSS: %d dropped (%d kernel / %d iface) of %d offered "
                    "= %.2f%% — analytics are blind to those packets",
                    report["dropped"] + report["ifdropped"],
                    report["dropped"],
                    report["ifdropped"],
                    report["offered"],
                    report["loss_pct"],
                )
            health_event = capture_health.observe(report, now)
            if health_event == "loss":
                stat_msg = make_message(
                    "IO_WORKER",
                    "CAPTURE_LOSS",
                    "UI_SHELL",
                    {
                        "message": f"CAPTURE LOSS: {report['loss_pct']:.1f}% of offered packets dropped by the "
                        f"driver ({report['total_dropped']} total; next reminder in "
                        f"{capture_health.reminder_sec:g}s)",
                        "severity": "anomaly",
                    },
                )
                # A busy store must not end capture: an uncaught "database is locked" here
                # killed the sniffer, whose exit then hung on its ingestion feeder (VM 2026-10-08).
                publish_evidence(stat_msg)
            elif health_event == "recovered":
                publish_evidence(
                    make_message(
                        "IO_WORKER",
                        "CAPTURE_RECOVERED",
                        "UI_SHELL",
                        {
                            "message": "CAPTURE RECOVERED: driver loss remained below threshold",
                            "severity": "recovered",
                        },
                    ),
                )

    if stall_file is not None:
        faulthandler.cancel_dump_traceback_later()
        stall_file.close()
    batch_stop.set()
    batch_thread.join(timeout=1)
    if not paused:
        flush_batch(force=True)
    service_evidence(time.time())
    if control_worker is not None:
        if control_worker.close():
            control_store.close()
        else:
            log.warning("control collector did not drain cleanly; next startup records a collection gap")
    if evidence is not None:
        for result in evidence.close(time.time()):
            report_evidence_result(result)
    try:
        publish_q.put(publish_stop, timeout=1.0)  # after the last results
    except queue.Full:
        log.warning("publisher stop sentinel not queued (queue full); relying on the bounded join")
    publisher_thread.join(timeout=3.0)  # short of the 10 s stop grace, which also covers the db worker
    if deferred_evidence:
        log.error("%d detection(s) not recorded at shutdown: security store busy", len(deferred_evidence))
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
    log.info("sniffer shut down")
    security_store.close()


def refresh_gateway(config, arp_analyzer, log):
    """Follow the default route, but never override a GATEWAY_IP the operator configured."""
    if not config.get("GATEWAY_IP_AUTO", True):
        return
    try:
        current_gw = detect_default_gateway()
        if current_gw and current_gw != arp_analyzer.gateway_ip:
            log.info("gateway changed: %s -> %s", arp_analyzer.gateway_ip or "<none>", current_gw)
            arp_analyzer.gateway_ip = current_gw
        elif not current_gw:
            log.info("gateway re-detection found no default route; keeping %s", arp_analyzer.gateway_ip or "<none>")
    except Exception as e:
        log.warning("gateway re-detection failed: %s: %s", type(e).__name__, e)


def evidence_policy(config, log):
    """The finding actions that request packet evidence, and their per-target cooldown gate."""
    try:
        gate = AlertGate(config.get("EVIDENCE_CAPTURE_COOLDOWN_SEC", 900))
    except (TypeError, ValueError) as exc:
        log.error("evidence capture cooldown invalid; using 900 seconds: %s", exc)
        gate = AlertGate(900)
    return frozenset(str(value) for value in config.get("EVIDENCE_CAPTURE_ACTIONS", ())), gate


def request_evidence(config, evidence_queue, actions, gate, msg):
    """Ask capture for pre/post-event PCAP for an evidence-worthy finding; False if the queue refused it."""
    data = msg.get("data") if isinstance(msg.get("data"), dict) else {}
    evidence_key = data.get("evidence_key") or msg.get("target_id") or "system"
    if not (config.get("EVIDENCE_CAPTURE_ENABLED", True) and msg["action"] in actions
            and gate.allow(msg["action"], evidence_key, time.time())):
        return True
    return try_put_no_drop(
        evidence_queue,
        make_message(
            "DOD_CORE",
            "EVIDENCE_CAPTURE",
            "IO_WORKER",
            {
                "trigger_ts": _event_time(data.get("timestamp"), time.time()),
                "action": msg["action"],
                "correlation_id": msg["correlation_id"],
                "source_event_id": data.get("source_event_id") or msg["correlation_id"],
                "source": msg["source"],
                "sensor_id": data.get("sensor_id") or config.get("SENSOR_ID", "unknown"),
                "message": str(data.get("message") or msg["action"]),
            },
            correlation_id=msg["correlation_id"],
        ),
    )


def durable_analysis_process(alert_queue, evidence_queue, inventory_queue, config, worker_status_queue,
                             shutdown_event):
    """ARP replay, passive assets and wireless watch over committed native records.

    Its own process, so its own GIL: as a core thread under a 10k events/s burst, the asset
    analyzer's poll waited on the core's GIL while holding the security store's writer lock for
    10 s, and the sniffer dropped ~10k packets (the sensor). Every analyzer resumes from its SQLite
    cursors, so a restart neither loses nor repeats committed work. The core sends its inventory
    snapshot on ``inventory_queue`` (one slot, drop-oldest) on its save cadence."""
    log = setup_logging("analysis", config)
    store = security_store_from_config(config)
    evidence_actions, evidence_gate = evidence_policy(config, log)
    arp_analyzer = None
    if config.get("ARP_DETECTION_ENABLED", True):
        from netwatch_arp import DurableArpAnalyzer

        arp_analyzer = DurableArpAnalyzer(store, config)
    from netwatch_assets import HEALTH_KEY as ASSET_HEALTH_KEY
    from netwatch_assets import DurableAssetAnalyzer
    from netwatch_inventory import load_oui_db  # missing/corrupt file -> {} like the core's inventory
    from netwatch_privilege import get_privilege_state
    from netwatch_wireless import HEALTH_KEY as WIRELESS_HEALTH_KEY
    from netwatch_wireless import WirelessWatch

    oui_db = load_oui_db(config.get("OUI_DB", "")) if config.get("DEVICE_INVENTORY_ENABLED", True) else None
    asset_analyzer = DurableAssetAnalyzer(store, config, oui_db=oui_db)
    wireless_watch = WirelessWatch(store, config)
    privilege_state = get_privilege_state()

    evidence_refused = [0]

    def _notify_committed(payload):
        # The analyzers commit findings with their cursors; this is presentation plus evidence only.
        try_put_drop_oldest(alert_queue, payload)
        if not request_evidence(config, evidence_queue, evidence_actions, evidence_gate, payload):
            evidence_refused[0] += 1

    # The gateway is re-detected periodically: it is captured once at config build
    # time, so a DHCP lease change or a move to another network would otherwise
    # leave ARP/MITM escalation anchored to an address that no longer routes.
    gateway_refresh = float(config.get("GATEWAY_REFRESH_SEC", 300))
    last_gateway_check = time.monotonic()
    last_arp_poll = last_asset_poll = last_arp_health = last_heartbeat = 0.0
    while not shutdown_event.wait(0.5):
        try:
            if arp_analyzer is not None and time.monotonic() - last_arp_poll >= 0.5:
                last_arp_poll = time.monotonic()
                arp_analyzer.notify = _notify_committed
                try:
                    arp_analyzer.poll()
                    arp_analyzer.last_error = None
                except Exception as exc:
                    arp_analyzer.last_error = str(exc)[:1000]
                    log.error("durable ARP analysis deferred: %s", exc)
                if time.monotonic() - last_arp_health >= 5:
                    try:
                        store.record_source_health(arp_analyzer.cursor_key, arp_analyzer.health())
                        last_arp_health = time.monotonic()
                    except Exception as exc:
                        log.error("ARP analysis health could not be recorded: %s", exc)
            if time.monotonic() - last_asset_poll >= 2:
                last_asset_poll = time.monotonic()
                try:
                    asset_analyzer.poll()
                    asset_analyzer.last_error = None
                except Exception as exc:
                    asset_analyzer.last_error = str(exc)[:1000]
                    log.error("asset analysis deferred: %s", exc)
                try:
                    store.record_source_health(ASSET_HEALTH_KEY, asset_analyzer.health())
                except Exception as exc:
                    log.error("asset analysis health could not be recorded: %s", exc)
            try:
                snapshot = inventory_queue.get_nowait()
            except queue.Empty:
                snapshot = None
            if is_message_payload(snapshot) and snapshot["action"] == "INVENTORY_SNAPSHOT":
                snapshot = snapshot["data"]["devices"]
                try:
                    asset_analyzer.observe_inventory(snapshot)
                except Exception as e:
                    log.error("inventory asset feed deferred: %s: %s", type(e).__name__, e)
                try:
                    wireless_watch.notify = lambda p: try_put_drop_oldest(alert_queue, p)
                    wireless_watch.poll(devices=snapshot)
                    wireless_watch.last_error = None
                except Exception as e:
                    wireless_watch.last_error = str(e)[:1000]
                    log.error("wireless watch deferred: %s: %s", type(e).__name__, e)
                try:
                    store.record_source_health(WIRELESS_HEALTH_KEY, wireless_watch.health())
                except Exception as e:
                    log.error("wireless watch health could not be recorded: %s", e)
            # Re-anchor gateway-rebind escalation if the default route moved.
            if (
                arp_analyzer is not None
                and gateway_refresh > 0
                and time.monotonic() - last_gateway_check >= gateway_refresh
            ):
                last_gateway_check = time.monotonic()
                refresh_gateway(config, arp_analyzer, log)
            if evidence_refused[0]:  # the core's alert for a refused request, as when this ran in its thread
                publish_detection(store, alert_queue, make_message(
                    "DOD_CORE", "EVIDENCE_BACKPRESSURE", "SYSTEM",
                    {"message": "EVIDENCE_BACKPRESSURE: capture request queue full"}))
                evidence_refused[0] = 0
        except Exception as exc:  # one bad turn must not end durable analysis
            log.error("durable analysis turn failed: %s: %s", type(exc).__name__, exc)
        if time.monotonic() - last_heartbeat >= 5:  # from the loop itself: a late one means a slow turn
            try_put_drop_oldest(worker_status_queue, make_message(
                "DURABLE_ANALYSIS", "WORKER_HEARTBEAT", "UI_SHELL",
                {"timestamp": time.time(), "status": "ALIVE", "privilege": privilege_state}))
            last_heartbeat = time.monotonic()
    log.info("durable analysis shut down")
    store.close()


def dod_core_process(
    ingestion_queue,
    render_queue,
    alert_queue,
    policy_queue,
    db_queue,
    evidence_queue,
    config,
    worker_status_queue,
    inventory_queue,
    shutdown_event=None,
):
    """Analytics core: consumes INGEST_* messages, runs the detectors over the
    pre-allocated arena, and emits ALERT/RENDER_UPDATE/DB_BATCH. Single process,
    single thread on the hot path (helper threads only for periodic reloads).

    With CORE_SHARDS > 1 the runtime starts it in two roles, named by ``config["_CORE_SHARD"]``.
    A shard (an int) does the per-flow work of its LAN devices (ledger rows, render, flows, policy,
    web classifier, signature and intel lookups) and sends one record per event to the merge on
    ``alert_queue``. The merge ("merge"; ``ingestion_queue`` is the tuple of shard queues) takes one
    SHARD_BATCH from every shard, restores capture order and runs everything keyed beyond one
    device (arena detectors, inventory, baseline, DNS, JA3, beacons, rate limits, the store and
    evidence) exactly as the single core does."""
    shard = config.get("_CORE_SHARD")
    run_flows = shard != "merge"  # per-packet flow work: the single core or a shard
    run_global = not isinstance(shard, int)  # cross-device state: the single core or the merge
    notices = shard in (None, 0)  # one process reports policy/signature file state, as the single core did
    log = setup_logging("core" if run_global else f"core-{shard}", config)
    security_store = security_store_from_config(config) if run_global else None
    log.info("allocating arena and loading rulesets...")

    class CoreMetrics:
        dropped_alerts = 0
        dropped_renders = 0
        dropped_db_batches = 0
        dropped_db_rows = 0
        evicted_active = 0
        last_log_time = time.time()
        last_render_log_time = time.time()
        last_eviction_alert_time = 0.0
        suppressed_eviction_alerts = 0
        last_capacity_emit_time = 0.0
        dropped_core_heartbeats = 0
        dropped_evidence_requests = 0
        dropped_policy_decisions = 0
        dropped_policy_responses = 0
        dropped_web_observations = 0
        event_faults = 0
        geo_faults = 0

    # GeoIP is enrichment, not a dependency of detection: a missing module or
    # database degrades country codes to "--" and must never stop the core.
    geo_reader = None
    try:
        if run_flows:  # the merge renders no rows
            import maxminddb

            geo_reader = maxminddb.open_database(config["GEO_DB"], maxminddb.MODE_MEMORY)
    except Exception as e:
        log.warning("GeoIP disabled (%s: %s); country codes will read '--'", type(e).__name__, e)
    geo_cache = {}  # destination text -> country code: a MODE_MEMORY lookup is pure Python, ~40 us a packet

    # Passive MAC device inventory (roadmap #1). Localized import like the other
    # process-specific deps. Degrades to None on any init failure — a fault here
    # must never take the analytics core down.
    inventory = None
    if run_global and config.get("DEVICE_INVENTORY_ENABLED", True):
        try:
            from netwatch_inventory import DeviceInventory, load_oui_db

            inventory = DeviceInventory(
                oui_db=load_oui_db(config.get("OUI_DB", "")),
                ledger_path=config.get("DEVICE_LEDGER"),
                alert_on_new=bool(config.get("DEVICE_NEW_ALERT", True)),
            )
        except Exception as e:
            log.error("device inventory disabled — init failed: %s: %s", type(e).__name__, e)
            inventory = None
    dev_save_interval = config.get("DEVICE_SAVE_INTERVAL_SEC", 10)
    last_dev_save = time.time()
    dev_new_sent = dev_new_dropped = dev_refused_seen = 0  # per save interval

    # Per-device egress baselining (roadmap #2). Accumulates each local device's
    # egress bytes per window, then scores the window against that device's learned
    # norm. Guarded like the inventory — a fault here never takes the core down.
    baseline = None
    if run_global and config.get("BASELINE_ENABLED", True):
        try:
            from netwatch_baseline import BaselineTracker

            baseline = BaselineTracker(
                alpha=config.get("BASELINE_ALPHA", 0.1),
                warmup=config.get("BASELINE_WARMUP", 10),
                z_threshold=config.get("BASELINE_Z", 4.0),
                rel_floor=config.get("BASELINE_REL_FLOOR", 0.15),
                abs_floor=config.get("BASELINE_ABS_FLOOR", 50_000),
                ledger_path=config.get("BASELINE_LEDGER"),
            )
        except Exception as e:
            log.error("baselining disabled — init failed: %s: %s", type(e).__name__, e)
            baseline = None
    baseline_window = config.get("BASELINE_WINDOW_SEC", 60)
    baseline_bytes = {}  # device MAC -> egress bytes accumulated this window
    last_baseline_flush = time.time()
    from netwatch_inventory import is_usable_mac, normalize_mac  # pure MAC helpers

    # The durable analyzers run in durable_analysis_process: in the packet loop their writes waited
    # out other processes' writer locks and the ingestion queue overflowed (the sensor, ~20k packets/s
    # dropped for 30 s). Packet-path alerts get a short busy wait here and fall back to the deferred
    # list, which the deferred-alerts thread retries on its own store connection.
    retry_store = None
    if run_global:  # a shard's few notices are published by the merge
        security_store.conn.execute(f"PRAGMA busy_timeout={ALERT_BUSY_TIMEOUT_MS}")
        retry_store = security_store_from_config(config)

    # DNS analytics (roadmap #4): DGA scoring, NXDOMAIN bursts, tunneling. Guarded.
    dns_analyzer = None
    if run_global and config.get("DNS_ANALYTICS_ENABLED", True):
        try:
            from netwatch_dns import DnsAnalyzer

            dns_analyzer = DnsAnalyzer(
                dga_threshold=config.get("DNS_DGA_THRESHOLD", 0.7),
                nxdomain_window_sec=config.get("DNS_NXDOMAIN_WINDOW_SEC", 30),
                nxdomain_threshold=config.get("DNS_NXDOMAIN_THRESHOLD", 10),
                ignore_suffixes=config.get("DNS_IGNORE_SUFFIXES", ()),
                tunnel_ignore_suffixes=config.get("DNS_TUNNEL_IGNORE_SUFFIXES", ()),
                tunnel_ignore_device_suffixes=config.get("DNS_TUNNEL_IGNORE_DEVICE_SUFFIXES", ()),
                ledger_path=config.get("DNS_LEDGER"),
            )
        except Exception as e:
            log.error("DNS analytics disabled — init failed: %s: %s", type(e).__name__, e)
            dns_analyzer = None
    last_dns_save = time.time()

    # JA3/JA3S TLS fingerprinting (roadmap #5): inventory fingerprints + match a
    # blocklist of known-bad JA3s (the seam for a JA3 threat-intel feed). Guarded.
    ja3watch = None
    if run_global and config.get("JA3_ENABLED", True):
        try:
            from netwatch_ja3 import Ja3Watch, load_blocklist

            ja3watch = Ja3Watch(
                blocklist=load_blocklist(config.get("JA3_BLOCKLIST", "")),
                ledger_path=config.get("JA3_LEDGER"),
            )
        except Exception as e:
            log.error("JA3 disabled — init failed: %s: %s", type(e).__name__, e)
            ja3watch = None
    last_ja3_save = time.time()

    # Threat-intel indicators (roadmap #6): the monitor only READS the local cache
    # written by threatintel_update.py — it never fetches. Hot-reloaded so a fresh
    # cache is picked up without a restart; JA3 indicators are merged into ja3watch.
    intel_box = [None]
    intel_cooldown = {}  # matched target -> last alert ts (rate-limit sustained hits)
    if config.get("THREATINTEL_ENABLED", True):
        try:
            from netwatch_threatintel import IndicatorSet

            # The file-backed blocklist is the immutable base. Each reload REBINDS
            # ja3watch.blocklist to base|feed rather than unioning in place: an
            # in-place |= can never drop a hash the feed retracted, and rebinding a
            # fresh set is atomic against the hot path reading it.
            ja3_base_blocklist = frozenset(ja3watch.blocklist) if ja3watch is not None else frozenset()

            def _load_intel():
                iset = IndicatorSet.load(config.get("THREATINTEL_CACHE", ""))
                if ja3watch is not None:
                    ja3watch.blocklist = set(ja3_base_blocklist) | iset.ja3_hashes()
                return iset if run_flows else None  # the merge keeps only the JA3 hashes, not the IP ranges

            if not os.path.exists(config.get("THREATINTEL_CACHE", "")):
                log.warning("threat-intel cache missing (%s); no indicators until threatintel_update.py runs",
                            config.get("THREATINTEL_CACHE", ""))
            try:
                intel_box[0] = _load_intel()
            except ValueError as exc:  # corrupt cache: stay up, the reloader retries
                log.error("threat-intel cache unreadable at boot: %s", exc)

            def intel_reloader():
                interval = config.get("THREATINTEL_RELOAD_SEC", 300)
                while shutdown_event is None or not shutdown_event.is_set():
                    time.sleep(interval)
                    try:
                        intel_box[0] = _load_intel()
                    except Exception as exc:
                        log.warning("threat-intel reload failed: %s: %s", type(exc).__name__, exc)

            threading.Thread(target=intel_reloader, daemon=True).start()
        except Exception as e:
            log.error("threat-intel disabled — init failed: %s: %s", type(e).__name__, e)
            intel_box[0] = None

    sig_file = config["SIG_FILE"]
    sig_box = [(set(), set(), set())]

    evidence_actions, evidence_gate = evidence_policy(config, log)

    deferred_alerts = []  # alerts the busy store refused; retried at the top of each loop

    def _send_alert(msg):
        if not run_global:  # a shard's notices reach the store through the merge
            if not try_put_no_drop(alert_queue, msg, timeout=1.0):
                CoreMetrics.dropped_alerts += 1
            return
        # A busy store must not kill the core: "database is locked" here restarted it (VM 2026-10-08).
        if publish_or_defer(security_store, alert_queue, msg, deferred_alerts, log) is False:
            CoreMetrics.dropped_alerts += 1
        _request_evidence(msg)

    def _request_evidence(msg):
        if not request_evidence(config, evidence_queue, evidence_actions, evidence_gate, msg):
            CoreMetrics.dropped_evidence_requests += 1

    def _emit_alert(action, message, target="SYSTEM", error=None, data=None):
        body = {"message": message}
        if isinstance(data, dict):
            body.update(data)
        msg = make_message("DOD_CORE", action, target, body, error=error)
        _send_alert(msg)

    def _select_victim_slot(current_time, keep=()):
        """Claim an arena slot. ``(index, was_forced)`` — forced means a slot that
        was still *fresh* had to be taken, i.e. the arena is genuinely too small.

        Slot selection used to be two full Python scans of the arena per
        allocation (4096 iterations at MAX_ENTITIES=2048) on a path hit by every
        previously-unseen endpoint — exactly the path a port scan or an IPv6
        address space hammers. A free list makes the common case O(1); the
        exhausted case falls back to one vectorised argmin instead of a scan."""
        if free_slots:
            return free_slots.pop(), False
        held = [(i, slot_last_access[i]) for i in keep]
        for i, _ in held:  # never the slot of the event's other endpoint, however stale it is
            slot_last_access[i] = np.inf
        idx = int(np.argmin(slot_last_access))
        for i, last in held:
            slot_last_access[i] = last
        return idx, (current_time - slot_last_access[idx] <= config["GC_STALE_SEC"])

    def signature_loader():
        sig_failed = False
        while shutdown_event is None or not shutdown_event.is_set():
            try:
                with open(sig_file) as f:
                    data = json.load(f)
                d = {str(i).strip().lower() for i in data.get("domains", [])}
                c = {str(i).strip().upper() for i in data.get("countries", [])}
                p = {int(i) for i in data.get("ports", []) if str(i).isdigit()}
                sig_box[0] = (d, c, p)
                if sig_failed and notices:
                    sig_failed = False
                    _emit_alert(
                        "SIGNATURE_UPDATE_RECOVERED",
                        f"SIGNATURE_UPDATE_RECOVERED: Intelligence restored from {sig_file}.",
                    )
            except Exception as e:
                if not sig_failed:
                    sig_failed = True
                    if notices:
                        _emit_alert(
                            "SIGNATURE_UPDATE_FAILED", f"SIGNATURE_UPDATE_FAILED: Read failure on {sig_file}.",
                            error=str(e),
                        )
            time.sleep(1.0)

    if run_flows:
        threading.Thread(target=signature_loader, daemon=True).start()

    from netwatch_capture import CaptureProgress

    core_progress = CaptureProgress()

    from netwatch_privilege import get_privilege_state

    privilege_state = get_privilege_state()

    def core_heartbeat_emitter():
        while shutdown_event is None or not shutdown_event.is_set():
            time.sleep(5)
            msg = make_message(
                "DOD_CORE" if run_global else f"DOD_CORE_{shard}",
                "WORKER_HEARTBEAT",
                "UI_SHELL",
                {"timestamp": time.time(), **core_progress.report(timeout=float(config.get("RUNTIME_HEARTBEAT_TIMEOUT_SEC", 10)), start_timeout=float(config.get("RUNTIME_START_GRACE_SEC", 120))), "privilege": privilege_state},
            )
            if not try_put_drop_oldest(worker_status_queue, msg):
                CoreMetrics.dropped_core_heartbeats += 1

    threading.Thread(target=core_heartbeat_emitter, daemon=True).start()

    MAX_ENTITIES = config["MAX_ENTITIES"] if run_global else 0  # the arena lives in the merge
    # The arena no longer stores the address (it was a uint32 — IPv4-only). The
    # endpoint key now lives in the ``slot_ip`` side-table as packed bytes (4=v4,
    # 16=v6); ``slot_ip[i] is None`` means the slot is free. Same fixed-size,
    # allocation-free design — just a Python list parallel to ``slot_last_access``.
    dtype = arena_dtype(config["DETECTOR_BUCKETS"])
    arena = np.zeros(MAX_ENTITIES, dtype=dtype)
    slot_last_access = np.zeros(MAX_ENTITIES, dtype="f8")
    slot_ip = [None] * MAX_ENTITIES  # slot index -> packed-bytes key (or None if free)
    free_slots = list(range(MAX_ENTITIES - 1, -1, -1))  # LIFO stack of unused slots
    ip_to_idx = {}
    sweep_targets = {}  # src -> {dst: None}, current sweep window only
    # Known scanners (the dev host's own LAN sweep): packed addresses, never port-sweep candidates.
    sweep_ignored = frozenset(ip_pack(str(ip)) for ip in config.get("SWEEP_IGNORE_SOURCES", ())) - {None}
    # {mac: [(networks, ports)]}: LAN UDP one known device sends to its peers' ports (Tailscale WireGuard
    # between the nodes) is a transfer, not a flood. Same entry shape as BEACON_IGNORE_DEVICE_ENDPOINTS.
    from netwatch_flow import accepted_egress_match, accepted_egress_rules, device_endpoint_rule

    udp_flood_ignored = {}
    for entry in config.get("UDP_FLOOD_IGNORE_DEVICE_ENDPOINTS", ()):
        if (parsed := device_endpoint_rule(entry)) is not None:
            udp_flood_ignored.setdefault(parsed[0], []).append(parsed[1:])

    # {mac: [(networks, start, end)]}: a scheduled bulk upload (e.g. a nightly off-site backup) is not
    # exfiltration inside its own local-time window; outside it, or to other networks, it still alerts.
    from netwatch_flow import device_window_rule, in_hours

    # Encrypted overlay transport (Tailscale WireGuard 41641) between the operator's own devices: its volume
    # is whatever the tunnel carries (a remote-desktop session), so flood and exfil counting skip it.
    tunnel_udp_ports = frozenset(int(p) for p in config.get("TUNNEL_UDP_PORTS") or ())

    exfil_windows = {}
    for entry in config.get("EXFIL_IGNORE_DEVICE_WINDOWS", ()):
        if (parsed := device_window_rule(entry)) is not None:
            exfil_windows.setdefault(parsed[0], []).append(parsed[1:])

    def exfil_exempt(mac, dst_key, now):
        rules = exfil_windows.get(str(mac or "").lower())
        if not rules:
            return False
        dst_ip, hour = ipaddress.ip_address(bytes(dst_key)), time.localtime(now).tm_hour
        return any(in_hours(hour, start, end) and any(dst_ip in net for net in nets) for nets, start, end in rules)

    def udp_flood_exempt(mac, dst_key, dport):
        rules = udp_flood_ignored.get(str(mac or "").lower())
        if not rules:
            return False
        dst_ip = ipaddress.ip_address(bytes(dst_key))
        return any((not ports or dport in ports) and any(dst_ip in net for net in nets) for nets, ports in rules)

    accepted_rules = accepted_egress_rules(config.get("ACCEPTED_EGRESS"))
    accepted_last = {}  # (rule, kind, dst) -> last info record time; expired rules are reported once

    def accept_egress(kind, mac, domain, dst, src_dotted, dst_dotted, now):
        """None when no live ACCEPTED_EGRESS entry covers this finding; else the info records (possibly none,
        when rate-limited) that replace it: logged as acknowledged, never an open case. A covering entry past
        its review_by date raises one expiry info case and the finding alerts as normal."""
        for index, rule in enumerate(accepted_rules):
            if not accepted_egress_match(rule, mac, domain, dst):
                continue
            if datetime.fromtimestamp(now).date() > rule["review_by"]:
                if (index, "expired", "") not in accepted_last:
                    accepted_last[(index, "expired", "")] = now
                    emit_accepted([(f"ACCEPTED_EGRESS expired {rule['review_by']}: {rule['note']}", "SYSTEM",
                                    {"expired": True})])
                continue
            if now - accepted_last.get((index, kind, dst), 0) < 60:
                return []
            accepted_last[(index, kind, dst)] = now
            return [(f"ACCEPTED_EGRESS {kind}: {src_dotted} ({mac}) -> {dst_dotted}; {rule['note']}", dst_dotted,
                     {"accepted": True, "src_ip": src_dotted, "src_mac": mac})]
        return None

    def emit_accepted(records):
        for msg, target, data in records:
            _emit_alert("ACCEPTED_EGRESS_EXPIRED" if data.get("expired") else "ACCEPTED_EGRESS", msg, target=target,
                        data={**data, "severity": "info"})

    batch = []
    observation_batch = []
    observation_buffer_max = max(1, int(config.get("WEB_OBSERVATION_BUFFER_MAX", 10_000)))
    last_commit = time.time()
    last_gc = time.time()
    last_flow_drain = time.time()
    last_policy_ledger_flush = time.time()
    coverage_active_sources = {}
    coverage_web_sources = {}
    coverage_window_sec = max(60.0, float(config.get("SENSOR_COVERAGE_WINDOW_SEC", 900)))
    coverage_emit_sec = max(1.0, float(config.get("SENSOR_COVERAGE_EMIT_SEC", 5)))
    last_coverage_emit = 0.0
    if run_global:
        log.info("arena: %d slots x %d B = %.1f MiB", MAX_ENTITIES, arena.itemsize, arena.nbytes / 1048576.0)

    local_prefixes = compile_v4_prefixes(config["LOCAL_PREFIXES"])
    local_prefixes6 = compile_v6_prefixes(config.get("LOCAL_PREFIXES6", ()))
    if config.get("LOCAL_PREFIXES6"):
        log.info("local IPv6 prefixes: %s", ", ".join(config["LOCAL_PREFIXES6"]))
    else:
        log.warning(
            "no local IPv6 prefixes configured — globally-routable LAN IPv6 "
            "will be treated as external (set LOCAL_PREFIXES6)"
        )

    def is_local(ip_key):
        return is_local_ip(ip_key, local_prefixes, local_prefixes6)

    detector_alert_gate = AlertGate(config["DETECTOR_ALERT_COOLDOWN_SEC"])
    exfil_alert_gate = AlertGate(config["EXFIL_ALERT_COOLDOWN_SEC"])

    beacon_wanted = bool(config.get("BEACONING_ENABLED", True))
    flow_tracker = beacon_detector = human_web_classifier = None
    if config.get("FLOW_TRACKING_ENABLED", True):
        try:
            from netwatch_flow import BeaconDetector, FlowTracker, HumanWebClassifier

            if run_flows:
                flow_tracker = FlowTracker(
                    max_flows=config.get("FLOW_MAX_ACTIVE", 100_000),  # per shard: one busy host keeps all its flows
                    tcp_idle_sec=config.get("FLOW_TCP_IDLE_SEC", 300),
                    udp_idle_sec=config.get("FLOW_UDP_IDLE_SEC", 60),
                )
                human_web_classifier = HumanWebClassifier(
                    max_flows=config.get("FLOW_MAX_ACTIVE", 100_000),
                    background_domains=config.get("WEB_BACKGROUND_DOMAINS", ()),
                    automation_sources=config.get("WEB_AUTOMATION_SOURCES", ()),
                )
            if run_global and beacon_wanted:
                beacon_detector = BeaconDetector(
                    min_samples=config.get("BEACON_MIN_SAMPLES", 6),
                    max_cv=config.get("BEACON_MAX_CV", 0.12),
                    min_period_sec=config.get("BEACON_MIN_PERIOD_SEC", 5),
                    max_period_sec=config.get("BEACON_MAX_PERIOD_SEC", 3600),
                    cooldown_sec=config.get("BEACON_COOLDOWN_SEC", 900),
                    ignored_udp_ports=config.get("BEACON_IGNORE_UDP_PORTS", ()),
                    ignored_domains=config.get("BEACON_IGNORE_DOMAINS", ()),
                    ignored_destinations=config.get("BEACON_IGNORE_DESTINATIONS", ()),
                    ignored_device_endpoints=config.get("BEACON_IGNORE_DEVICE_ENDPOINTS", ()),
                )
        except Exception as exc:
            log.error("flow tracking disabled — init failed: %s: %s", type(exc).__name__, exc)
            flow_tracker = beacon_detector = human_web_classifier = None

    policy_box = [None]
    policy_state = {}
    policy_mtime = [None]
    last_policy_reload = 0.0
    decision_ledger = None
    if config.get("POLICY_ENABLED", True):
        try:
            from netwatch_policy import DecisionLedger, PolicyEngine

            if run_flows:
                policy_box[0] = PolicyEngine.load(
                    config.get("POLICY_FILE"),
                    mode=config.get("POLICY_MODE", "monitor"),
                )
                policy_mtime[0] = os.path.getmtime(config.get("POLICY_FILE"))
            if run_global:  # the merge writes every shard's decisions, in capture order
                decision_ledger = DecisionLedger(
                    config.get("POLICY_DECISION_LEDGER"),
                    max_bytes=config.get("POLICY_LEDGER_MAX_BYTES", 20_000_000),
                )
            if run_flows:
                log.info(
                    "policy v%d loaded (%s, %d rules, %.12s)",
                    policy_box[0].version,
                    policy_box[0].mode,
                    len(policy_box[0].rules),
                    policy_box[0].digest,
                )
        except Exception as exc:
            if notices or shard == "merge":
                _emit_alert("POLICY_LOAD_FAILED", f"POLICY_LOAD_FAILED: {type(exc).__name__}: {exc}")

    def _external_of(src_key, dst_key):
        """The endpoint an alert should be attributed to: the non-local side of the
        flow, so mitigation acts on the remote host and never on the LAN."""
        if not is_local(dst_key):
            return dst_key
        if not is_local(src_key):
            return src_key
        return src_key

    analysis_stop = threading.Event()

    def deferred_alerts_retry():
        while not analysis_stop.wait(0.5):
            try:
                retry_deferred(retry_store, alert_queue, deferred_alerts, log)
            except Exception as exc:  # one bad turn must not end the retries
                log.error("deferred alert retry failed: %s: %s", type(exc).__name__, exc)

    analysis_thread = threading.Thread(target=deferred_alerts_retry, name="deferred-alerts", daemon=True)
    if run_global:
        analysis_thread.start()

    def observe_global(record, current_loop_time):
        """Cross-device analytics for one event, in capture order: the arena detectors, inventory,
        baseline, DNS, JA3, beacons and every rate limit. Returns True if an arena detector or a
        signature alerted (the render row's flag). The single core calls it per event; the merge
        per shard record."""
        nonlocal dev_new_sent, dev_new_dropped, intel_cooldown
        (_, src, dst, src_dotted, dst_dotted, current_time, size, dport, sport, protocol, mac_src, mac_dst,
         src_local, dst_local, outbound_web, tcp_flags, extra) = record
        policy_item, beacon_item, dns_item, ja3_item, intel_item, signature_msgs = extra or NO_EXTRA

        # Resolve each endpoint to an arena slot, allocating (and evicting) as needed.
        keys_to_allocate = []
        if src not in ip_to_idx:
            keys_to_allocate.append(src)
        if dst not in ip_to_idx and dst != src:
            keys_to_allocate.append(dst)

        keep = [ip_to_idx[key] for key in (src, dst) if key in ip_to_idx]
        for ip_key in keys_to_allocate:
            target_slot, was_forced = _select_victim_slot(current_loop_time, keep)
            keep.append(target_slot)
            old_ip = slot_ip[target_slot]
            if old_ip is not None:
                row = arena[target_slot]
                vol_active = row["vol_state"][1] > 0
                udp_active = row["udp_state"][1] > 0
                sweep_active = row["sweep_state"][1] > 0
                if vol_active or udp_active or sweep_active:
                    CoreMetrics.evicted_active += 1
                    if was_forced:
                        categories = ",".join(
                            c
                            for c, a in (("VOL", vol_active), ("UDP", udp_active), ("SWEEP", sweep_active))
                            if a
                        )
                        evicted_ip = ip_str(old_ip)
                        if current_loop_time - CoreMetrics.last_eviction_alert_time >= 1.0:
                            suffix = (
                                f" (+{CoreMetrics.suppressed_eviction_alerts} suppressed)"
                                if CoreMetrics.suppressed_eviction_alerts > 0
                                else ""
                            )
                            _emit_alert(
                                "ARENA_EVICTION_ACTIVE",
                                f"ARENA_EVICTION_ACTIVE: {evicted_ip} discarded active state [{categories}]{suffix}",
                            )
                            CoreMetrics.last_eviction_alert_time = current_loop_time
                            CoreMetrics.suppressed_eviction_alerts = 0
                        else:
                            CoreMetrics.suppressed_eviction_alerts += 1
                if ip_to_idx.get(old_ip) == target_slot:
                    del ip_to_idx[old_ip]

            slot_ip[target_slot] = ip_key
            arena[target_slot] = np.zeros((), dtype=arena.dtype)
            ip_to_idx[ip_key] = target_slot
            slot_last_access[target_slot] = current_loop_time

        s_idx, d_idx = ip_to_idx[src], ip_to_idx[dst]
        slot_last_access[s_idx] = current_time
        slot_last_access[d_idx] = current_time
        alert_msgs = []  # (message, packed-address the alert is about)

        if policy_item is not None:
            decision, response, respond = policy_item
            if decision is not None and decision_ledger is not None:
                if not decision_ledger.append(decision):
                    CoreMetrics.dropped_policy_decisions += 1
            if response is not None:
                _send_alert(response)
                if respond and not try_put_no_drop(policy_queue, response, timeout=0.05):
                    CoreMetrics.dropped_policy_responses += 1
                    log.critical("policy response backlog full; verdict retained in audit ledger")
        if beacon_detector is not None and beacon_item is not None:
            beacon_flow, community_id = beacon_item
            beacon = beacon_detector.observe(beacon_flow, current_time)
            accepted = (accept_egress("beacon", mac_src, beacon_flow.get("domain"), dst, src_dotted, dst_dotted,
                                      current_time) if beacon is not None else None)
            if accepted is not None:
                emit_accepted(accepted)
            elif beacon is not None:
                bmsg = (
                    f"BEACONING: {src_dotted} -> {dst_dotted}:"
                    f"{beacon['port']} every {beacon['period_sec']:.1f}s "
                    f"(jitter {beacon['jitter_cv']:.3f}, {beacon['samples']} samples)"
                )
                _emit_alert(
                    "BEACON_ANOMALY",
                    bmsg,
                    target=dst,
                    data={**beacon, "severity": "alert", "community_id": community_id},
                )
        # Inbound QUIC (an external server's UDP/443 to a local client) is a download, not a flood.
        tunnel = protocol == "UDP" and (sport in tunnel_udp_ports or dport in tunnel_udp_ports)
        if (protocol == "UDP" and not tunnel and not (sport == 443 and dst_local and not src_local)
                and not (dst_local and udp_flood_exempt(mac_src, dst, dport))):
            res = analyze_udp_flood(arena[s_idx], current_time, config, src_dotted)
            if res and detector_alert_gate.allow("udp", src, current_time):
                alert_msgs.append((res, src))
        sweep = arena[s_idx]["sweep_state"]
        track_sweep_target(sweep_targets, src, dst_dotted,
                           sweep[1] == 0 or abs(current_time - sweep[0]) > config["SWEEP_WINDOW_SEC"])
        res = None if src in sweep_ignored else analyze_port_sweep(
            arena[s_idx], current_time, config, src_dotted, dport, sport, tcp_flags)
        if res:
            targets = sweep_targets.pop(src, {})
            if detector_alert_gate.allow("sweep", src, current_time):
                alert_msgs.append((res, src, {"target_ips": list(targets),
                                              "distinct_ports": config["SWEEP_THRESHOLD_PORTS"] + 1}))
        # Exfiltration is a property of the SENDER, and only of traffic
        # actually leaving the network. Accumulating on the destination row
        # counted every inbound byte as egress, so any ordinary download
        # crossing EXFIL_THRESHOLD_BYTES alerted against the local host.
        if src_local and not dst_local and not tunnel:
            res = analyze_volumetric_exfil(arena[s_idx], current_time, config, dst_dotted, size)
            if (res and not exfil_exempt(mac_src, dst, current_time)
                    and exfil_alert_gate.allow("exfil", (src, dst), current_time)):
                alert_msgs.append((f"{res} by {src_dotted}", dst))

        # [DEVICE INVENTORY] passively record both endpoints' MACs, associating
        # the IP only when it is local (so a remote IP behind the gateway's MAC
        # is not mis-attributed). A first sighting raises a NEW-DEVICE notice.
        if inventory is not None:
            for mac_obs, ip_dotted_obs, ip_local_obs in (
                (mac_src, src_dotted, src_local),
                (mac_dst, dst_dotted, dst_local),
            ):
                dev = inventory.observe(mac_obs, ip_dotted_obs if ip_local_obs else None, current_time)
                if dev and dev["new_device"] and dev_new_sent >= 20:
                    dev_new_dropped += 1  # flood guard: rolled into the save-tick summary
                elif dev and dev["new_device"]:
                    dev_new_sent += 1
                    loc = f" @ {dev['ip']}" if dev["ip"] else ""
                    _emit_alert(
                        "DEVICE_NEW", f"NEW DEVICE: {dev['mac']} [{dev['vendor']}]{loc}", target="UI_SHELL"
                    )

        # [BASELINE] accumulate a local device's egress bytes for the window.
        # Egress = the device is the source; only local senders are baselined.
        if baseline is not None and src_local and is_usable_mac(mac_src):
            bkey = normalize_mac(mac_src)
            baseline_bytes[bkey] = baseline_bytes.get(bkey, 0) + size
        if src_local and is_usable_mac(mac_src):
            coverage_active_sources[normalize_mac(mac_src)] = current_time
            if outbound_web:
                coverage_web_sources[normalize_mac(mac_src)] = current_time

        # [DNS ANALYTICS] DGA / NXDOMAIN-burst / tunneling, on DNS packets only.
        if dns_analyzer is not None and dns_item is not None:
            for finding in dns_analyzer.observe(src_dotted, dst_dotted, *dns_item, current_time, src_mac=mac_src):
                dns_payload = make_message(
                    "DOD_CORE",
                    "DNS_ANOMALY",
                    "UI_SHELL",
                    {
                        "message": finding["message"],
                        "severity": finding["severity"],
                        "evidence_key": f"{finding['kind']}:{finding['host']}",
                    },
                )
                _send_alert(dns_payload)

        # [JA3] inventory TLS fingerprints; alert on a blocklist hit. ja3 is the
        # client (keyed to src), ja3s the server (keyed to src = the server).
        if ja3watch is not None and ja3_item is not None:
            sni, fingerprints = ja3_item
            for fp_hash, fp_kind in fingerprints:
                hit = ja3watch.observe(fp_hash, fp_kind, sni, src_dotted, current_time)
                if hit:
                    ja3_payload = make_message(
                        "DOD_CORE",
                        "JA3_ANOMALY",
                        "UI_SHELL",
                        {"message": hit["message"], "severity": hit["severity"]},
                    )
                    _send_alert(ja3_payload)

        # [THREAT INTEL] the packet's match (flow side) rate-limited per target, sensor-wide.
        if intel_item is not None:
            hit_msg, hit_target = intel_item
            if current_time - intel_cooldown.get(hit_target, 0) >= 60:
                if len(intel_cooldown) > 4096:
                    intel_cooldown = {k: t for k, t in intel_cooldown.items() if current_time - t < 60}
                intel_cooldown[hit_target] = current_time
                _emit_alert("ALERT", hit_msg, target=hit_target)

        alert_msgs.extend(signature_msgs)
        for msg, alert_target, *extra_data in alert_msgs:
            if extra_data and extra_data[0].get("accepted"):  # an ACCEPTED_EGRESS info record, never an alert
                emit_accepted([(msg, alert_target, extra_data[0])])
                continue
            _emit_alert("ALERT", msg, target=alert_target, data=extra_data[0] if extra_data else None)
        return bool(alert_msgs)

    def forward_records(records, seq):
        """A shard's records for one ingest batch. The merge reads every shard's in lock-step, so none may
        be dropped: a merge that stops reading leaves this loop stalled for the supervisor to replace.
        Only once stopping does a merge that has not read for MERGE_STOP_WAIT_SEC count as gone."""
        message = make_message("DOD_CORE", "SHARD_BATCH", "DOD_CORE", {"records": records, "seq": seq})
        refused_since, refused = None, 0
        while not try_put_no_drop(alert_queue, message, timeout=1.0):
            refused += 1  # one per 1 s attempt; the desktop never replaces a stalled generation, so say so
            if refused == MERGE_STALL_WARN_SEC or (refused > MERGE_STALL_WARN_SEC and refused % 60 == 0):
                log.warning("merge not reading for %d s; %d record(s) waiting (no drop)", refused, len(records))
            if shutdown_event is not None and shutdown_event.is_set():
                refused_since = refused_since or time.monotonic()
                if time.monotonic() - refused_since >= MERGE_STOP_WAIT_SEC:
                    log.error("merge not reading at stop: %d record(s) not analysed", len(records))
                    alert_queue.cancel_join_thread()  # its unread backlog must not hold this exit either
                    return

    def forward_drops():
        """A shard's IPC drop counters, summed into the merge's one IPC_DROP report."""
        drops = {name: getattr(CoreMetrics, name) for name in SHARD_DROP_COUNTERS if getattr(CoreMetrics, name)}
        if drops and try_put_no_drop(alert_queue, make_message("DOD_CORE", "SHARD_METRICS", "DOD_CORE", drops),
                                     timeout=1.0):
            for name in drops:
                setattr(CoreMetrics, name, 0)

    def run_round(parts, current_loop_time):
        """Merge one ingest chunk: every shard's records back in capture order, then the global analytics."""
        nonlocal batches_total, events_total
        records = sorted((record for part in parts if part for record in part["records"]), key=itemgetter(0))
        batches_total += 1
        events_total += len(records)
        if records:
            core_progress.packet_seen()
        for record in records:
            try:
                observe_global(record, current_loop_time)
            except Exception as e:
                if not CoreMetrics.event_faults:
                    log.error("event fault: %s: %s", type(e).__name__, e)
                CoreMetrics.event_faults += 1

    def merge_side(payload):
        """A shard message that is not part of a round: its drop counters, or a notice to publish."""
        if payload["action"] == "SHARD_METRICS":
            for name, count in payload["data"].items():
                if name in SHARD_DROP_COUNTERS:
                    setattr(CoreMetrics, name, getattr(CoreMetrics, name) + int(count))
        else:
            _send_alert(payload)

    tp_wall, tp_cpu, tp_events, tp_batches = time.monotonic(), time.process_time(), 0, 0
    events_total = batches_total = 0
    merge_queues = tuple(ingestion_queue) if shard == "merge" else ()
    parts = [None] * len(merge_queues)  # the merge's round in progress: one SHARD_BATCH per shard
    last_chunk, out_of_step = None, False
    while True:
        current_loop_time = time.time()
        if not any(parts):  # a merge holding part of a round is waiting on a shard, not progressing
            core_progress.read_complete()
        wall = time.monotonic()
        if wall - tp_wall >= THROUGHPUT_LOG_SEC:
            span, cpu = wall - tp_wall, time.process_time()
            try:
                depth = sum(q.qsize() for q in merge_queues) if merge_queues else ingestion_queue.qsize()
            except NotImplementedError:  # e.g. macOS multiprocessing queues
                depth = -1
            log.info("throughput: events_per_sec=%.1f batches=%d cpu_pct=%.1f ingest_queue=%d",
                     (events_total - tp_events) / span, batches_total - tp_batches,
                     100.0 * (cpu - tp_cpu) / span, depth)
            tp_wall, tp_cpu, tp_events, tp_batches = wall, cpu, events_total, batches_total
        records = None  # a shard's records for this batch, forwarded even if the batch faults
        try:
            if merge_queues:
                shard_index = parts.index(None)
                payload = merge_queues[shard_index].get(timeout=0.5)
                if not is_message_payload(payload):
                    continue
                if payload["action"] != "SHARD_BATCH":
                    merge_side(payload)
                    continue
                parts[shard_index] = payload["data"]
                if None in parts:
                    continue
                round_parts, parts = parts, [None] * len(merge_queues)
                chunks = {part.get("seq") for part in round_parts}
                if len(chunks) != 1 or (last_chunk is not None and chunks != {last_chunk + 1}):
                    # A lost or garbled part would mix chunks: fail like a dead shard, so the generation is replaced.
                    log.critical("shard batches out of step: chunks %s after %s", sorted(chunks, key=str), last_chunk)
                    out_of_step = True
                    break
                last_chunk = chunks.pop()
                run_round(round_parts, current_loop_time)  # then the periodic work, as after a core batch

            else:
                threat_domains, threat_countries, threat_ports = sig_box[0]

                payload = ingestion_queue.get(timeout=0.5)
                if not is_message_payload(payload):
                    continue
                core_progress.packet_seen()

                # ARP is consumed from the durable native stream, never this queue.
                if payload["action"] != "INGEST_PACKET":
                    continue
                if not run_global:
                    records, records_seq = [], payload["data"].get("seq")

                # Packets arrive batched (one IPC message per N packets). Each event is
                # independently guarded so one malformed member cannot discard the rest
                # of the batch.
                events = payload["data"].get("events")
                if not isinstance(events, list):
                    continue
                index = payload["data"].get("index")  # sharded: each event's position in the capture chunk
                batches_total += 1
                events_total += len(events)
                render_events = []
                web_candidates = []

                for evt_index, evt_data in enumerate(events):
                    try:
                        src, dst, size, dport, protocol, current_time = (
                            evt_data["src_ip"],
                            evt_data["dst_ip"],
                            evt_data["size_bytes"],
                            evt_data["port"],
                            evt_data["protocol"],
                            evt_data["timestamp"],
                        )

                        # The ledger row comes first: an analyser fault below must not lose the packet's row.
                        # Text form (v4 dotted / v6 colon) derived once from the packed keys;
                        # used for alert messages, geo lookup, DB rows, and render payloads.
                        src_dotted = ip_str(src)
                        dst_dotted = ip_str(dst)

                        country_code = geo_cache.get(dst_dotted)
                        if country_code is None:
                            country_code = "--"
                            if geo_reader:
                                try:
                                    geo_data = geo_reader.get(dst_dotted)
                                    if geo_data and "country" in geo_data:
                                        country_code = geo_data["country"]["iso_code"]
                                except ValueError:
                                    CoreMetrics.geo_faults += 1  # cached below, so once per destination
                            if len(geo_cache) >= GEO_CACHE_MAX:
                                geo_cache.clear()
                            geo_cache[dst_dotted] = country_code

                        # Rows in a batch share one correlation id, so the ledger's primary
                        # key needs the per-event suffix to stay unique.
                        event_id = f"{payload['correlation_id']}-{evt_index}"
                        batch.append(
                            (
                                event_id,
                                current_time,
                                evt_data["mac_src"],
                                evt_data["mac_dst"],
                                src_dotted,
                                dst_dotted,
                                protocol,
                                dport,
                                evt_data["tcp_flags"],
                                evt_data["ttl"],
                                size,
                                evt_data["sni_domain"],
                                country_code,
                                1,
                                *packet_row_key(evt_data),
                            )
                        )

                        src_local, dst_local = is_local(src), is_local(dst)
                        flow_snapshot = None
                        web_observation = None
                        policy_decision = policy_item = beacon_item = None
                        direction = (
                            "egress"
                            if src_local and not dst_local
                            else "ingress"
                            if not src_local and dst_local
                            else "lateral"
                            if src_local and dst_local
                            else "any"
                        )
                        if flow_tracker is not None:
                            flow_snapshot, flow_created = flow_tracker.observe(
                                evt_data,
                                src_local=src_local,
                                dst_local=dst_local,
                            )
                            direction = flow_snapshot["observation_direction"]
                            policy = policy_box[0]
                            policy_key = None
                            if policy is not None:
                                policy_key = (
                                    policy.digest,
                                    flow_snapshot["identity_revision"],
                                )
                            flow_policy_state = policy_state.setdefault(flow_snapshot["flow_id"], {})
                            if policy is not None and flow_policy_state.get(direction) != policy_key:
                                context = {
                                    **flow_snapshot,
                                    "src_ip": src,
                                    "dst_ip": dst,
                                    "source_port": int(evt_data.get("source_port") or 0),
                                    "destination_port": int(evt_data.get("port") or 0),
                                    "source_mac": str(evt_data.get("mac_src") or ""),
                                    "direction": direction,
                                }
                                policy_decision = policy.evaluate(context, current_time)
                                flow_policy_state[direction] = policy_key
                                # Audit ledger entry, then the response; both land in capture order with the global analytics.
                                audited = (policy_decision["rule_id"] != "default"
                                           or policy_decision["configured_action"] != "allow")
                                response = None
                                if policy_decision["effective_action"] != "allow":
                                    target = dst if direction == "egress" else src
                                    configured = policy_decision["configured_action"].upper()
                                    pmsg = (
                                        f"POLICY {configured}: {policy_decision['rule_id']} · "
                                        f"{src_dotted}:{context['source_port']} -> "
                                        f"{dst_dotted}:{context['destination_port']}"
                                    )
                                    response = make_message(
                                        "DOD_CORE",
                                        "POLICY_DECISION",
                                        target,
                                        {
                                            "message": pmsg,
                                            **policy_decision,
                                            "community_id": detection_community_id(evt_data, src, dst),
                                            "severity": "critical"
                                            if (
                                                policy_decision["configured_action"] == "block"
                                                and policy_decision["mode"] == "enforce"
                                            )
                                            else "alert",
                                        },
                                    )
                                if audited or response is not None:
                                    policy_item = (
                                        policy_decision if audited else None,
                                        response,
                                        policy_decision["configured_action"] == "block"
                                        and policy_decision["mode"] in {"manual", "enforce"},
                                    )
                            if beacon_wanted and flow_snapshot["first_local_egress"]:
                                beacon_item = ({
                                    **flow_snapshot,
                                    "src_ip": src,
                                    "dst_ip": dst,
                                    "source_port": int(evt_data.get("source_port") or 0),
                                    "destination_port": int(evt_data.get("port") or 0),
                                    "src_local": True,
                                    "dst_local": False,
                                    "first_seen": current_time,
                                    "source_mac": str(evt_data.get("mac_src") or ""),
                                }, detection_community_id(evt_data, src, dst))

                        dns_item = ((evt_data.get("dns_qname"), evt_data["dns_qr"], evt_data.get("dns_rcode"),
                                     evt_data.get("dns_qtype")) if evt_data.get("dns_qr") is not None else None)
                        fingerprints = tuple((fp_hash, fp_kind) for fp_hash, fp_kind in (
                            (evt_data.get("ja3"), "ja3"),
                            (evt_data.get("ja3s"), "ja3s"),
                            (evt_data.get("ja4"), "ja4"),
                        ) if fp_hash)
                        ja3_item = (evt_data["sni_domain"], fingerprints) if fingerprints else None

                        # [THREAT INTEL] match endpoints/domain against the loaded blocklists. An
                        # IP hit targets the bad EXTERNAL ip (so mitigation can block it); emitted
                        # as a normal ALERT (mitigation-eligible) and rate-limited per target.
                        # Only PUBLIC endpoints are IP-matched: feeds like firehol_level1 embed
                        # bogon/RFC1918 ranges (10/8, 172.16/12, 192.168/16), so a LAN endpoint
                        # would otherwise false-positive on essentially every flow. This mirrors
                        # the inventory/baseline locality guards above and the mitigation allowlist.
                        intel = intel_box[0]
                        intel_item = None
                        if intel is not None:
                            hit_msg, hit_target = None, src
                            if not dst_local and is_global_ip(dst) and (dst_hit := intel.match_ip(dst)):
                                hit_msg, hit_target = f"THREAT INTEL: egress to {dst_dotted} on {dst_hit} blocklist", dst
                            elif not src_local and is_global_ip(src) and (src_hit := intel.match_ip(src)):
                                hit_msg = f"THREAT INTEL: traffic from {src_dotted} on {src_hit} blocklist"
                            elif dom_hit := intel.match_domain(evt_data["sni_domain"]):
                                # target the LAN source: dst is a resolver or shared CDN IP, not the offender
                                hit_msg = f"THREAT INTEL: {evt_data['sni_domain']} on {dom_hit} blocklist"
                            if hit_msg:
                                intel_item = (hit_msg, hit_target)

                        signature_msgs = []
                        domain_lower = evt_data["sni_domain"].lower()
                        if domain_lower in threat_domains:
                            signature_msgs.append(
                                (f"THREAT DOMAIN: {src_dotted} -> {evt_data['sni_domain']}", _external_of(src, dst))
                            )
                        # A known scanner (the dev host's own LAN sweep) touching LAN telnet/RDP/FTP is the sweep itself.
                        if dport in threat_ports and not (src in sweep_ignored and dst_local):
                            signature_msgs.append((f"THREAT PORT: Restricted port {dport} accessed", _external_of(src, dst)))
                        if country_code in threat_countries:
                            signature_msgs.append((f"GEO-THREAT: Egress to {country_code} from {src_dotted} ({evt_data['mac_src']})",
                                                   dst, {"src_ip": src_dotted, "src_mac": evt_data["mac_src"]}))

                        outbound_web = (
                            (src_local and not dst_local and (protocol, dport) in HumanWebClassifier.WEB_PORTS)
                            if human_web_classifier is not None
                            else False
                        )
                        # ACCEPTED_EGRESS: a listed device's threat-intel / egress-country finding becomes an info record.
                        accepted = []
                        if intel_item is not None or country_code in threat_countries:
                            mac_text = str(evt_data.get("mac_src") or "")
                            kinds = (("threat-intel", intel_item is not None), ("egress-country", country_code in threat_countries))
                            for kind, hit in kinds:
                                if hit and (acc := accept_egress(kind, mac_text, evt_data["sni_domain"], dst,
                                                                 src_dotted, dst_dotted, current_time)) is not None:
                                    accepted.extend(acc)
                                    if kind == "threat-intel":
                                        intel_item = None
                                    else:
                                        signature_msgs = [m for m in signature_msgs if not m[0].startswith("GEO-THREAT")]
                        signature_msgs.extend(accepted)
                        extra = (policy_item, beacon_item, dns_item, ja3_item, intel_item, signature_msgs)
                        record = (
                            evt_index if index is None else index[evt_index],
                            src, dst, src_dotted, dst_dotted, current_time, size, dport,
                            int(evt_data.get("source_port") or 0), protocol, evt_data["mac_src"], evt_data["mac_dst"],
                            src_local, dst_local, outbound_web,
                            evt_data.get("tcp_flags") if protocol == "TCP" else None,
                            extra if any(extra) else None,
                        )
                        if records is None:
                            alerted = observe_global(record, current_loop_time)
                        else:
                            records.append(record)  # the merge cannot flag this row: it alerts after the render
                            alerted = bool(signature_msgs)

                        ttl = evt_data.get("ttl", 0)
                        os_guess = ttl_profile(
                            ttl,
                            config["OS_THRESHOLD_NIX"],
                            config["OS_THRESHOLD_WIN"],
                        )

                        render_data = {
                            "event_id": event_id,
                            "timestamp": current_time,
                            "time_str": clock_text(current_time),
                            "os_guess": os_guess,
                            "mac": evt_data["mac_src"],
                            "mac_dst": evt_data["mac_dst"],
                            "src": src,
                            "dst": dst,
                            "protocol": protocol,
                            "port": dport,
                            "flags": evt_data["tcp_flags"],
                            "size": size,
                            "domain": evt_data["sni_domain"],
                            "country": country_code,
                            "alert": alerted
                            or (policy_decision is not None and policy_decision["effective_action"] != "allow"),
                            "is_lan_to_lan": src_local and dst_local,
                            "direction": direction,
                            "flow_id": flow_snapshot.get("flow_id") if flow_snapshot else "",
                            "ja4": evt_data.get("ja4"),
                            "web_observation": web_observation,
                        }
                        render_data.update(
                            {
                                key: evt_data.get(key)
                                for key in (
                                    "source_port",
                                    "sensor_id",
                                    "vlan_ids",
                                    "ip_protocol",
                                    "fragmented",
                                    "non_initial_fragment",
                                    "icmp_type",
                                    "icmp_code",
                                )
                            }
                        )
                        render_data["capture_interface"] = evt_data.get("interface")
                        render_data["event_version"] = 2
                        render_events.append(render_data)
                        if human_web_classifier is not None and flow_snapshot is not None:
                            dns_query = src_local and evt_data.get("dns_qr") == 0
                            web_phase = (
                                flow_snapshot["first_local_egress"]
                                or flow_snapshot["identity_changed"]
                                or int(flow_snapshot.get("packets_up") or 0) >= 3
                                or int(flow_snapshot.get("packets_down") or 0) >= 1
                            )
                            if dns_query or (outbound_web and web_phase):
                                web_candidates.append(
                                    (
                                        len(render_events) - 1,
                                        evt_data,
                                        flow_snapshot,
                                        src_local,
                                        dst_local,
                                    )
                                )
                    except Exception as e:
                        # A single faulting event must not kill the analytics loop. Log the first
                        # in each second; the 1 s metrics block reports the count.
                        if not CoreMetrics.event_faults:
                            log.error("event fault: %s: %s", type(e).__name__, e)
                        CoreMetrics.event_faults += 1

                render_observations = []
                for render_index, candidate, flow, candidate_src_local, candidate_dst_local in web_candidates:
                    observation = human_web_classifier.observe(
                        candidate,
                        flow,
                        src_local=candidate_src_local,
                        dst_local=candidate_dst_local,
                    )
                    render_events[render_index]["web_observation"] = observation
                    if observation is None:
                        continue
                    observed_event = render_events[render_index]
                    render_observations.append(observed_event)
                    observation_batch.append(
                        (
                            observation["flow_id"],
                            observation["started_at"],
                            ip_str(observed_event["src"]),
                            ip_str(observed_event["dst"]),
                            observed_event["mac"],
                            observed_event["mac_dst"],
                            observed_event["protocol"],
                            observed_event["port"],
                            observation.get("domain", ""),
                            observation["label"],
                            observation["score"],
                            observation.get("reason", ""),
                            observed_event["os_guess"],
                            observed_event["country"],
                            observed_event["size"],
                        )
                    )
                    overflow = len(observation_batch) - observation_buffer_max
                    if overflow > 0:
                        del observation_batch[:overflow]
                        CoreMetrics.dropped_web_observations += overflow

                if render_events:
                    r_msg = make_message(
                        "DOD_CORE",
                        "RENDER_BATCH",
                        0,
                        {
                            "events": render_events,
                            "observations": render_observations,
                            "total_ingested": len(events),
                        },
                        correlation_id=payload["correlation_id"],
                    )
                    accepted, evicted = try_put_drop_oldest_with_eviction(render_queue, r_msg)
                    if evicted and is_message_payload(evicted) and evicted["action"] == "RENDER_BATCH":
                        old_events = evicted["data"].get("events")
                        if isinstance(old_events, list):
                            CoreMetrics.dropped_renders += len(old_events)
                    if not accepted:
                        CoreMetrics.dropped_renders += len(render_events)

        except queue.Empty:
            if shutdown_event is not None and shutdown_event.is_set():
                break
        except Exception as e:
            log.error("batch fault: %s: %s", type(e).__name__, e)
        finally:
            if records is not None:
                forward_records(records, records_seq)

        # BOUNDED DB OFFLOAD WITH STRICT IPC. Unlike the render/alert paths this one
        # must NOT drop-oldest: evicting a batch the queue already accepted discards
        # persisted evidence silently. Refuse the new batch loudly instead.
        if len(batch) >= config["DB_BATCH_CEILING"] or (current_loop_time - last_commit > 1.0 and len(batch) > 0):
            db_rows = encode_packet_rows(compact_event_rows(batch))
            db_payload = make_db_batch_message(db_rows, observation_batch)
            db_accepted = try_put_no_drop(db_queue, db_payload)
            if not db_accepted:
                CoreMetrics.dropped_db_batches += 1
                CoreMetrics.dropped_db_rows += sum(row[13] for row in db_rows)
            batch.clear()
            if db_accepted:
                observation_batch.clear()
            last_commit = current_loop_time

        if run_global and current_loop_time - last_coverage_emit >= coverage_emit_sec:
            cutoff = current_loop_time - coverage_window_sec
            coverage_active_sources = {mac: seen for mac, seen in coverage_active_sources.items() if seen >= cutoff}
            coverage_web_sources = {mac: seen for mac, seen in coverage_web_sources.items() if seen >= cutoff}
            coverage_message = make_message(
                "DOD_CORE",
                "SENSOR_COVERAGE",
                "UI_SHELL",
                {
                    "active_sources": len(coverage_active_sources),
                    "web_sources": len(coverage_web_sources),
                    "window_sec": coverage_window_sec,
                    "topology": str(config.get("CAPTURE_TOPOLOGY", "endpoint")),
                    "coverage_assertion": str(config.get("CAPTURE_COVERAGE_ASSERTION", "unverified")),
                },
            )
            try_put_drop_oldest(worker_status_queue, coverage_message)
            last_coverage_emit = current_loop_time

        try:
            if flow_tracker is not None and current_loop_time - last_flow_drain >= 1.0:
                for flow in flow_tracker.drain_evicted():
                    policy_state.pop(flow["flow_id"], None)
                if flow_tracker.evicted_dropped:  # snapshots lost: drop policy state of every flow no longer live
                    live = {flow["flow_id"] for flow in flow_tracker.flows.values()}
                    for flow_id in policy_state.keys() - live:
                        del policy_state[flow_id]
                    log.warning("flow eviction backlog dropped %d snapshots", flow_tracker.evicted_dropped)
                    flow_tracker.evicted_dropped = 0
                last_flow_drain = current_loop_time
        except Exception as e:
            log.error("flow drain failed: %s: %s", type(e).__name__, e)

        if decision_ledger is not None and current_loop_time - last_policy_ledger_flush >= 1.0:
            if not decision_ledger.flush():
                log.error("policy decision ledger flush failed; buffered decisions retained")
            last_policy_ledger_flush = current_loop_time

        # Return long-idle slots to the free list so allocation stays O(1) instead of
        # degrading to an argmin scan once the arena has been touched everywhere.
        try:
            if current_loop_time - last_gc >= config["GC_INTERVAL_SEC"]:
                stale_threshold = config["GC_STALE_SEC"]
                for idx in np.flatnonzero(current_loop_time - slot_last_access > stale_threshold):
                    idx = int(idx)
                    old_ip = slot_ip[idx]
                    if old_ip is None:
                        continue
                    if ip_to_idx.get(old_ip) == idx:
                        del ip_to_idx[old_ip]
                    slot_ip[idx] = None
                    free_slots.append(idx)
                if flow_tracker is not None:
                    for flow in [*flow_tracker.drain_evicted(), *flow_tracker.expire(current_loop_time)]:
                        policy_state.pop(flow["flow_id"], None)
                last_gc = current_loop_time
        except Exception as e:
            log.error("arena GC failed: %s: %s", type(e).__name__, e)

        policy_reload_sec = max(1.0, float(config.get("POLICY_RELOAD_SEC", 5)))
        if (run_flows and config.get("POLICY_ENABLED", True)
                and current_loop_time - last_policy_reload >= policy_reload_sec):
            last_policy_reload = current_loop_time
            try:
                policy_path = config.get("POLICY_FILE")
                current_mtime = os.path.getmtime(policy_path)
                if current_mtime != policy_mtime[0]:
                    from netwatch_policy import PolicyEngine

                    replacement = PolicyEngine.load(
                        policy_path,
                        mode=config.get("POLICY_MODE", "monitor"),
                    )
                    policy_box[0] = replacement
                    policy_mtime[0] = current_mtime
                    if notices:
                        _emit_alert(
                            "POLICY_UPDATE_RECOVERED",
                            f"POLICY_UPDATE_RECOVERED: v{replacement.version} loaded with "
                            f"{len(replacement.rules)} rules ({replacement.digest[:12]})",
                        )
            except Exception as exc:
                log.warning("policy reload rejected; retaining last-known-good policy: %s: %s", type(exc).__name__, exc)

        # Periodically flush new devices and last-seen/IP/count updates (observe()
        # never writes). Cheap no-op if clean.
        if inventory is not None and current_loop_time - last_dev_save >= dev_save_interval:
            try:
                inventory.save()
            except Exception as e:
                log.error("inventory.save failed: %s: %s", type(e).__name__, e)
            refused = inventory.refused - dev_refused_seen
            if dev_new_dropped or refused:
                _emit_alert(
                    "DEVICE_NEW",
                    f"NEW DEVICES: {dev_new_dropped} not alerted, {refused} not tracked (inventory full)",
                    target="UI_SHELL",
                )
            dev_new_sent = dev_new_dropped = 0
            dev_refused_seen = inventory.refused
            # Only the latest snapshot matters to durable_analysis_process.
            try_put_drop_oldest(inventory_queue, make_message(
                "DOD_CORE", "INVENTORY_SNAPSHOT", "DURABLE_ANALYSIS", {"devices": inventory.snapshot()}))
            last_dev_save = current_loop_time

        # [BASELINE] close the window: score each device's egress total against its
        # learned norm, emit a notice on an upward deviation, then reset + persist.
        if baseline is not None and current_loop_time - last_baseline_flush >= baseline_window:
            try:
                for bkey, total in baseline_bytes.items():
                    res = baseline.observe(bkey, total, current_loop_time)
                    if res["anomaly"]:
                        vendor = inventory.devices.get(bkey, {}).get("vendor", "?") if inventory is not None else "?"
                        _emit_alert(
                            "BASELINE_ANOMALY",
                            f"BASELINE: {bkey} [{vendor}] egress {_human_bytes(total)} this window is {res['z']:.1f}σ over its norm (mean {_human_bytes(res['mean'])})",
                            target="UI_SHELL",
                        )
                baseline_bytes.clear()
                baseline.save()
            except Exception as e:
                log.error("baseline flush/save failed: %s: %s", type(e).__name__, e)
            last_baseline_flush = current_loop_time

        if dns_analyzer is not None and current_loop_time - last_dns_save >= 10:
            try:
                dns_analyzer.save()
            except Exception as e:
                log.error("dns_analyzer.save failed: %s: %s", type(e).__name__, e)
            last_dns_save = current_loop_time

        if ja3watch is not None and current_loop_time - last_ja3_save >= 10:
            try:
                ja3watch.save()
            except Exception as e:
                log.error("ja3watch.save failed: %s: %s", type(e).__name__, e)
            last_ja3_save = current_loop_time

        try:
            if current_loop_time - CoreMetrics.last_log_time > 1.0:
                if CoreMetrics.event_faults:
                    log.error("event faults: %d in the last second", CoreMetrics.event_faults)
                    CoreMetrics.event_faults = 0
                if CoreMetrics.geo_faults:
                    log.warning("geo faults: %d in the last second", CoreMetrics.geo_faults)
                    CoreMetrics.geo_faults = 0
                if not run_global:
                    forward_drops()
                elif (
                    CoreMetrics.dropped_alerts > 0
                    or CoreMetrics.dropped_db_batches > 0
                    or CoreMetrics.dropped_core_heartbeats > 0
                    or CoreMetrics.dropped_evidence_requests > 0
                    or CoreMetrics.dropped_policy_decisions > 0
                    or CoreMetrics.dropped_policy_responses > 0
                    or CoreMetrics.dropped_web_observations > 0
                ):
                    log.warning(
                        "IPC_DROP: alerts=%d db_batches=%d (%d rows LOST) heartbeats=%d "
                        "evidence=%d policy_audit=%d policy_response=%d web_observations=%d",
                        CoreMetrics.dropped_alerts,
                        CoreMetrics.dropped_db_batches,
                        CoreMetrics.dropped_db_rows,
                        CoreMetrics.dropped_core_heartbeats,
                        CoreMetrics.dropped_evidence_requests,
                        CoreMetrics.dropped_policy_decisions,
                        CoreMetrics.dropped_policy_responses,
                        CoreMetrics.dropped_web_observations,
                    )
                    if CoreMetrics.dropped_db_rows:
                        _emit_alert(
                            "DB_BACKPRESSURE",
                            f"DB_BACKPRESSURE: persistence queue full — {CoreMetrics.dropped_db_rows} packet event(s) not recorded",
                        )
                    if CoreMetrics.dropped_evidence_requests:
                        _emit_alert("EVIDENCE_BACKPRESSURE", "EVIDENCE_BACKPRESSURE: capture request queue full")
                    if CoreMetrics.dropped_policy_decisions:
                        _emit_alert("POLICY_AUDIT_BACKPRESSURE", "POLICY_AUDIT_BACKPRESSURE: decision buffer full")
                    if CoreMetrics.dropped_policy_responses:
                        _emit_alert("POLICY_RESPONSE_BACKPRESSURE", "POLICY_RESPONSE_BACKPRESSURE: control queue full")
                    if CoreMetrics.dropped_web_observations:
                        _emit_alert(
                            "WEB_OBSERVATION_BACKPRESSURE",
                            "WEB_OBSERVATION_BACKPRESSURE: durable retry buffer overflowed",
                        )
                    CoreMetrics.dropped_alerts = CoreMetrics.dropped_db_batches = 0
                    CoreMetrics.dropped_db_rows = CoreMetrics.dropped_core_heartbeats = 0
                    CoreMetrics.dropped_evidence_requests = CoreMetrics.dropped_policy_decisions = 0
                    CoreMetrics.dropped_policy_responses = 0
                    CoreMetrics.dropped_web_observations = 0
                if CoreMetrics.dropped_renders and current_loop_time - CoreMetrics.last_render_log_time >= 60.0:
                    log.info("UI_LOAD_SHED: %d render row(s) superseded in the last minute", CoreMetrics.dropped_renders)
                    CoreMetrics.dropped_renders = 0
                    CoreMetrics.last_render_log_time = current_loop_time
                n_occupied = len(ip_to_idx)
                n_evicted_this_window = CoreMetrics.evicted_active
                capacity_due = current_loop_time - CoreMetrics.last_capacity_emit_time >= config["ARENA_ALERT_INTERVAL_SEC"]
                if capacity_due and (n_occupied > MAX_ENTITIES * 0.75 or n_evicted_this_window > 0):
                    _emit_alert(
                        "ARENA_CAPACITY",
                        f"ARENA_CAPACITY: occupied {n_occupied}/{MAX_ENTITIES} evicted_active {n_evicted_this_window}",
                    )
                    CoreMetrics.last_capacity_emit_time = current_loop_time
                if capacity_due:
                    CoreMetrics.evicted_active = 0
                CoreMetrics.last_log_time = current_loop_time
        except Exception as e:
            log.error("metrics block failed: %s: %s", type(e).__name__, e)

    if merge_queues and not out_of_step:
        # The shards have exited: publish what they left. Whole rounds only remain after a shard failed.
        leftovers = [[] if part is None else [part] for part in parts]
        for shard_index, merge_queue in enumerate(merge_queues):
            while True:
                try:
                    payload = merge_queue.get_nowait()
                except queue.Empty:
                    break
                if not is_message_payload(payload):
                    continue
                if payload["action"] == "SHARD_BATCH":
                    leftovers[shard_index].append(payload["data"])
                else:
                    merge_side(payload)
        while any(leftovers):
            run_round([pending.pop(0) if pending else None for pending in leftovers], time.time())

    # Shutdown: flush every ledger so a clean exit never loses accumulated state.
    for name, component in (("inventory", inventory), ("baseline", baseline), ("dns", dns_analyzer), ("ja3", ja3watch)):
        if component is None:
            continue
        try:
            component.save()
        except Exception as e:
            log.error("final %s.save failed: %s: %s", name, type(e).__name__, e)
    if decision_ledger is not None:
        decision_ledger.flush()
    if batch or observation_batch:
        db_rows = encode_packet_rows(compact_event_rows(batch))
        if not try_put_no_drop(db_queue, make_db_batch_message(db_rows, observation_batch), timeout=1.0):
            _emit_alert("DB_BACKPRESSURE", "Final persistence batch could not be queued before shutdown")
    if not run_global:
        forward_drops()
        log.info("analytics shard %d shut down", shard)
        return
    analysis_stop.set()
    analysis_thread.join(timeout=6.0)  # one 5 s busy wait; close() below still waits for its transaction
    retry_deferred(retry_store, alert_queue, deferred_alerts, log)  # one pass: a try can take 5 s of the stop grace
    if deferred_alerts:
        log.error("%d detection(s) not recorded at shutdown: security store busy", len(deferred_alerts))
    log.info("analytics core shut down")
    retry_store.close()
    security_store.close()
    if out_of_step:
        raise SystemExit(1)
