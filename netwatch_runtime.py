"""Process supervision shared by the desktop launcher and headless service."""

import ipaddress
import logging
import multiprocessing as mp
import queue
import threading
import time

from netwatch_actions import service_actions
from netwatch_core import is_message_payload, make_message
from netwatch_db import db_persistence_worker
from netwatch_privilege import get_privilege_state
from netwatch_security_store import _event_time, security_store_from_config
from netwatch_ui_state import load_response_mode, response_dispatch
from netwatch_workers import dod_core_process, durable_analysis_process, io_sniffer_process, worker_entrypoint

log = logging.getLogger("netwatch.service")
# Counts INGEST_PACKET batches (up to INGEST_BATCH_MAX packets each), not packets. Until the queue is
# full, drop-oldest never fires and every batch waits in the sniffer's feeder buffer: the old 100,000
# let a starved core grow the VM sniffer past 1.7 GB. 128 x 512 keeps the old ~100k-packet intent.
INGESTION_QUEUE_BATCHES = 128
NATIVE_STOP_SEC = 10  # Share of the stop budget native collectors and analysis get before core/db drain.
STOP_POLL_SEC = 0.01  # stop-signal poll period in wait(): a stop is seen within 10 ms
MAX_PENDING_FINDINGS = 64  # ~32 min of continuous store refusal at the 30 s restart backoff
KILL_WAIT_SEC = 5  # SIGKILL wait for an uninterruptible disk wait; never unbounded.


class StopSignal:
    """Sticky process signal without shared locks that a killed child can strand."""

    def __init__(self, context):
        self.reader, self.writer = context.Pipe(duplex=False)
        self._set = False
        self._lock = threading.Lock()

    def __getstate__(self):
        return self.reader, self.writer, self._set

    def __setstate__(self, state):
        self.reader, self.writer, self._set = state
        self._lock = threading.Lock()

    def is_set(self):
        with self._lock:
            if not self._set and self.reader.poll(0):
                self.reader.recv_bytes()
                self._set = True
            return self._set

    def set(self):
        with self._lock:
            if not self._set:
                self.writer.send_bytes(b"1")  # One tiny notification per process; no queue feeder.
                self._set = True

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + max(0, timeout)
        while not self.is_set():
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            # Every pipe touch is a non-blocking poll under the process-local lock (in is_set);
            # the wait itself is a plain sleep. Threads polling the one pipe concurrently stalled
            # the sensor's capture loop ~32 s inside multiprocessing's Windows wait() (ov.cancel(),
            # 2026-10-12 stall dump). No interprocess lock survives a dead worker.
            time.sleep(STOP_POLL_SEC if remaining is None else min(STOP_POLL_SEC, remaining))
        return True

    def close(self):
        self.reader.close()
        self.writer.close()


def core_workers(config):
    """``(process name, heartbeat source)`` of every analytics core worker: the core (the merge when
    CORE_SHARDS > 1), then its shards."""
    shards = max(1, int(config.get("CORE_SHARDS", 1)))
    return [("core", "DOD_CORE")] + ([(f"core-{i}", f"DOD_CORE_{i}") for i in range(shards)] if shards > 1 else [])


class MonitoringRuntime:
    def __init__(self, config):
        self.config = dict(config)
        self.context = mp.get_context("spawn")
        self.workers = []
        self.queues = {}
        self.generation = 0
        self.shard_names = [name for name, _ in core_workers(self.config)[1:]]

    def start(self):
        if self.workers:
            raise RuntimeError("monitoring workers already started")
        self.shutdown_event = StopSignal(self.context)
        self.worker_stops = {name: StopSignal(self.context) for name in ("db", "sniffer", "core", "analysis",
                                                                           "suricata-eve", *self.shard_names)}
        self.capture_stop = StopSignal(self.context)
        self.capture_drained = StopSignal(self.context)
        sizes = {"ingestion": INGESTION_QUEUE_BATCHES, "render": 1000, "alert": 500, "policy": 500,
                 "db": max(1, int(self.config.get("DB_QUEUE_BATCHES", 128))),
                 "db_status": 100, "worker_status": 100, "evidence": 100,
                 "inventory": 1}  # only the core's latest inventory snapshot matters
        for name in self.shard_names:  # sharded: capture -> shard ("ingestion-core-i"), shard -> merge ("merge-core-i")
            sizes[f"ingestion-{name}"] = sizes[f"merge-{name}"] = INGESTION_QUEUE_BATCHES
        self.queues = {name: self.context.Queue(maxsize=size) for name, size in sizes.items()}
        q, config = self.queues, self.config
        stops = self.worker_stops
        self.sniffer_progress = self.context.RawValue("d", 0.0)  # capture loop's time.monotonic(); 0.0 = none yet
        ingestion = tuple(q[f"ingestion-{name}"] for name in self.shard_names) or q["ingestion"]
        merge = tuple(q[f"merge-{name}"] for name in self.shard_names)
        specs = [
            ("db", db_persistence_worker, (q["db"], q["db_status"], config, stops["db"])),
            ("sniffer", io_sniffer_process, (ingestion, q["evidence"], config, q["worker_status"],
                                            stops["sniffer"], self.capture_stop, self.capture_drained,
                                            self.sniffer_progress)),
            # Sharded, the "core" is the merge: it reads every shard and owns the alert/evidence/policy outputs.
            ("core", dod_core_process, (merge or q["ingestion"], q["render"], q["alert"], q["policy"],
                                       q["db"], q["evidence"], dict(config, _CORE_SHARD="merge") if merge else config,
                                       q["worker_status"], q["inventory"], stops["core"])),
            ("analysis", durable_analysis_process, (q["alert"], q["evidence"], q["inventory"], config,
                                                    q["worker_status"], stops["analysis"])),
        ]
        for index, name in enumerate(self.shard_names):  # a shard's alert output is its queue to the merge
            specs.append((name, dod_core_process, (q[f"ingestion-{name}"], q["render"], q[f"merge-{name}"], None,
                                                   q["db"], None, dict(config, _CORE_SHARD=index),
                                                   q["worker_status"], None, stops[name])))
        if config.get("SURICATA_EVE_ENABLED", False):
            from netwatch_suricata import suricata_eve_process

            specs.append(("suricata-eve", suricata_eve_process,
                          (q["alert"], q["evidence"], config, q["worker_status"], stops["suricata-eve"])))
        try:
            for name, target, args in specs:
                transient = {"db": ("db_status",), "sniffer": ("worker_status",),
                             "core": ("render", "alert", "policy", "worker_status", "inventory"),
                             "analysis": ("alert", "worker_status"),
                             "suricata-eve": ("alert", "worker_status")}.get(name, ("render", "worker_status"))
                process = self.context.Process(target=worker_entrypoint, name=name,
                                               args=(target, args, stops[name], tuple(q[key] for key in transient),
                                                     name != "sniffer"), daemon=True)
                process.start()
                self.workers.append(process)
        except BaseException:
            self.stop(drain=False)
            raise
        self.generation += 1

    def stop(self, grace=10, *, drain=True):
        if not self.workers and not self.queues and hasattr(self, "shutdown_report"):
            return []
        if hasattr(self, "shutdown_event"):
            self.shutdown_event.set()
        deadline = time.monotonic() + max(0, grace)
        forced = []
        failed = []  # Exited on its own but not cleanly (crash or kill mid-drain).
        processes = {p.name: p for p in self.workers}
        clean_capture = not processes
        if any(not p.is_alive() for p in self.workers):
            drain = False

        def finish(name, until=deadline):
            process = processes.get(name)
            if process is None:
                return
            process.join(max(0, until - time.monotonic()))
            if process.is_alive():
                forced.append(name)  # Terminated together with the other stragglers below.
            elif process.exitcode != 0:
                failed.append(name)
        if self.workers and drain:
            # The native source collector and durable analysis stop first: store consumers whose work is
            # committed with SQLite cursors; analysis still needs capture alive for its evidence requests.
            self.worker_stops["suricata-eve"].set()
            self.worker_stops["analysis"].set()
            # A hung collector must not spend core/db's drain budget (VM: a collector in fdatasync ate all 60 s).
            native_deadline = min(deadline, time.monotonic() + NATIVE_STOP_SEC)
            finish("suricata-eve", native_deadline)
            finish("analysis", native_deadline)
            self.capture_stop.set()
            clean_capture = self.capture_drained.wait(max(0, deadline - time.monotonic()))
            # Shards drain into the merge, which needs every shard's last records before it can finish.
            for name in self.shard_names:
                self.worker_stops[name].set()
            for name in self.shard_names:
                finish(name)
            self.worker_stops["core"].set()
            finish("core")
            # Core exit also joins its database/evidence producer feeders.
            self.worker_stops["db"].set()
            finish("db")
            self.worker_stops["sniffer"].set()
            finish("sniffer")
        else:
            # Shards before the merge: a shard flushing its last records needs the merge still reading.
            last = ["core"] if self.shard_names and "core" in processes else []
            for group in ([name for name in processes if name not in last], last):
                for name in group:
                    if processes[name].is_alive():
                        self.worker_stops[name].set()
                for name in group:
                    finish(name)
        # After the deadline every wait is shared and bounded: one SIGTERM wait, one SIGKILL wait.
        stuck = [processes[name] for name in forced]
        for send, wait in ((lambda process: process.terminate(), 1), (lambda process: process.kill(), KILL_WAIT_SEC)):
            stuck = [process for process in stuck if process.is_alive()]
            for process in stuck:
                send(process)
            until = time.monotonic() + wait
            for process in stuck:
                process.join(max(0, until - time.monotonic()))
        for process in processes.values():
            if not process.is_alive():
                process.close()
            else:
                # A thread in uninterruptible I/O outlives SIGKILL; multiprocessing's atexit would join it forever.
                # shortcut: private multiprocessing set, revisit if CPython renames it.
                mp.process._children.discard(process)
        self.shutdown_report = {"capture_drained": clean_capture, "forced_workers": list(forced),
                                "failed_workers": failed,
                                "ordered_drain": bool(drain and clean_capture and not forced and not failed)}
        self.workers = []
        for ipc in self.queues.values():
            # Presentation/telemetry queues are not durable receipts; don't wait
            # forever for a feeder whose consumer has crashed.
            ipc.cancel_join_thread()
            ipc.close()
        self.queues = {}
        for signal in [getattr(self, "shutdown_event", None), getattr(self, "capture_stop", None),
                       getattr(self, "capture_drained", None), *getattr(self, "worker_stops", {}).values()]:
            if signal is not None:
                signal.close()
        return forced


class ServiceSupervisor:
    """Restart a failed generation; never reuse queues after a process crash."""

    def __init__(self, config):
        self.runtime = MonitoringRuntime(config)
        self.store = security_store_from_config(config)
        # Recording owner only. Wall-clock expiry is independent of the monotonic tick.
        self.actions = service_actions(self.store, config)
        self.next_start = 0.0
        self.failures = 0
        self.started_at = None
        self.last_health = 0.0
        self.health = {}
        self.pending_findings = []  # findings the store has not yet accepted; flushed each tick
        self.coalesced_findings = 0  # findings past the cap, written as one counted summary
        self.reports = {}  # heartbeats received since the last health write
        previous = self.store.source_health("RUNTIME:SERVICE")
        if previous and previous.get("status") != "STOPPED":
            self._queue_finding(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {
                "message": "Previous run ended without an ordered stop; queued telemetry may be missing",
                "count": None, "severity": "critical", "containment_eligible": False,
            }))

    def _queue_finding(self, message):
        if len(self.pending_findings) < MAX_PENDING_FINDINGS:
            self.pending_findings.append(message)
            return
        self.coalesced_findings += 1
        log.error("pending findings at cap %d; coalesced %d so far", MAX_PENDING_FINDINGS, self.coalesced_findings)

    def tick(self, now=None):
        self.actions.expire_due()
        now = time.monotonic() if now is None else now
        heartbeat_timeout = max(1, float(self.runtime.config.get("RUNTIME_HEARTBEAT_TIMEOUT_SEC", 10)))
        # A loaded host (boot, cold cache) can take far longer to start a worker than
        # a live worker may go silent; killing slow starters only adds load and loops.
        start_grace = max(heartbeat_timeout, float(self.runtime.config.get("RUNTIME_START_GRACE_SEC", 120)))
        # Read queued heartbeats before judging staleness: a supervisor that stalled on
        # a store write would otherwise kill workers whose heartbeats are waiting here.
        self._drain(now)
        # The sniffer's capture loop stamps a shared time.monotonic() value; its heartbeat thread can be
        # GIL-starved for 10+ s under load. Always compared with the real clock, never the injected `now`.
        progress = getattr(self.runtime, "sniffer_progress", None)
        capturing = (progress is not None and progress.value > 0
                     and time.monotonic() - progress.value <= heartbeat_timeout)
        failed = [p.name for p in self.runtime.workers if not p.is_alive()]
        reasons = {p.name: f"exited {p.exitcode}" for p in self.runtime.workers if not p.is_alive()}
        if self.runtime.workers and self.started_at is not None:
            for source, name in (("IO_WORKER", "sniffer"), ("DB_WORKER", "db"),
                                 *((source, name) for name, source in core_workers(self.runtime.config))):
                observed, report = self.health.get(source, (None, {}))
                stalled = (now - self.started_at > start_grace if observed is None else
                           (now - observed > heartbeat_timeout and not (name == "sniffer" and capturing))
                           or report.get("status") == "DEADLOCK_DETECTED")
                if stalled and name not in failed:
                    failed.append(name)
                    reasons[name] = (f"no first heartbeat in {now - self.started_at:.0f}s" if observed is None
                                     else f"{report.get('status')}, last heartbeat {now - observed:.0f}s ago, "
                                          f"loop age {report.get('loop_age_sec')}")
        if failed:
            generation = self.runtime.generation
            log.warning("restarting generation %s: %s", generation,
                        "; ".join(f"{name}: {reasons.get(name, '?')}" for name in failed))
            self.runtime.stop(drain=False)
            self.failures += 1
            self.next_start = now + min(30, 2 ** min(5, self.failures))
            self.health.clear()
            self._queue_finding(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {
                "message": "Monitoring generation stopped after a worker exit or stalled progress; queued telemetry may be missing",
                "failed_workers": failed, "generation": generation, "count": None,
                "severity": "critical", "containment_eligible": False,
            }))
        if not self.runtime.workers and now >= self.next_start:
            try:
                self.runtime.start()
                self.started_at = now
            except Exception as exc:
                self.failures += 1
                self.next_start = now + min(30, 2 ** min(5, self.failures))
                self._queue_finding(make_message("SERVICE", "RUNTIME_START_FAILED", "SYSTEM", {
                    "message": "Monitoring workers could not start; retry is scheduled",
                    "severity": "critical", "containment_eligible": False,
                }, error=str(exc)[:1000]))
        while self.pending_findings:
            self.store.add(self.pending_findings[0])
            self.pending_findings.pop(0)
        if self.coalesced_findings:
            self.store.add(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {
                "message": f"{self.coalesced_findings} further runtime findings coalesced while the security store refused writes",
                "count": self.coalesced_findings, "severity": "critical", "containment_eligible": False,
            }))
            self.coalesced_findings = 0  # only after add returns, so a raising add retries next tick
        statuses = {}
        for source in ("IO_WORKER", "DB_WORKER", *(source for _, source in core_workers(self.runtime.config))):
            observed, report = self.health.get(source, (self.started_at if self.started_at is not None else now, {}))
            statuses[source] = ("STALE" if now - observed > heartbeat_timeout and not (source == "IO_WORKER" and capturing) else report.get("status", "STARTING"))
        healthy = bool(self.runtime.workers) and all(value in {"ALIVE", "IDLE"} for value in statuses.values())
        if healthy and self.started_at is not None and now - self.started_at > 60:
            self.failures = 0
        if now - self.last_health >= 5 or failed:
            stats = self.health.get("IO_WORKER", (0, {}))[1].get("capture_stats", {})
            timestamp = _event_time(stats.get("timestamp"), None) if isinstance(stats, dict) else None
            measured = (isinstance(stats, dict) and stats.get("available") is True and timestamp is not None
                        and 0 <= time.time() - timestamp <= max(10, 2 * float(self.runtime.config.get("PCAP_STATS_INTERVAL_SEC", 10))))
            privileges = {"SERVICE": get_privilege_state(), **{
                source: report.get("privilege", {"status": "unverified"}) for source, (_, report) in self.health.items()}}
            # One commit for every health row: per-heartbeat writes queued the supervisor behind
            # the shared writer lock while workers' heartbeats piled up unread.
            with self.store._transaction():
                self.store.record_source_health("RUNTIME:SERVICE", {
                    "status": "RUNNING" if healthy else "DEGRADED", "generation": self.runtime.generation,
                    "workers": statuses, "capture": "measured" if measured else "unverified",
                    "response_actions": "recording-only",
                    "worker_privileges": privileges,
                })
                for source, report in self.reports.items():
                    self.store.record_source_health("RUNTIME:" + source, report)
            self.reports.clear()
            self.last_health = now

    def _drain(self, now):
        q = self.runtime.queues
        for name in ("db_status", "worker_status", "alert", "render", "policy"):
            if name not in q:
                continue
            for _ in range(256):
                try:
                    payload = q[name].get_nowait()
                except queue.Empty:
                    break
                if not is_message_payload(payload):
                    continue
                if payload["action"] in {"WORKER_HEARTBEAT", "DB_HEARTBEAT"}:
                    status = payload["data"].get("status") or ("ALIVE" if payload["action"] == "DB_HEARTBEAT" else "UNVERIFIED")
                    report = {**payload["data"], "status": status, "generation": self.runtime.generation}
                    self.health[payload["source"]] = (now, report)
                    self.reports[payload["source"]] = report  # stored with the next health write
                elif name == "alert" and payload["action"] == "ALERT":
                    self._respond(payload, payload["data"].get("message") or "ALERT")
                elif name == "policy":
                    if payload["data"].get("configured_action") == "block":
                        self._respond(payload, payload["data"].get("message") or "Policy block")
                # Detectors commit before these transient presentation queues.

    def _respond(self, payload, reason):
        """Apply the response mode to a block-worthy finding: leave it, queue a request, or approve it.

        One request per target while one is open or for a TTL after the last, so a
        noisy source cannot flood the approval queue. Protected and local targets
        are refused by the action service and skipped.
        """
        config = self.runtime.config
        dispatch = response_dispatch(load_response_mode(config.get("RESPONSE_MODE_LEDGER"),
                                                        default=config.get("RESPONSE_MODE", "ids_only")))
        if dispatch == "ignore":
            return None
        try:
            target = str(ipaddress.ip_address(bytes(payload["target_id"])))
        except (TypeError, ValueError):
            return None
        if self.store._read("""SELECT 1 FROM security_response_actions WHERE kind='block_ip' AND target=?
                AND (state IN ('requested', 'approved', 'applied') OR requested_at>?) LIMIT 1""",
                            (target, time.time() - self.actions.default_ttl)):
            return None
        case = self.store._read("SELECT incident_id FROM security_detections WHERE source_event_id=? LIMIT 1",
                                (str(payload.get("correlation_id")),))
        actor = "response-mode:" + ("autonomous" if dispatch == "enforce" else "ready")
        try:
            action = self.actions.request(kind="block_ip", target=target, reason=str(reason)[:4096],
                                          requested_by=actor, case_id=case[0][0] if case else None)
            if dispatch == "enforce":
                action = self.actions.approve(action["id"], actor=actor)
            return action
        except ValueError as exc:
            logging.getLogger(__name__).debug("response mode skipped %s: %s", target, exc)
            return None

    def close(self):
        running = bool(self.runtime.workers)
        forced = self.runtime.stop(grace=float(self.runtime.config.get("RUNTIME_STOP_GRACE_SEC", 60)))
        if not running:
            # Stopped in restart backoff: the failed generation already filed its gap; its report is stale.
            self.runtime.shutdown_report = {"capture_drained": True, "forced_workers": [],
                                            "failed_workers": [], "ordered_drain": True}
        try:
            if not self.runtime.shutdown_report["ordered_drain"]:
                self.store.add(make_message("SERVICE", "RUNTIME_COLLECTION_GAP", "SYSTEM", {
                    "message": "Monitoring shutdown could not verify an ordered drain; queued telemetry may be missing",
                    "forced_workers": forced, "failed_workers": self.runtime.shutdown_report["failed_workers"],
                    "count": None, "severity": "anomaly", "containment_eligible": False,
                }))
            self.store.record_source_health("RUNTIME:SERVICE", {"status": "STOPPED", **self.runtime.shutdown_report})
            self.actions.expire_due()
        finally:
            self.store.close()
