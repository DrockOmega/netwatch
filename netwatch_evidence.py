"""Bounded packet evidence ring and capture-on-alert PCAP writer."""

from __future__ import annotations

import math
import os
import queue
import re
import struct
import threading
import time
import uuid
from collections import deque
from datetime import UTC, datetime

from netwatch_core import disk_admission
from netwatch_evidence_catalog import EvidenceCatalog, file_digest, sync_directory, write_manifest

_PCAP_GLOBAL = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
_SAFE = re.compile(r"[^a-zA-Z0-9_.-]+")


class EvidenceRecorder:
    """Keep a time/size-bounded raw-frame ring and fulfill delayed PCAP requests."""

    def __init__(self, directory, *, pre_sec=15, post_sec=5,
                 max_ring_bytes=64 * 1024 * 1024, max_files=100,
                 max_pending=32, max_write_jobs=8, coalesce_sec=2.0,
                 catalog_path=None, max_bytes=2_147_483_648, retention_days=7,
                 sensor_id="unknown", capture_interface=None, max_triggers=256,
                 min_free_bytes=0):
        self.directory = os.path.abspath(directory)
        self.pre_sec = max(0.0, float(pre_sec))
        self.post_sec = max(0.0, float(post_sec))
        self.max_ring_bytes = max(1_048_576, int(max_ring_bytes))
        self.max_files = max(1, int(max_files))
        self.max_bytes = max(1, int(max_bytes))
        self.retention_days = max(0.0, float(retention_days))
        self.sensor_id = str(sensor_id or "unknown")
        self.capture_interface = capture_interface
        self.max_triggers = max(1, int(max_triggers))
        self.min_free_bytes = max(0, int(min_free_bytes))
        self.catalog = EvidenceCatalog(self.directory, db_path=catalog_path)
        # The recorder writes from its own thread, so it can outwait another writer's
        # transaction instead of dropping the capture at the store's 5 s default.
        with self.catalog.store._lock:
            self.catalog.store.conn.execute("PRAGMA busy_timeout=30000")
        self.recovery = self.catalog.recover()
        self.max_pending = max(1, int(max_pending))
        self.coalesce_sec = max(0.0, float(coalesce_sec))
        self.frames = deque()
        self.ring_bytes = 0
        self.pending = []
        self.write_jobs = queue.Queue(maxsize=max(1, int(max_write_jobs)))
        self.results = queue.Queue()
        self.closed = False
        self.writer = threading.Thread(target=self._write_loop, name="evidence-writer", daemon=True)
        self.writer.start()

    def add(self, timestamp, frame):
        timestamp = float(timestamp if timestamp is not None else time.time())
        if not math.isfinite(timestamp) or not 0 <= timestamp < 4_294_967_296:
            raise ValueError("frame timestamp is outside the PCAP range")
        raw = bytes(frame)
        self.frames.append((timestamp, raw))
        self.ring_bytes += len(raw)
        self._trim(timestamp)

    def request(self, request, now=None):
        if self.closed:
            return False
        now = time.time() if now is None else float(now)
        if not math.isfinite(now) or not 0 <= now < 4_294_967_296:
            return False
        try:
            trigger = float(request.get("trigger_ts", now))
        except (ValueError, TypeError):
            return False
        if not math.isfinite(trigger) or not 0 <= trigger < 4_294_967_296:
            return False
        action = str(request.get("action") or "alert")
        trigger_record = {
            "trigger_ts": trigger,
            "correlation_id": str(request.get("correlation_id") or "uncorrelated"),
            "source_event_id": request.get("source_event_id") or request.get("correlation_id"),
            "message": str(request.get("message") or "")[:500],
            "source": request.get("source"), "sensor_id": request.get("sensor_id"),
        }
        for pending in reversed(self.pending):
            if (pending["action"] == action
                    and abs(trigger - pending["trigger_ts"]) <= self.coalesce_sec):
                if len(pending["triggers"]) >= self.max_triggers:
                    return False
                pending["triggers"].append(trigger_record)
                pending["deadline"] = max(pending["deadline"], max(now, trigger) + self.post_sec)
                pending["coalesced"] += 1
                return True
        if len(self.pending) >= self.max_pending:
            return False
        self.pending.append({
            "trigger_ts": trigger,
            "deadline": max(now, trigger) + self.post_sec,
            "action": action,
            "correlation_id": str(request.get("correlation_id") or "uncorrelated"),
            "trigger_message": str(request.get("message") or "")[:500],
            "coalesced": 1,
            "triggers": [trigger_record],
        })
        return True

    def poll(self, now=None, force=False):
        now = time.time() if now is None else float(now)
        results = self._drain_results()
        waiting = []
        for request in self.pending:
            if not force and now < request["deadline"]:
                waiting.append(request)
                continue
            selected = self._snapshot(request)
            try:
                self.write_jobs.put_nowait((request, selected, now))
            except queue.Full:
                results.append(self._failure(request, "evidence writer backlog is full", now))
        self.pending = waiting
        return results

    def close(self, now=None):
        """Flush mature requests, stop the writer, and return final results."""
        if self.closed:
            return self._drain_results()
        now = time.time() if now is None else float(now)
        immediate = self.poll(now, force=True)
        self.write_jobs.join()
        self.closed = True
        self.write_jobs.put(None)
        self.writer.join()
        self.catalog.close()
        return [*immediate, *self._drain_results()]

    def _trim(self, now):
        cutoff = now - max(self.pre_sec + self.post_sec + 2.0, 5.0)
        while self.frames and (self.frames[0][0] < cutoff or self.ring_bytes > self.max_ring_bytes):
            _, raw = self.frames.popleft()
            self.ring_bytes -= len(raw)

    def _snapshot(self, request):
        start = min(trigger["trigger_ts"] for trigger in request["triggers"]) - self.pre_sec
        end = max(trigger["trigger_ts"] for trigger in request["triggers"]) + self.post_sec
        return [(ts, raw) for ts, raw in self.frames if start <= ts <= end]

    def _write_loop(self):
        while True:
            job = self.write_jobs.get()
            if job is None:
                self.write_jobs.task_done()
                return
            request, selected, now = job
            try:
                try:
                    result = self._write(request, selected, now)
                except Exception as exc:
                    result = self._failure(request, f"{type(exc).__name__}: {exc}", now)
                self.results.put(result)
            finally:
                self.write_jobs.task_done()

    def _drain_results(self):
        results = []
        while True:
            try:
                results.append(self.results.get_nowait())
            except queue.Empty:
                return results

    @staticmethod
    def _failure(request, error, now):
        return {
            "ok": False,
            "path": "",
            "error": error,
            "action": request["action"],
            "correlation_id": request["correlation_id"],
            "trigger_message": request.get("trigger_message", ""),
            "coalesced": request["coalesced"],
            "triggers": request.get("triggers", []),
            "completed_ts": now,
        }

    def _write(self, request, selected, now):
        stamp = datetime.fromtimestamp(request["trigger_ts"], UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        action = _SAFE.sub("-", request["action"]).strip("-")[:40] or "alert"
        evidence_id = uuid.uuid4().hex
        path = os.path.join(self.directory, f"{stamp}_{action}_{evidence_id}.pcap")
        estimated_bytes = 24 + sum(16 + min(len(raw), 65535) for _, raw in selected)
        admitted, free = disk_admission(path, self.min_free_bytes)
        if not admitted:
            return self._failure(request, f"data volume free space {free} bytes is below the "
                                 f"{self.min_free_bytes}-byte floor; capture not written", now)
        retention = self.catalog.prune(max_files=self.max_files, max_bytes=self.max_bytes,
                                       retention_days=self.retention_days, reserve_files=1,
                                       reserve_bytes=estimated_bytes, now=now)
        if not retention["admitted"]:
            return self._failure(request, "evidence quota is occupied by held or unregistered captures", now)
        temporary = path + ".partial"
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
            handle.write(_PCAP_GLOBAL)
            for timestamp, raw in selected:
                seconds = int(timestamp)
                micros = int((timestamp - seconds) * 1_000_000)
                length = min(len(raw), 65535)
                handle.write(struct.pack("<IIII", seconds, micros, length, len(raw)))
                handle.write(raw[:length])
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(self.directory)
        manifest = {
            "version": 1, "evidence_id": evidence_id, "filename": os.path.basename(path),
            "created_at": now, "sha256": file_digest(path), "file_bytes": estimated_bytes,
            "frames": len(selected), "observed_bytes": sum(len(raw) for _, raw in selected),
            "captured_bytes": sum(min(len(raw), 65535) for _, raw in selected), "snaplen": 65535,
            "first_frame_ts": min(ts for ts, _ in selected) if selected else None,
            "last_frame_ts": max(ts for ts, _ in selected) if selected else None,
            "requested_pre_sec": self.pre_sec, "requested_post_sec": self.post_sec,
            "sensor_id": self.sensor_id, "capture_interface": self.capture_interface,
            "triggers": request["triggers"],
            "coverage": "Ethernet frames observed by this collector; ring bytes and time bound history",
        }
        write_manifest(path + ".manifest.json", manifest)
        self.catalog.register(manifest)
        return {
            "ok": True, "path": path, "evidence_id": evidence_id,
            "sha256": manifest["sha256"], "frames": len(selected),
            "bytes": manifest["observed_bytes"], "action": request["action"],
            "correlation_id": request["correlation_id"],
            "trigger_message": request["trigger_message"],
            "coalesced": request["coalesced"], "triggers": request["triggers"], "completed_ts": now,
        }
