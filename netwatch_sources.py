"""Bounded JSON-lines collection with persisted, commit-after-accept cursors."""

from __future__ import annotations

import glob
import hashlib
import json
import math
import os
import time
import uuid
from pathlib import Path

MAX_NESTING = 64  # Real EVE records nest a handful of levels; deeper ones cannot be re-encoded safely.


def _reject_constant(value):
    raise ValueError(f"non-finite JSON value: {value}")


def _finite_float(text):
    # 1e999 parses to inf, which the store's allow_nan=False encoder rejects on every retry.
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON value: {text}")
    return value


def _check_native(value):
    """Refuse what the store cannot re-encode: excessive nesting and escaped lone surrogates."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_NESTING:
            raise ValueError("native record nesting exceeds limit")
        if isinstance(item, str):
            item.encode("utf-8")  # UnicodeEncodeError on a lone surrogate such as "\ud800"
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _open_log(path):
    if os.name != "nt":
        return open(path, "rb")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    # Read-only, with read/write/delete sharing so the producer can rotate logs.
    handle = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    try:
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


ROTATED_TAIL_GRACE_SEC = 300
OVERSIZE_SCAN_READS = 64  # ~64 MiB of one unterminated record per poll; past it the run is filed as a loss and the cursor moves on


class JSONLinesReader:
    """Follow native log files, including rename rotation and explicit globs.

    ``accept`` must commit the native record and cursor together. Binary offsets
    avoid text decoder cookies; unfinished lines are left at their start. Held
    descriptors drain renamed files before moving to the replacement.
    """

    def __init__(self, pattern, store, source, *, start_at_end=False, max_record_bytes=1_048_576):
        self.pattern = os.path.abspath(pattern)
        self.store = store
        self.source = source
        self.start_at_end = bool(start_at_end)
        self.max_record_bytes = max(1024, min(1_048_576, int(max_record_bytes)))
        self.channel = hashlib.sha256(json.dumps(
            [source, store.sensor_id, self.pattern], separators=(",", ":"),
        ).encode()).hexdigest()
        self.handles = {}
        self.errors = []
        self.partial_lines = 0
        self.visible_files = 0
        self.gaps = None  # Unread vanished files found on first discovery; None until then.

    @staticmethod
    def _anchor(handle, offset):
        position = handle.tell()
        try:
            handle.seek(max(0, offset - 128))
            return hashlib.sha256(handle.read(min(128, offset))).hexdigest()
        finally:
            handle.seek(position)

    def _paths(self):
        pattern = self.pattern if self.pattern.endswith("*") else self.pattern + "*"
        paths = []
        for path in glob.glob(pattern):
            try:
                if Path(path).is_file():
                    paths.append((os.stat(path).st_mtime_ns, path))
            except OSError as exc:
                self.errors.append(f"Cannot inspect source file: {exc}")
        return [path for _, path in sorted(paths)]

    def _discover(self):
        seen = set()
        # Skip history only on a channel's first-ever discovery; a file that appears later
        # (rotation) must be read from byte 0 or its first records are lost.
        first_run = self.start_at_end and not self.store.channel_has_cursor(self.channel)
        paths = self._paths()
        self.visible_files = len(paths)
        for path in paths:
            try:
                handle = _open_log(path)
                stat = os.fstat(handle.fileno())
                identity = [stat.st_dev, stat.st_ino]
                if not stat.st_ino:
                    identity = [os.path.realpath(path), stat.st_ctime_ns]
                key = hashlib.sha256(json.dumps([self.source, self.store.sensor_id, identity]).encode()).hexdigest()
                seen.add(key)
                if key in self.handles:
                    self.handles[key]["path"] = path
                    handle.close()
                    continue
                cursor = self.store.cursor(key)
                if (cursor is not None and path != self.pattern
                        and cursor["offset"] == stat.st_size
                        and cursor["anchor"] == self._anchor(handle, cursor["offset"])):
                    handle.close()
                    continue
                if len(self.handles) >= 64:
                    handle.close()
                    self.errors.append("Source file backlog; deferred files remain unacknowledged")
                    break
                if cursor is None:
                    offset = stat.st_size if first_run else 0
                    cursor = {"offset": offset, "generation": uuid.uuid4().hex,
                              "anchor": self._anchor(handle, offset), "channel": self.channel,
                              "file_size": stat.st_size, "path": path,
                              "initial_skip_bytes": offset}
                    cursor = self.store.initialize_cursor(key, cursor)
                handle.seek(cursor["offset"])
                self.handles[key] = {"handle": handle, "cursor": cursor, "path": path,
                                     "seen": True, "initial_skip": cursor.get("initial_skip_bytes", 0)}
            except OSError as exc:
                self.errors.append(f"Cannot open source file: {exc}")
        for key, state in self.handles.items():
            state["seen"] = key in seen
        if self.gaps is None:
            # Skip when discovery was incomplete (backlog cap, open error): unseen is not gone.
            self.gaps = [] if self.errors else [
                (key, body) for key, body in self.store.channel_cursors(self.channel)
                if key not in seen and key not in self.handles and not body.get("abandoned")
                and body.get("offset", 0) < body.get("file_size", 0)]

    BATCH_RECORDS, BATCH_SEC = 100, 0.25

    def poll(self, accept, limit=1000, transaction=None, committed=None):
        """Call accept(key, cursor, native, reference) for complete records only.

        With ``transaction`` (a store's context manager), records commit in batches
        instead of one fsync each; a failed batch rolls back whole and the cursor
        rewinds to its start, so nothing is skipped or half-accepted. ``committed()`` runs
        after each batch commits, for side effects (notifications) that must not outlive a rollback.
        """
        if transaction is None:
            consumed = self._poll(accept, limit)
            self.gaps = self.gaps and []  # Reported; a failed poll raised before this.
            return consumed
        self.errors, self.partial_lines = [], 0
        self._discover()  # Cursor initialization commits on its own, outside any batch.
        consumed = 0
        stop_at = time.monotonic() + 2.0  # Return to the caller's heartbeat between polls.
        while consumed < max(1, int(limit)) and time.monotonic() < stop_at:
            saved = {key: (dict(state["cursor"]), state["initial_skip"]) for key, state in self.handles.items()}
            try:
                with transaction():
                    # Start the clock once BEGIN IMMEDIATE has the lock, not while waiting for it.
                    began = time.monotonic()
                    deadline = began + self.BATCH_SEC
                    count = self._poll(accept, min(self.BATCH_RECORDS, max(1, int(limit)) - consumed),
                                       deadline=deadline, batched=True)
                    held = time.monotonic() - began
            except Exception:
                for key, (cursor, skip) in saved.items():
                    if key in self.handles:
                        self.handles[key]["cursor"], self.handles[key]["initial_skip"] = cursor, skip
                        self.handles[key]["handle"].seek(cursor["offset"])
                raise
            self.gaps = self.gaps and []  # Reported and committed; a rolled-back batch keeps them.
            if committed is not None:
                committed()  # Outside the rewind try: a callback error must not replay a committed batch.
            consumed += count
            if count < self.BATCH_RECORDS and time.monotonic() < deadline:
                break  # Drained what is available.
            if not count:
                break
            # SQLite's lock has no queue: waiters poll every ~100ms, so back-to-back
            # catch-up batches starve every other writer past its busy timeout.
            # Rest at least as long as the batch held the lock (<= 50% duty).
            time.sleep(max(0.1, held))
        return consumed

    def _poll(self, accept, limit=1000, deadline=None, batched=False):
        if not batched:
            self.errors = []
            self.partial_lines = 0
            self._discover()
        consumed = 0
        for key, body in self.gaps or ():
            diagnostic = {"event_type": "collector_gap", "reason": "source_file_left_glob_unread",
                          "unread_bytes_at_least": body["file_size"] - body["offset"],
                          "source_path": body.get("path")}
            accept(key, {**body, "abandoned": True}, diagnostic,
                   {"path": body.get("path"), "offset": body["offset"], "length": 0,
                    "generation": body["generation"]})
            self.errors.append("Source file left the glob before it was fully read")
        # The live file first: a rotated backlog must not starve current alerts; it
        # gets whatever the live file leaves of this poll's budget.
        for key, state in sorted(self.handles.items(), key=lambda kv: kv[1]["path"] != self.pattern):
            handle, cursor = state["handle"], state["cursor"]
            stat = os.fstat(handle.fileno())
            if stat.st_size < cursor["offset"] or self._anchor(handle, cursor["offset"]) != cursor["anchor"]:
                old_offset = cursor["offset"]
                cursor = {**cursor, "offset": 0, "anchor": self._anchor(handle, 0),
                          "generation": uuid.uuid4().hex, "initial_skip_bytes": 0}
                handle.seek(0)
                diagnostic = {"event_type": "collector_gap", "reason": "source_truncated_or_rewritten",
                              "previous_offset": old_offset, "source_path": state["path"]}
                accept(key, cursor, diagnostic, {"path": state["path"], "offset": 0,
                                                "length": 0, "generation": cursor["generation"]})
                state["cursor"] = cursor
                state["initial_skip"] = 0
                self.errors.append("Source file was truncated or rewritten; previous uncollected bytes are unknown")
            if state["initial_skip"]:
                diagnostic = {"event_type": "collector_gap", "reason": "configured_initial_history_skip",
                              "skipped_bytes": state["initial_skip"], "source_path": state["path"]}
                cursor = {**cursor, "initial_skip_bytes": 0}
                accept(key, cursor, diagnostic, {"path": state["path"], "offset": cursor["offset"],
                                                "length": 0, "generation": cursor["generation"]})
                state["cursor"] = cursor
                state["initial_skip"] = 0
            while consumed < max(1, int(limit)):
                if deadline is not None and consumed and time.monotonic() >= deadline:
                    break
                start = cursor["offset"]
                handle.seek(start)
                line = handle.readline(self.max_record_bytes + 1)
                if not line:
                    break
                digest = hashlib.sha256(line)
                oversized = len(line) > self.max_record_bytes
                capped = False
                if oversized:
                    # Bounded memory and reads: an unterminated run is not re-read from its start every poll.
                    for _ in range(OVERSIZE_SCAN_READS):
                        if not line or line.endswith(b"\n"):
                            break
                        line = handle.readline(self.max_record_bytes + 1)
                        digest.update(line)
                    capped = bool(line) and not line.endswith(b"\n")
                # A quiet, non-live file will never be completed: keep its tail as an error record.
                final_tail = (not line.endswith(b"\n") and not oversized
                              and (not state["seen"] or (not any(c in self.pattern for c in "*?[")
                                                         and state["path"] != self.pattern))
                              and time.time() - stat.st_mtime > ROTATED_TAIL_GRACE_SEC)
                if not line.endswith(b"\n") and not final_tail and not capped:
                    self.partial_lines += 1
                    handle.seek(start)
                    break
                end = handle.tell()
                if final_tail:
                    native = {"event_type": "collector_error", "reason": "truncated_final_record",
                              "record_bytes": end - start, "sha256": digest.hexdigest()}
                    self.errors.append("Rotated file ended mid-record; tail retained as loss record")
                elif oversized:
                    native = {"event_type": "collector_error", "reason": "record_size_limit",
                              "record_bytes": end - start, "sha256": digest.hexdigest()}
                    self.errors.append("Oversized native record omitted; loss record retained")
                else:
                    try:
                        native = json.loads(line, parse_constant=_reject_constant, parse_float=_finite_float)
                        if not isinstance(native, dict):
                            raise ValueError("native record is not an object")
                        _check_native(native)
                    except (ValueError, UnicodeError, RecursionError) as exc:  # nesting bomb is invalid input
                        native = {"event_type": "collector_error", "reason": "invalid_native_json",
                                  "detail": str(exc), "sha256": digest.hexdigest(),
                                  "raw_preview": line[:256].decode("utf-8", errors="replace")}
                        self.errors.append("Invalid native record retained as collection error")
                following = {**cursor, "offset": end, "anchor": self._anchor(handle, end),
                             "file_size": os.fstat(handle.fileno()).st_size,
                             "path": state["path"], "initial_skip_bytes": 0}
                reference = {"path": state["path"], "offset": start, "length": end - start,
                             "generation": cursor["generation"], "sha256": digest.hexdigest()}
                try:
                    accept(key, following, native, reference)
                except Exception:
                    handle.seek(start)
                    raise
                cursor = following
                state["cursor"] = following
                consumed += 1
            if (not state["seen"] or state["path"] != self.pattern) and cursor["offset"] == os.fstat(handle.fileno()).st_size:
                handle.close()
                del self.handles[key]
        return consumed

    def lag(self, now):
        """(unread bytes in followed files, age of the newest file write); the writer's side of the cursor."""
        behind, newest = 0, None
        for state in self.handles.values():
            try:
                stat = os.fstat(state["handle"].fileno())
            except (OSError, ValueError):
                continue
            behind += max(0, stat.st_size - state["cursor"]["offset"])
            newest = stat.st_mtime if newest is None else max(newest, stat.st_mtime)
        return behind, None if newest is None else max(0.0, now - newest)

    def close(self):
        for state in self.handles.values():
            state["handle"].close()
        self.handles.clear()
