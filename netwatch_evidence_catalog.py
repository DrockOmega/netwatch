"""Local evidence integrity, investigation holds and auditable payload retention."""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
import uuid
import zipfile
from pathlib import Path

from netwatch_security_store import DurableIncidentStore


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sync_directory(directory):
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_manifest(path, body):
    temporary = str(path) + f".{uuid.uuid4().hex}.partial"
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as handle:
            json.dump(body, handle, sort_keys=True, separators=(",", ":"), allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(os.path.dirname(os.path.abspath(path)))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class EvidenceCatalog:
    """A collector-local catalog; hashes are integrity checks, not remote attestations."""

    def __init__(self, directory, *, store=None, db_path=None):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            self.directory.chmod(0o700)
        self.owns_store = store is None
        self.store = store or DurableIncidentStore(db_path or str(self.directory / "catalog.db"))

    def _path(self, filename):
        if not isinstance(filename, str) or not filename or filename in {".", ".."} or Path(filename).name != filename or "/" in filename or "\\" in filename:
            raise ValueError("evidence filename must stay within its storage directory")
        path = self.directory / filename
        if path.is_symlink() or path.resolve().parent != self.directory:
            raise ValueError("evidence path must be a regular file in its storage directory")
        return path

    def _audit(self, evidence_id, operation, body, actor="evidence-recorder"):
        self.store.conn.execute("INSERT INTO evidence_audit (evidence_id,timestamp,actor,operation,body) VALUES (?,?,?,?,?)",
                                (evidence_id, time.time(), actor, operation, json.dumps(body, sort_keys=True)))

    def get(self, evidence_id):
        rows = self.store._read("SELECT * FROM evidence_items WHERE evidence_id=? AND directory=?",
                                (str(evidence_id), str(self.directory)))
        return self._decode(rows[0]) if rows else None

    @staticmethod
    def _decode(row):
        return dict(row) | {"body": json.loads(row["body"]), "held": bool(row["held"])}

    def list(self, limit=500):
        return [self._decode(row) for row in self.store._read(
            "SELECT * FROM evidence_items WHERE directory=? ORDER BY created_at DESC LIMIT ?",
            (str(self.directory), max(1, min(10_000, int(limit)))),
        )]

    def _manifest(self, path):
        if path.stat().st_size > 1_048_576:
            raise ValueError("oversized evidence manifest")
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)

    def register(self, manifest, *, recovered=False):
        if not isinstance(manifest, dict) or not math.isfinite(float(manifest["created_at"])):
            raise ValueError("invalid evidence manifest")
        if not isinstance(manifest["file_bytes"], int) or manifest["file_bytes"] < 24:
            raise ValueError("invalid capture size")
        evidence_id = str(manifest["evidence_id"])
        uuid.UUID(hex=evidence_id)
        path = self._path(manifest["filename"])
        if not path.is_file() or path.stat().st_size != manifest["file_bytes"] or file_digest(path) != manifest["sha256"]:
            raise ValueError("capture does not match its integrity manifest")
        sidecar = self._path(path.name + ".manifest.json")
        if not sidecar.is_file() or self._manifest(sidecar) != manifest:
            raise ValueError("capture manifest is missing or inconsistent")
        metadata = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False)
        marker = self._path(path.name + ".hold")
        with self.store._transaction():
            existing = self.get(evidence_id)
            if existing:
                if existing["body"] != manifest:
                    raise ValueError("evidence identity reused with different metadata")
                return existing
            self.store.conn.execute("INSERT INTO evidence_items VALUES (?,?,?,?,?,?,?,?)",
                                    (evidence_id, str(self.directory), path.name, manifest["created_at"],
                                     manifest["file_bytes"], "available", int(marker.exists()), metadata))
            self._audit(evidence_id, "recovered" if recovered else "registered", {"sha256": manifest["sha256"]})
            for trigger in manifest.get("triggers", []):
                clauses, params = ["source_event_id=?"], [trigger.get("source_event_id") or trigger["correlation_id"]]
                for key in ("source", "sensor_id"):
                    if trigger.get(key):
                        clauses.append(f"{key}=?")
                        params.append(trigger[key])
                cases = self.store.conn.execute(
                    "SELECT DISTINCT incident_id FROM security_detections WHERE " + " AND ".join(clauses), params,
                ).fetchall()
                if not (trigger.get("source") and trigger.get("sensor_id")) and len(cases) != 1:
                    continue  # Legacy unqualified identifiers cannot attribute multiple cases.
                for case in cases:
                    inserted = self.store.conn.execute("INSERT OR IGNORE INTO security_case_links VALUES (?,?,?)",
                                                       (case[0], "evidence", evidence_id)).rowcount
                    if inserted:
                        self.store._audit(case[0], "link", {"kind": "evidence", "reference": evidence_id},
                                          "evidence-recorder", time.time())
        return self.get(evidence_id)

    def recover(self):
        """At writer startup, recover completed manifests left before catalog commit."""
        recovered, errors = 0, []
        for row in self.store._read("SELECT * FROM evidence_items WHERE directory=? AND status='pruning'",
                                    (str(self.directory),)):
            item = self._decode(row)
            try:
                self._finish_prune(item)
            except (OSError, ValueError) as exc:
                errors.append({"path": item["filename"], "error": str(exc)})
        for sidecar in self.directory.glob("*.pcap.manifest.json"):
            try:
                if sidecar.is_symlink() or sidecar.stat().st_size > 1_048_576:
                    raise ValueError("unsafe or oversized evidence manifest")
                with sidecar.open(encoding="utf-8") as handle:
                    manifest = json.load(handle)
                if self.get(manifest["evidence_id"]) is None:
                    self.register(manifest, recovered=True)
                    recovered += 1
            except (OSError, ValueError, TypeError, KeyError) as exc:
                errors.append({"path": str(sidecar), "error": str(exc)})
        return {"recovered": recovered, "errors": errors}

    def verify(self, evidence_id, *, actor="local-console"):
        item = self.get(evidence_id)
        if item is None:
            raise ValueError("evidence item not found")
        if item["status"] in {"pruned", "pruning"}:
            return {"ok": False, "status": item["status"], "evidence_id": evidence_id}
        try:  # Hash outside the transaction; the write lock is only held to record the result.
            path = self._path(item["filename"])
            actual = file_digest(path)
            sidecar = self._manifest(self._path(path.name + ".manifest.json"))
            valid = actual == item["body"]["sha256"] and sidecar == item["body"] and path.stat().st_size == item["size_bytes"]
            status = "available" if valid else "corrupt"
        except FileNotFoundError:
            status = "missing"
        except (OSError, ValueError, TypeError):
            status = "corrupt"
        with self.store._transaction():
            current = self.get(evidence_id)["status"]
            if current in {"pruned", "pruning"}:  # Pruned while hashing; never resurrect it.
                return {"ok": False, "status": current, "evidence_id": evidence_id}
            self.store.conn.execute("UPDATE evidence_items SET status=? WHERE evidence_id=?", (status, evidence_id))
            self._audit(evidence_id, "verified", {"status": status}, actor)
            return {"ok": status == "available", "status": status, "evidence_id": evidence_id}

    def hold(self, evidence_id, *, actor, reason, enabled=True):
        if not isinstance(actor, str) or not actor.strip() or not isinstance(reason, str) or not reason.strip() or len(reason) > 4096:
            raise ValueError("a hold change requires an actor and a bounded reason")
        with self.store._transaction():
            item = self.get(evidence_id)
            if item is None or item["status"] in {"pruned", "pruning"}:
                raise ValueError("retained evidence item not found")
            marker = self._path(item["filename"] + ".hold")
            if enabled:
                write_manifest(marker, {"evidence_id": evidence_id, "actor": actor, "reason": reason})
            elif marker.exists():
                marker.unlink()
                sync_directory(self.directory)
            self.store.conn.execute("UPDATE evidence_items SET held=? WHERE evidence_id=?", (int(enabled), evidence_id))
            self._audit(evidence_id, "hold" if enabled else "release", {"reason": reason}, actor)
        return self.get(evidence_id)

    def _usage(self):
        files = [entry for entry in self.directory.iterdir()
                 if entry.name.endswith((".pcap", ".pcap.partial")) and entry.is_file() and not entry.is_symlink()]
        return len(files), sum(path.stat().st_size for path in files)

    def _finish_prune(self, item):
        # Commit deletion intent before unlink so restart can finish the audit.
        path = self._path(item["filename"])
        if item["held"] or self._path(path.name + ".hold").exists():
            raise ValueError("held evidence has a pending prune intent")
        path.unlink(missing_ok=True)
        self._path(path.name + ".manifest.json").unlink(missing_ok=True)
        sync_directory(self.directory)
        with self.store._transaction():
            self.store.conn.execute("UPDATE evidence_items SET status='pruned' WHERE evidence_id=?", (item["evidence_id"],))
            self._audit(item["evidence_id"], "pruned", {"bytes": item["size_bytes"]})

    def prune(self, *, max_files=100, max_bytes=2_147_483_648, retention_days=7,
              reserve_files=0, reserve_bytes=0, now=None):
        now = time.time() if now is None else float(now)
        if not math.isfinite(now) or min(max_files, max_bytes, retention_days, reserve_files, reserve_bytes) < 0:
            raise ValueError("invalid evidence retention limits")
        removed = []
        count, used = self._usage()
        if ((max_files > 0 and reserve_files > max_files) or
                (max_bytes > 0 and reserve_bytes > max_bytes)):
            return {"removed": [], "admitted": False, "payload_bytes": used, "payload_files": count}
        # Missing/corrupt items age out too: unpruned, they pin native records and cases forever.
        rows = self.store._read("SELECT * FROM evidence_items WHERE directory=? AND status IN "
                                "('available','missing','corrupt') ORDER BY created_at",
                                (str(self.directory),))
        for row in rows:
            # Decide outside the writer lock: a directory scan per catalog row under it starved every other writer.
            if not ((retention_days > 0 and row["created_at"] < now - retention_days * 86400) or
                    (max_files > 0 and count + reserve_files > max_files) or
                    (max_bytes > 0 and used + reserve_bytes > max_bytes)):
                continue
            # SQLite serializes the intent with holds across connections.
            with self.store._transaction():
                item = self.get(row["evidence_id"])
                count, used = self._usage()
                expired = retention_days > 0 and item["created_at"] < now - retention_days * 86400
                over = ((max_files > 0 and count + reserve_files > max_files) or
                        (max_bytes > 0 and used + reserve_bytes > max_bytes))
                if item["status"] not in {"available", "missing", "corrupt"} or item["held"] or self._path(item["filename"] + ".hold").exists():
                    continue
                if not expired and not over:
                    continue
                self.store.conn.execute("UPDATE evidence_items SET status='pruning' WHERE evidence_id=?", (item["evidence_id"],))
                self._audit(item["evidence_id"], "prune_requested", {"reason": "age" if expired else "quota"})
            self._finish_prune(item)
            removed.append(item["evidence_id"])
        count, used = self._usage()
        enough = not ((max_files > 0 and count + reserve_files > max_files) or
                      (max_bytes > 0 and used + reserve_bytes > max_bytes))
        return {"removed": removed, "admitted": enough, "payload_bytes": used, "payload_files": count}

    def audit(self, evidence_id, limit=300):
        return [dict(row) | {"body": json.loads(row["body"])} for row in self.store._read(
            "SELECT * FROM evidence_audit WHERE evidence_id=? ORDER BY sequence DESC LIMIT ?", (str(evidence_id), max(1, min(10_000, int(limit)))),
        )]

    def export(self, evidence_id, destination, *, actor):
        # Copy and verify outside any transaction so a slow export never holds the
        # SQLite write lock that the recorder, holds and detections need.
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("evidence export requires an actor")
        item = self.get(evidence_id)
        if item is None:
            raise ValueError("evidence item not found")
        path = self._path(item["filename"])
        if item["status"] != "available" or self._manifest(self._path(path.name + ".manifest.json")) != item["body"]:
            raise ValueError("evidence integrity verification failed")
        destination = Path(destination)
        manifest = {"version": 1, "capture": item["body"], "held": item["held"], "audit": self.audit(evidence_id)}
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
                    archive.write(path, arcname=path.name)
                    archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
                output.flush()
                os.fsync(output.fileno())
            try:
                verified = verify_export(destination)  # The copy is checked against the catalog hash.
            except (OSError, ValueError, KeyError, zipfile.BadZipFile):
                verified = {"ok": False}
            if not verified["ok"]:
                raise ValueError("evidence integrity verification failed")
            with self.store._transaction():
                if self.get(evidence_id)["status"] != "available":
                    raise ValueError("evidence changed during export")
                self._audit(evidence_id, "exported", {"destination": str(destination)}, actor)
        except BaseException:
            destination.unlink(missing_ok=True)
            status = (self.get(evidence_id) or {}).get("status")
            if status != "available":  # Pruning (or a failed verify) won the race; report that, not the copy error.
                raise ValueError(f"evidence is no longer available ({status}) after export started") from None
            raise
        sync_directory(destination.resolve().parent)
        return verified

    def close(self):
        if self.owns_store:
            self.store.close()


def verify_export(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != 2 or len({entry.filename for entry in entries}) != 2:
            raise ValueError("export must contain exactly one capture and one manifest")
        metadata = archive.getinfo("manifest.json")
        if metadata.file_size > 1_048_576 or metadata.compress_type != zipfile.ZIP_STORED:
            raise ValueError("unsafe export manifest")
        manifest = json.loads(archive.read(metadata))
        capture = manifest["capture"]
        filename = capture["filename"]
        if not isinstance(filename, str) or Path(filename).name != filename or "/" in filename or "\\" in filename:
            raise ValueError("unsafe export capture name")
        payload = archive.getinfo(filename)
        if payload.compress_type != zipfile.ZIP_STORED or payload.file_size != capture["file_bytes"]:
            raise ValueError("export capture size or compression is invalid")
        digest = hashlib.sha256()
        with archive.open(payload) as handle:
            for chunk in iter(lambda: handle.read(1_048_576), b""):
                digest.update(chunk)
        return {"ok": digest.hexdigest() == capture["sha256"],
                "evidence_id": capture["evidence_id"], "sha256": digest.hexdigest()}
