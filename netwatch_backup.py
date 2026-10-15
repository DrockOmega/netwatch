"""Online backup, verification and restore of a NetWatch runtime directory.

    python netwatch_backup.py backup --base-dir <runtime-directory> <backup-directory>
    python netwatch_backup.py verify <backup-directory>
    python netwatch_backup.py restore <backup-directory> <empty-target-directory>

The SQLite stores (security store, telemetry ledger, spool) are copied with SQLite's backup API from a
read-only connection, so each is a consistent snapshot that includes committed WAL content while the
service keeps writing. Config overlays (``netwatch.*.json``) and every file under the evidence directory
are copied as files. ``netwatch-backup.json`` lists each file with its SHA-256; ``verify`` checks every
hash and runs ``PRAGMA integrity_check`` on each store, and ``restore`` verifies before writing into an
empty directory. The API secret and the JSON desktop ledgers are not included. The manifest is not
signed: it detects corruption, not a deliberate rewrite of both a file and its hash.
"""

import argparse
import json
import os
import shutil
import socket
import sqlite3
import sys
import time
from pathlib import Path, PurePosixPath

from netwatch_config import build_config
from netwatch_evidence_catalog import file_digest
from netwatch_security_store import security_db_path

MANIFEST = "netwatch-backup.json"
STORE_KEYS = ("INCIDENT_DB", "DB_NAME", "SPOOL_PATH")


def _empty_directory(path, role):
    path = Path(path)
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"{role} {path} must be an empty directory")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _relative(path, base):
    try:
        return Path(path).resolve().relative_to(base).as_posix()
    except ValueError:
        # ponytail: stores/evidence configured outside the runtime directory are refused, not remapped.
        raise ValueError(f"{path} is outside the runtime directory {base}") from None


def _safe_target(root, relative):
    """Manifest paths are data: refuse anything that would land outside ``root``."""
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or ".." in parts or ":" in relative or "\\" in relative:
        raise ValueError(f"unsafe path in manifest: {relative!r}")
    return Path(root, *parts)


def _snapshot(source, destination):
    """Consistent copy of a live WAL database; the result is a single self-contained file."""
    src = sqlite3.connect(Path(source).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
    try:
        dst = sqlite3.connect(destination)
        try:
            src.backup(dst)  # one step: a single read transaction, so one point in time
            dst.execute("PRAGMA journal_mode=DELETE")
        finally:
            dst.close()
    finally:
        src.close()


def _integrity(path):
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return conn.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        conn.close()


def backup(base_dir, out_dir):
    base = Path(base_dir).resolve()
    if Path(out_dir).resolve().is_relative_to(base):
        raise ValueError("the backup directory must be outside the runtime directory")
    out = _empty_directory(out_dir, "backup directory")
    if os.name == "posix":
        out.chmod(0o700)  # the snapshots hold cases, notes and native payloads, like the 0600 live store
    # Detection is skipped: only the configured paths are needed here.
    config, _ = build_config(str(base), extra={"GATEWAY_IP": "backup", "LOCAL_PREFIXES6_AUTO": False})
    files = []

    def add(relative, kind):
        files.append({"path": relative, "kind": kind, "bytes": (out / relative).stat().st_size,
                      "sha256": file_digest(out / relative)})

    for key in STORE_KEYS:
        path = security_db_path(config) if key == "INCIDENT_DB" else config.get(key)
        if not path or not os.path.isfile(path):
            continue
        relative = _relative(path, base)
        (out / relative).parent.mkdir(parents=True, exist_ok=True)
        _snapshot(path, out / relative)
        if os.name == "posix":
            os.chmod(out / relative, 0o600)
        add(relative, "sqlite")
    for overlay in sorted(base.glob("netwatch.*.json")):
        shutil.copy2(overlay, out / overlay.name)
        add(overlay.name, "config")
    evidence = Path(config.get("EVIDENCE_DIR") or base / "evidence")
    if evidence.is_dir():
        _relative(evidence, base)
        for path in sorted(p for p in evidence.rglob("*") if p.is_file() and not p.is_symlink()):
            relative = _relative(path, base)
            (out / relative).parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(path, out / relative)
            except FileNotFoundError:
                continue  # pruned by retention while the backup ran
            add(relative, "evidence")
    manifest = {"format": 1, "created_at": time.time(), "hostname": socket.gethostname(),
                "base_dir": str(base), "files": files}
    (out / MANIFEST).write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    verify(out)
    return manifest


def verify(backup_dir):
    """Raise ValueError unless every listed file is present, matches its hash and every store is intact."""
    root = Path(backup_dir)
    manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("format") != 1 or not isinstance(manifest.get("files"), list):
        raise ValueError("unsupported backup manifest")
    problems = []
    for entry in manifest["files"]:
        path = _safe_target(root, entry["path"])
        if not path.is_file():
            problems.append(f"{entry['path']}: missing")
        elif file_digest(path) != entry["sha256"]:
            problems.append(f"{entry['path']}: SHA-256 mismatch")
        elif entry["kind"] == "sqlite":
            try:
                result = _integrity(path)
            except sqlite3.DatabaseError as exc:
                result = str(exc)
            if result != "ok":
                problems.append(f"{entry['path']}: integrity check failed: {result}")
    if problems:
        raise ValueError("backup verification failed: " + "; ".join(problems))
    return manifest


def restore(backup_dir, target_dir):
    manifest = verify(backup_dir)  # nothing is written unless the whole backup checks out
    target = _empty_directory(target_dir, "restore target")
    for entry in manifest["files"]:
        destination = _safe_target(target, entry["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_safe_target(backup_dir, entry["path"]), destination)
        if file_digest(destination) != entry["sha256"]:
            raise ValueError(f"{entry['path']}: restored copy does not match; {target} is incomplete")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Back up, verify or restore a NetWatch runtime directory")
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("backup", help="online backup of a runtime directory")
    make.add_argument("--base-dir", required=True, type=Path)
    make.add_argument("backup_dir", type=Path)
    check = commands.add_parser("verify", help="check hashes and SQLite integrity")
    check.add_argument("backup_dir", type=Path)
    put = commands.add_parser("restore", help="verify, then restore into an empty directory")
    put.add_argument("backup_dir", type=Path)
    put.add_argument("target_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            manifest = backup(args.base_dir, args.backup_dir)
        elif args.command == "verify":
            manifest = verify(args.backup_dir)
        else:
            manifest = restore(args.backup_dir, args.target_dir)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1
    print(f"{args.command} ok: {len(manifest['files'])} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
