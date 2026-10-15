"""Run monitoring without a graphical session: python -m netwatch_service."""

import argparse
import multiprocessing as mp
import os
import signal
import sqlite3
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from multiprocessing import resource_tracker
from pathlib import Path

from netwatch_api import ServiceAPI, load_secret, secret_path
from netwatch_config import build_config
from netwatch_log import setup_logging
from netwatch_privilege import drop_effective_privileges, run_without_ambient
from netwatch_runtime import ServiceSupervisor
from netwatch_security_store import security_db_path, sqlite_wal_safe

# Close-path allowance past the drain budget; grace 60 + 20 stays under the unit's TimeoutStopSec=90.
STOP_CLOSE_SEC = 20
STOP_FILE = "netwatch.stop"


@contextmanager
def service_lock(path):
    """A process-lifetime lock shared by instances using the same ledger."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError("monitoring service already owns this ledger") from exc
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError("monitoring service already owns this ledger") from exc
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Supervised NetWatch monitoring service")
    parser.add_argument("--base-dir", type=Path, default=Path(__file__).resolve().parent,
                        help="configuration and runtime data directory")
    parser.add_argument("--api-host", default="127.0.0.1")
    parser.add_argument("--api-port", type=int, default=8765)
    parser.add_argument("--allow-non-loopback", action="store_true",
                        help="explicitly enable SERVICE_API_ALLOW_NON_LOOPBACK (unencrypted HTTP)")
    args = parser.parse_args(argv)
    base = args.base_dir.resolve()
    try:
        config, notes = build_config(str(base), resource_dir=str(Path(__file__).resolve().parent))
    except Exception:
        # Before logging exists; the SYSTEM task discards stderr, so leave a line where the log would be.
        (base / "logs").mkdir(parents=True, exist_ok=True)
        with open(base / "logs" / "netwatch-service.log", "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} CRITICAL [netwatch.service] "
                         f"configuration failed; not starting\n{traceback.format_exc()}")
        raise
    config["SERVICE_API_ALLOW_NON_LOOPBACK"] = args.allow_non_loopback
    log = setup_logging("service", config)
    for note in notes:
        (log.warning if note.startswith("WARNING") else log.info)("%s", note)
    if not sqlite_wal_safe():  # the sensor's security store was corrupted twice by it (2026-10-10/11)
        log.critical("SQLite %s has the WAL-reset corruption bug; not starting. Install 3.51.3 or later "
                     "(the interpreter's sqlite3 library)", sqlite3.sqlite_version)
        return 2
    stop = threading.Event()
    exit_after = float(config.get("RUNTIME_STOP_GRACE_SEC", 60)) + STOP_CLOSE_SEC

    def hard_exit():
        # A disk stall can block a step no timeout reaches (fsync, joining an unreapable child).
        # The next start records the unordered stop as a gap unless close() already recorded it.
        log.critical("stop did not finish within %.0fs; exiting without completing close", exit_after)
        os._exit(1)

    timer = threading.Timer(exit_after, hard_exit)
    timer.daemon = True

    def request_stop(*_):
        if not stop.is_set():
            timer.start()
        stop.set()

    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_stop)
    # Task Scheduler's End is TerminateProcess, which no handler sees: on Windows an ordered
    # stop is asked for by creating this file (see the README's headless service section). A stale one must not stop a start.
    stop_file = base / STOP_FILE
    stop_file.unlink(missing_ok=True)
    # Supervisor and API run without effective raw-socket privilege; permitted/ambient
    # stay only so a restarted capture worker inherits them (see packaging/linux).
    drop_effective_privileges()
    # ponytail: a resource tracker that dies and is relaunched later would inherit ambient again.
    if sys.platform.startswith("linux"):  # resource tracker is POSIX-only; ambient caps are Linux-only
        run_without_ambient(resource_tracker.ensure_running)
    path = security_db_path(config)
    try:
        with service_lock(path + ".service.lock"):
            supervisor = ServiceSupervisor(config)
            api = None
            try:
                api = ServiceAPI(supervisor, load_secret(secret_path(config), create=True),
                                 host=args.api_host, port=args.api_port).start()
                while not stop.is_set():
                    try:
                        supervisor.tick()
                    except sqlite3.OperationalError as exc:
                        # A shared-store writer outlasting the busy timeout is transient;
                        # the next tick redoes the work. Anything else still stops the service.
                        if "locked" not in str(exc) and "busy" not in str(exc):
                            raise
                        log.warning("supervisor tick deferred: %s at %s", exc, " <- ".join(
                            f"{os.path.basename(f.filename)}:{f.lineno} {f.name}"
                            for f in reversed(traceback.extract_tb(exc.__traceback__)[-3:])))
                    if stop_file.exists():
                        log.info("stop requested by %s", stop_file)
                        stop_file.unlink(missing_ok=True)
                        request_stop()
                    stop.wait(0.2)
            finally:
                if api is not None:
                    api.close()
                supervisor.close()
                timer.cancel()
    except Exception:
        # A scheduled task or unit may discard stderr; the log is the only witness.
        # This covers startup too: lock held, store unopenable, rule pack invalid.
        log.exception("service stopped on an unhandled error")
        raise
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
