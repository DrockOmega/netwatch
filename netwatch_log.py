"""Process-aware logging for NetWatch.

Every diagnostic used to be a bare ``print()``, which is invisible the moment the
app runs detached (which is the point of a monitor). This gives each of the four
processes a rotating file plus the console it may or may not have.

One file *per component* on purpose: ``RotatingFileHandler`` rotation is not
multi-process safe on Windows — concurrent rotation of a shared file fails on the
open handle. Separate files sidestep it entirely.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_FORMAT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(component, config=None):
    """Configure and return the logger for one process. Idempotent: calling it
    twice in the same process reuses the handlers already installed.

    A failure to open the log file is never fatal — the console handler stays and
    the reason is emitted through it."""
    config = config or {}
    logger = logging.getLogger(f"netwatch.{component}")
    if logger.handlers:
        return logger

    level = getattr(logging, str(config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    logger.setLevel(level)
    logger.propagate = False
    formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    if config.get("LOG_TO_CONSOLE", True):
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        logger.addHandler(console)

    log_dir = config.get("LOG_DIR")
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            handler = RotatingFileHandler(
                os.path.join(log_dir, f"netwatch-{component}.log"),
                maxBytes=int(config.get("LOG_MAX_BYTES", 5_000_000)),
                backupCount=int(config.get("LOG_BACKUPS", 3)),
                encoding="utf-8",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        except OSError as exc:
            logger.warning("file logging disabled — %s: %s", type(exc).__name__, exc)

    return logger
