"""Per-device behavioral baselining (roadmap #2).

The fixed-threshold detectors in ``netwatch_core`` ask "is this above an absolute
line?" (e.g. >10 MB in 10 s = exfil). Baselining asks a different, complementary
question: "is this abnormal *for this device*?" Each device learns its own normal
egress volume online, and a window that deviates far above that learned norm is
flagged — so a webcam that suddenly uploads 50x its usual volume trips even though
it never crosses a global threshold.

Design, consistent with the rest of NetWatch:
- **Pure + online.** ``EwmaStat`` keeps an exponentially-weighted mean and variance
  in O(1) memory per device (no packet history retained). ``BaselineTracker`` scores
  each window against the model learned *so far*, then folds it in.
- **Self-healing.** A transient spike alerts once or twice; a *sustained* new level
  is absorbed into the EWMA within ~1/alpha windows and stops alerting — legitimate
  behavior change becomes the new normal instead of a permanent false positive.
- **False-positive guards.** A regularity floor (min std as a fraction of the mean,
  plus an absolute floor) stops a very steady device from tripping on trivial
  absolute jitter. A warmup period suppresses scoring until enough samples exist.
- **One-sided.** Only upward deviations (spikes) are flagged; a device going quiet
  is not a volume threat.
- **Persisted + bounded.** The learned model serializes to JSON (the cloud-sync
  seam) and the key set is capped with LRU eviction.

Anomalies here are *notices to investigate*, never auto-mitigation triggers.
"""

import json
import math
import time

from netwatch_core import write_json_atomic


class EwmaStat:
    """Online exponentially-weighted mean + variance (West's incremental form).

    Tracks a single scalar stream in O(1) memory. ``alpha`` is the decay/learning
    rate: larger forgets faster. ``std`` is the EW standard deviation."""

    __slots__ = ("alpha", "mean", "var", "n")

    def __init__(self, alpha, mean=0.0, var=0.0, n=0):
        self.alpha = alpha
        self.mean = float(mean)
        self.var = float(var)
        self.n = int(n)

    def update(self, x):
        x = float(x)
        if self.n == 0:
            self.mean = x
            self.var = 0.0
        else:
            diff = x - self.mean
            incr = self.alpha * diff
            self.mean += incr
            # EW variance: shrink the old estimate and add the new squared deviation.
            self.var = (1.0 - self.alpha) * (self.var + diff * incr)
        self.n += 1

    @property
    def std(self):
        return math.sqrt(self.var) if self.var > 0.0 else 0.0

    def as_dict(self):
        return {"mean": self.mean, "var": self.var, "n": self.n}


class BaselineTracker:
    """Per-key online baseline with robust, one-sided spike detection.

    ``observe(key, value)`` feeds one per-window aggregate (e.g. a device's egress
    bytes in the window). It scores ``value`` against the model learned so far,
    then updates the model. Keys are typically device MACs."""

    def __init__(
        self,
        *,
        alpha=0.1,
        warmup=10,
        z_threshold=4.0,
        rel_floor=0.15,
        abs_floor=1.0,
        max_keys=512,
        ledger_path=None,
    ):
        self.alpha = alpha
        self.warmup = warmup
        self.z_threshold = z_threshold
        self.rel_floor = rel_floor      # min std as a fraction of |mean| (regularity guard)
        self.abs_floor = abs_floor      # absolute min std floor
        self.max_keys = max_keys
        self.ledger_path = ledger_path
        self.models = {}        # key -> EwmaStat
        self.last_seen = {}     # key -> ts
        self._dirty = False
        if ledger_path:
            self._load()

    def observe(self, key, value, now=None):
        """Score ``value`` for ``key`` against its learned baseline, then learn it.

        Returns a result dict: ``anomaly`` is True only after warmup and when the
        robust, one-sided z-score exceeds ``z_threshold``. ``learning`` is True while
        still in warmup."""
        now = time.time() if now is None else now
        value = float(value)

        stat = self.models.get(key)
        if stat is None:
            if len(self.models) >= self.max_keys:
                self._evict_one()
            stat = EwmaStat(self.alpha)
            self.models[key] = stat

        learning = stat.n < self.warmup
        # Robust spread: never let a hyper-regular device score on trivial jitter.
        eff_std = max(stat.std, self.rel_floor * abs(stat.mean), self.abs_floor)
        z = 0.0 if learning else (value - stat.mean) / eff_std
        anomaly = (not learning) and z > self.z_threshold  # one-sided: spikes only

        stat.update(value)
        self.last_seen[key] = now
        self._dirty = True
        return {
            "key": key,
            "value": value,
            "mean": stat.mean,
            "std": stat.std,
            "z": z,
            "anomaly": anomaly,
            "learning": learning,
            "n": stat.n,
        }

    def snapshot(self):
        """Sorted, copied view of the learned baselines for a CLI/UI."""
        return [
            {
                "key": k,
                "mean": s.mean,
                "std": s.std,
                "n": s.n,
                "last_seen": self.last_seen.get(k, 0.0),
            }
            for k, s in sorted(self.models.items())
        ]

    def save(self):
        """Flush to the ledger if anything changed since the last write."""
        if self._dirty:
            self._save()

    # --- internals -------------------------------------------------------
    def _evict_one(self):
        """Drop the least-recently-seen key to stay under ``max_keys``."""
        if not self.last_seen:
            # No timestamps yet (all brand new): drop an arbitrary key.
            victim = next(iter(self.models))
        else:
            victim = min(self.last_seen, key=self.last_seen.get)
        self.models.pop(victim, None)
        self.last_seen.pop(victim, None)

    def _save(self):
        if not self.ledger_path:
            self._dirty = False
            return
        payload = {
            "models": {k: s.as_dict() for k, s in self.models.items()},
            "last_seen": self.last_seen,
        }
        if write_json_atomic(self.ledger_path, payload):
            self._dirty = False

    def _load(self):
        try:
            with open(self.ledger_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        for k, d in data.get("models", {}).items():
            self.models[k] = EwmaStat(self.alpha, d.get("mean", 0.0), d.get("var", 0.0), d.get("n", 0))
        self.last_seen = dict(data.get("last_seen", {}))
