"""Unit tests for per-device baselining: the online EWMA mean/variance, robust
one-sided anomaly scoring, warmup, self-healing, eviction, and persistence."""

import json

from netwatch_baseline import BaselineTracker, EwmaStat

# --- EwmaStat --------------------------------------------------------------


def test_ewma_first_sample_sets_mean_zero_var():
    s = EwmaStat(alpha=0.2)
    s.update(42.0)
    assert s.mean == 42.0
    assert s.std == 0.0
    assert s.n == 1


def test_ewma_constant_stream_converges():
    s = EwmaStat(alpha=0.3)
    for _ in range(50):
        s.update(100.0)
    assert abs(s.mean - 100.0) < 1e-9
    assert s.std < 1e-6  # no variance in a constant stream


def test_ewma_tracks_a_level_shift():
    s = EwmaStat(alpha=0.3)
    for _ in range(50):
        s.update(10.0)
    for _ in range(50):
        s.update(20.0)
    assert 19.0 < s.mean <= 20.0  # mean has migrated toward the new level


# --- baseline scoring ------------------------------------------------------


def stable_then(tracker, key, stable_val, n_stable, *, start=0.0):
    t = start
    for _ in range(n_stable):
        tracker.observe(key, stable_val, now=t)
        t += 1.0
    return t


def test_no_anomaly_during_warmup():
    bt = BaselineTracker(warmup=5, z_threshold=4.0)
    # Even a wild value during warmup must not fire.
    for i in range(5):
        r = bt.observe("dev", 1_000_000 if i == 4 else 100, now=float(i))
        assert r["anomaly"] is False
        assert r["learning"] is True


def test_spike_after_warmup_flags():
    bt = BaselineTracker(warmup=5, z_threshold=4.0, alpha=0.2)
    t = stable_then(bt, "dev", 100.0, 10)
    r = bt.observe("dev", 5000.0, now=t)
    assert r["learning"] is False
    assert r["anomaly"] is True
    assert r["z"] > 4.0


def test_small_jump_on_regular_device_does_not_fire():
    # Perfectly steady at 100; a +10 nudge is trivial relative to the regularity
    # floor (rel_floor*mean = 15), so it must NOT be an anomaly.
    bt = BaselineTracker(warmup=5, z_threshold=4.0, rel_floor=0.15)
    t = stable_then(bt, "dev", 100.0, 10)
    r = bt.observe("dev", 110.0, now=t)
    assert r["anomaly"] is False


def test_idle_device_byte_jitter_does_not_fire_with_byte_floor():
    # Regression: the monitor feeds egress in BYTES, so it configures abs_floor in
    # bytes (main.py BASELINE_ABS_FLOOR=50_000). A near-idle device (e.g. a phone
    # with a randomized MAC sending a few hundred bytes of keepalives per window)
    # must not score huge sigma on trivial byte-scale jitter. Without a byte-scale
    # floor (class default 1.0) this fired at 9-16σ and rendered as "0.00MB over 0.00MB".
    bt = BaselineTracker(warmup=5, z_threshold=4.0, rel_floor=0.15, abs_floor=50_000)
    t = 0.0
    for v in (300, 250, 400, 200, 350, 300, 280, 320, 260, 300):  # bytes/window
        bt.observe("phone", v, now=t)
        t += 1.0
    for jitter in (700.0, 5_000.0, 40_000.0):  # all sub-50 KB swings -> noise
        r = bt.observe("phone", jitter, now=t)
        assert r["anomaly"] is False, f"{jitter}B jitter should not alert (z={r['z']:.1f})"
        t += 1.0


def test_idle_device_real_spike_still_fires_with_byte_floor():
    # The byte floor silences noise, NOT genuine spikes: an idle device suddenly
    # egressing hundreds of KB in a window is a real notice and must still fire.
    bt = BaselineTracker(warmup=5, z_threshold=4.0, rel_floor=0.15, abs_floor=50_000)
    t = stable_then(bt, "phone", 300.0, 10)
    r = bt.observe("phone", 300_000.0, now=t)  # ~0 -> 300 KB
    assert r["anomaly"] is True
    assert r["z"] > 4.0


def test_one_sided_drop_is_not_anomaly():
    bt = BaselineTracker(warmup=5, z_threshold=4.0)
    t = stable_then(bt, "dev", 1000.0, 10)
    r = bt.observe("dev", 1.0, now=t)  # huge drop
    assert r["z"] < 0
    assert r["anomaly"] is False


def test_sustained_new_level_self_heals():
    bt = BaselineTracker(warmup=5, z_threshold=4.0, alpha=0.3)
    t = stable_then(bt, "dev", 100.0, 10)
    fired = []
    for _ in range(40):
        r = bt.observe("dev", 5000.0, now=t)
        fired.append(r["anomaly"])
        t += 1.0
    assert fired[0] is True          # the jump alerts
    assert fired[-1] is False        # ...but a sustained new normal stops alerting
    assert any(fired) and not all(fired)


# --- eviction + persistence ------------------------------------------------


def test_eviction_bounds_key_count():
    bt = BaselineTracker(warmup=1, max_keys=3)
    for i in range(10):
        bt.observe(f"dev{i}", 100.0, now=float(i))
    assert len(bt.models) <= 3
    # the most recent keys survive; the oldest were evicted
    assert "dev9" in bt.models
    assert "dev0" not in bt.models


def test_persistence_continues_not_rewarms(tmp_path):
    ledger = str(tmp_path / "baseline.json")
    bt1 = BaselineTracker(warmup=5, ledger_path=ledger, alpha=0.2)
    t = stable_then(bt1, "dev", 100.0, 10)
    bt1.save()
    # A reloaded tracker must keep the learned model: NOT in warmup, and a spike
    # fires immediately rather than re-learning from scratch.
    bt2 = BaselineTracker(warmup=5, ledger_path=ledger, alpha=0.2)
    assert bt2.models["dev"].n == 10
    r = bt2.observe("dev", 5000.0, now=t)
    assert r["learning"] is False and r["anomaly"] is True
    on_disk = json.loads((tmp_path / "baseline.json").read_text())
    assert "dev" in on_disk["models"]


def test_corrupt_ledger_degrades(tmp_path):
    ledger = tmp_path / "baseline.json"
    ledger.write_text("{ not json")
    bt = BaselineTracker(ledger_path=str(ledger))
    assert bt.snapshot() == []  # corrupt → empty, no crash
