"""Unit tests for the per-entity anomaly detectors.

These exercise the bucket-ring / bitmap / windowed-sum arithmetic that is the
most likely place for off-by-one bugs to hide. Thresholds come from
``conftest.base_config`` (flood=3, sweep=3, exfil=1000 bytes) with 4 buckets per
window, so one bucket is UDP_FLOOD_WINDOW_SEC/4 = 0.5s and
EXFIL_WINDOW_SEC/4 = 2.5s wide.
"""

from conftest import base_config, make_arena_row

from netwatch_core import (
    AlertGate,
    _roll_window,
    analyze_port_sweep,
    analyze_udp_flood,
    analyze_volumetric_exfil,
)


def test_alert_gate_suppresses_sustained_condition_until_cooldown():
    gate = AlertGate(cooldown_sec=60)
    assert gate.allow("udp", "10.0.0.5", 1000) is True
    assert gate.allow("udp", "10.0.0.5", 1059) is False
    assert gate.allow("udp", "10.0.0.5", 1060) is True
    assert gate.allow("exfil", "10.0.0.5", 1060) is True

def test_alert_gate_bounded_under_key_flood():
    gate = AlertGate(60)
    for i in range(10_000):
        gate.allow("scan", f"k{i}", 1000 + i / 1000)
    assert len(gate.last_alert) <= 4096
    assert gate.allow("scan", "k9999", 1000 + 10) is False  # fed within the last second

# --- UDP flood -------------------------------------------------------------


def test_udp_flood_fires_just_over_threshold():
    row, cfg = make_arena_row(), base_config()
    t = 1000.0
    # threshold is strictly-greater: 3 packets stay quiet, the 4th alerts.
    assert analyze_udp_flood(row, t, cfg, "1.1.1.1") is None
    assert analyze_udp_flood(row, t, cfg, "1.1.1.1") is None
    assert analyze_udp_flood(row, t, cfg, "1.1.1.1") is None
    assert analyze_udp_flood(row, t, cfg, "1.1.1.1") is not None


def test_udp_flood_resets_after_alert():
    row, cfg = make_arena_row(), base_config()
    t = 1000.0
    for _ in range(4):
        analyze_udp_flood(row, t, cfg, "1.1.1.1")
    # after the alert the window collapsed; a single fresh packet is quiet again.
    assert analyze_udp_flood(row, t, cfg, "1.1.1.1") is None


def test_udp_flood_window_expiry_drops_old_packets():
    row, cfg = make_arena_row(), base_config()
    # 3 packets at t0, then advance past the 2s window: stale packets age out so
    # the count never crosses the threshold.
    for _ in range(3):
        analyze_udp_flood(row, 1000.0, cfg, "1.1.1.1")
    assert analyze_udp_flood(row, 1100.0, cfg, "1.1.1.1") is None


# --- port sweep ------------------------------------------------------------


def test_port_sweep_fires_on_distinct_ports():
    row, cfg = make_arena_row(), base_config()
    t = 1000.0
    assert analyze_port_sweep(row, t, cfg, "1.1.1.1", 80) is None
    assert analyze_port_sweep(row, t, cfg, "1.1.1.1", 443) is None
    assert analyze_port_sweep(row, t, cfg, "1.1.1.1", 22) is None
    assert analyze_port_sweep(row, t, cfg, "1.1.1.1", 3389) is not None


def test_port_sweep_ignores_server_replies_to_ephemeral_ports():
    row, cfg = make_arena_row(), base_config()
    for port in range(49152, 49152 + 200):  # a resolver answering 200 client queries
        assert analyze_port_sweep(row, 1000.0, cfg, "75.75.75.75", port, sport=53) is None
    prober = make_arena_row()
    results = [analyze_port_sweep(prober, 1000.0, cfg, "203.0.113.9", port, sport=51000)
               for port in (80, 443, 22, 3389)]  # an ephemeral-port prober is still counted
    assert results[-1] is not None


def test_port_sweep_counts_only_bare_syns_when_flags_given():
    cfg = base_config()
    for flags in ("SA", "R", "RA", "PA", "A", "F"):
        row = make_arena_row()
        assert all(analyze_port_sweep(row, 1000.0, cfg, "10.0.0.1", p, 2000, flags) is None
                   for p in (80, 443, 22, 3389))
    row = make_arena_row()
    assert [analyze_port_sweep(row, 1000.0, cfg, "10.0.0.9", p, 51000, "S") for p in (80, 443, 22, 3389)][-1]


def test_port_sweep_ignores_duplicate_ports():
    row, cfg = make_arena_row(), base_config()
    t = 1000.0
    for _ in range(10):
        # hammering one port must not advance the distinct-port count.
        assert analyze_port_sweep(row, t, cfg, "1.1.1.1", 80) is None


def test_port_sweep_high_port_no_index_error():
    row, cfg = make_arena_row(), base_config()
    # dport 65535 -> bitmap index 1023, bit 63: must land inside the 1024xu64 map.
    assert analyze_port_sweep(row, 1000.0, cfg, "1.1.1.1", 65535) is None


def test_port_sweep_window_reset_clears_bitmap():
    row, cfg = make_arena_row(), base_config()
    for p in (80, 443, 22):
        analyze_port_sweep(row, 1000.0, cfg, "1.1.1.1", p)
    # new window: counter resets, so three fresh distinct ports stay quiet again.
    assert analyze_port_sweep(row, 2000.0, cfg, "1.1.1.1", 1) is None
    assert analyze_port_sweep(row, 2000.0, cfg, "1.1.1.1", 2) is None
    assert analyze_port_sweep(row, 2000.0, cfg, "1.1.1.1", 3) is None


# --- volumetric exfil ------------------------------------------------------


def test_exfil_fires_when_sum_crosses_threshold():
    row, cfg = make_arena_row(), base_config()
    t = 1000.0
    assert analyze_volumetric_exfil(row, t, cfg, "8.8.8.8", 500) is None
    assert analyze_volumetric_exfil(row, t, cfg, "8.8.8.8", 500) is None
    # cumulative 1500 > 1000 threshold.
    assert analyze_volumetric_exfil(row, t, cfg, "8.8.8.8", 500) is not None


def test_exfil_window_expiry_ages_out_bytes():
    row, cfg = make_arena_row(), base_config()
    analyze_volumetric_exfil(row, 1000.0, cfg, "8.8.8.8", 900)
    # 900 bytes age out past the 10s window before the next chunk lands.
    assert analyze_volumetric_exfil(row, 1100.0, cfg, "8.8.8.8", 900) is None


def test_exfil_sum_is_windowed_not_lifetime():
    # 300b every full window: each observation lands in a fresh bucket ring, so the
    # trailing sum tracks the window, never the lifetime total.
    row, cfg = make_arena_row(), base_config()
    results = [analyze_volumetric_exfil(row, 1000.0 + i * 11.0, cfg, "8.8.8.8", 300) for i in range(8)]
    assert all(r is None for r in results)


def test_exfil_partial_window_expiry_deducts_only_aged_buckets():
    # 4 buckets over 10s => 2.5s each. 600b now and 600b one bucket later are both
    # inside the window (1200 > 1000 fires); the older 600 has NOT aged out.
    row, cfg = make_arena_row(), base_config()
    assert analyze_volumetric_exfil(row, 1000.0, cfg, "8.8.8.8", 600) is None
    assert analyze_volumetric_exfil(row, 1003.0, cfg, "8.8.8.8", 600) is not None


# --- bucket ring arithmetic ------------------------------------------------


def test_roll_window_zeroes_only_skipped_buckets():
    row = make_arena_row()
    buckets, state = row['vol_buckets'], row['vol_state']
    # fill two adjacent buckets by hand through the roll
    i0 = _roll_window(buckets, state, 1000.0, 10.0, 4)
    buckets[i0] += 100.0
    state[1] += 100.0
    i1 = _roll_window(buckets, state, 1003.0, 10.0, 4)
    buckets[i1] += 50.0
    state[1] += 50.0
    assert i0 != i1
    assert state[1] == 150.0          # nothing aged out yet
    # advance far enough that only the oldest bucket falls off the ring
    _roll_window(buckets, state, 1011.0, 10.0, 4)
    assert state[1] == 50.0


def test_roll_window_clears_on_large_gap_and_clock_step_back():
    row = make_arena_row()
    buckets, state = row['vol_buckets'], row['vol_state']
    idx = _roll_window(buckets, state, 1000.0, 10.0, 4)
    buckets[idx] += 900.0
    state[1] += 900.0
    _roll_window(buckets, state, 5000.0, 10.0, 4)   # far future
    assert state[1] == 0.0
    buckets[_roll_window(buckets, state, 5000.0, 10.0, 4)] += 400.0
    state[1] += 400.0
    _roll_window(buckets, state, 100.0, 10.0, 4)    # clock stepped backwards
    assert state[1] == 0.0


def test_running_total_never_goes_negative_across_many_windows():
    row, cfg = make_arena_row(), base_config()
    for i in range(200):
        analyze_volumetric_exfil(row, 1000.0 + i * 0.7, cfg, "8.8.8.8", 10)
        assert row['vol_state'][1] >= 0.0


def test_sweep_target_tracking_is_bounded_ordered_and_resets_per_window():
    from netwatch_core import MAX_SWEEP_SOURCES, MAX_SWEEP_TARGETS, track_sweep_target
    targets = {}
    for i in range(MAX_SWEEP_TARGETS + 5):
        track_sweep_target(targets, b"s", f"10.0.0.{i}", i == 0)
    assert list(targets[b"s"]) == [f"10.0.0.{i}" for i in range(MAX_SWEEP_TARGETS)]
    track_sweep_target(targets, b"s", "10.9.9.9", True)
    assert list(targets[b"s"]) == ["10.9.9.9"]
    for i in range(MAX_SWEEP_SOURCES + 1):
        track_sweep_target(targets, i, "10.0.0.1", False)
    assert len(targets) == MAX_SWEEP_SOURCES


def test_port_sweep_resets_after_backward_clock_step():
    row, cfg = make_arena_row(), base_config()
    analyze_port_sweep(row, 100000.0, cfg, "1.1.1.1", 1)
    # Clock steps back by more than a window; one port per minute must not accumulate.
    t = 1000.0
    for port in range(2, 2 + cfg["SWEEP_THRESHOLD_PORTS"] + 20):
        assert analyze_port_sweep(row, t, cfg, "1.1.1.1", port) is None
        t += 60.0
