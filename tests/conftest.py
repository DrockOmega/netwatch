"""Shared fixtures/helpers for the NetWatch core test suite.

Builds a single arena row from the *same* dtype the DOD core allocates
(``netwatch_core.arena_dtype``), with a small bucket count so the windowing and
bucket-expiry edges are easy to drive in tests.
"""

import numpy as np

from netwatch_core import arena_dtype

TEST_BUCKETS = 4


def make_arena_row(buckets=TEST_BUCKETS):
    """Return one zeroed arena row with the live arena's field layout."""
    return np.zeros(1, dtype=arena_dtype(buckets))[0]


def base_config(buckets=TEST_BUCKETS):
    """Detector thresholds sized for deterministic tests."""
    return {
        "DETECTOR_BUCKETS": buckets,
        "EXFIL_THRESHOLD_BYTES": 1000,
        "EXFIL_WINDOW_SEC": 10,
        "SWEEP_WINDOW_SEC": 5,
        "SWEEP_THRESHOLD_PORTS": 3,
        "UDP_FLOOD_WINDOW_SEC": 2,
        "UDP_FLOOD_THRESHOLD": 3,
    }
