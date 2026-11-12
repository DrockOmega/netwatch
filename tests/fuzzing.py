"""Seeded standard-library mutators for the parser robustness tests.

Every run uses a fixed seed, so a failure reproduces exactly. The mutations target what an attacker
controls on the wire or in a log line: flipped bits, truncation, lying length fields, deep nesting,
huge numbers and wrong JSON types.
"""

import json
import random

NASTY_VALUES = [
    None, True, False, 0, -1, 2**63, -(2**63) - 1, 10**400, 1e308, -1e308, 0.5, "", "x" * 5000,
    "\x00", "\ud800", "1:" + "A" * 27 + "=", "::", "999.1.1.1", "fe80::1%eth0", [], {}, [[[]]],
    {"a": {"b": {}}}, "NaN", "Infinity", "1e999", "2026-13-45T99:99:99Z", "-", "‮",
]


def mutate_bytes(rng, data, rounds=3):
    """Return a mutated copy of ``data``: bit flips, truncation, length-field lies, splices."""
    data = bytearray(data)
    for _ in range(rng.randint(1, rounds)):
        op = rng.randrange(6)
        if op == 0 and data:  # flip bits
            for _ in range(rng.randint(1, 8)):
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        elif op == 1 and data:  # truncate
            del data[rng.randrange(len(data) + 1):]
        elif op == 2 and len(data) >= 2:  # lie in a 16-bit length/count field
            at = rng.randrange(len(data) - 1)
            data[at:at + 2] = rng.choice([0, 1, 0x7FFF, 0xFFFF, len(data), len(data) + 1]).to_bytes(2, "big")
        elif op == 3 and data:  # set one byte to an edge value
            data[rng.randrange(len(data))] = rng.choice([0, 1, 0x3F, 0x40, 0x7F, 0x80, 0xC0, 0xFF])
        elif op == 4:  # insert random bytes
            at = rng.randrange(len(data) + 1)
            data[at:at] = rng.randbytes(rng.randint(1, 64))
        elif op == 5 and data:  # duplicate a slice (repeated headers/options)
            start = rng.randrange(len(data))
            data[start:start] = data[start:start + rng.randint(1, 64)]
    return bytes(data)


def deep(depth, leaf=0):
    value = leaf
    for _ in range(depth):
        value = [value]
    return value


def mutate_json(rng, value, depth=0):
    """Return a mutated copy of a JSON-like value: wrong types, huge numbers, nesting, dropped keys."""
    roll = rng.random()
    if roll < 0.08:
        return rng.choice(NASTY_VALUES)
    if roll < 0.10:
        return deep(rng.choice([50, 500]))
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if rng.random() < 0.1:
                continue  # dropped key
            out[key] = mutate_json(rng, item, depth + 1) if rng.random() < 0.4 else item
        if rng.random() < 0.1:
            out[rng.choice(["_path", "event_type", "id.orig_h", "ts", "timestamp", "alert", "x"])] = \
                rng.choice(NASTY_VALUES)
        return out
    if isinstance(value, list):
        return [mutate_json(rng, item, depth + 1) for item in value if rng.random() > 0.1]
    return value


def json_roundtrip(value):
    """Keep only what a JSON line can carry (the collectors read JSON, not Python objects)."""
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (ValueError, RecursionError):
        return None


def rng_for(name):
    return random.Random(f"netwatch-fuzz:{name}")
