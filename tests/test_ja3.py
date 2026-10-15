"""Unit tests for JA3/JA3S: ClientHello/ServerHello parsing, canonical string +
hash (against independently-computed reference values), GREASE handling, defensive
parsing, and the Ja3Watch inventory + blocklist."""

import json
import struct

import pytest

from netwatch_ja3 import (
    GREASE,
    Ja3Watch,
    fingerprint,
    ja3_string,
    ja3s_string,
    ja4_string,
    load_blocklist,
    md5,
    parse_client_hello,
    parse_server_hello,
)


def _u16(x):
    return struct.pack(">H", x)


def build_client_hello(version=0x0303, ciphers=(0x1301, 0x002f), sni="test.com",
                       curves=(0x001d, 0x0017), point_formats=(0,), extra_extensions=()):
    exts = b"".join(_u16(t) + _u16(0) for t in extra_extensions)
    if sni is not None:
        name = sni.encode()
        sni_list = b"\x00" + _u16(len(name)) + name           # name_type=0, len, name
        sni_data = _u16(len(sni_list)) + sni_list
        exts += _u16(0) + _u16(len(sni_data)) + sni_data
    groups = b"".join(_u16(c) for c in curves)
    sg = _u16(len(groups)) + groups
    exts += _u16(10) + _u16(len(sg)) + sg
    pf = bytes(point_formats)
    pf_data = bytes([len(pf)]) + pf
    exts += _u16(11) + _u16(len(pf_data)) + pf_data

    cs = b"".join(_u16(c) for c in ciphers)
    body = (_u16(version) + b"\x00" * 32 + b"\x00"            # version, random, sid_len=0
            + _u16(len(cs)) + cs + b"\x01\x00"               # ciphers, compression
            + _u16(len(exts)) + exts)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def build_server_hello(version=0x0303, cipher=0x1301, ext_types=(0, 11)):
    exts = b""
    for t in ext_types:
        data = b"\x01\x00" if t == 11 else b""
        exts += _u16(t) + _u16(len(data)) + data
    body = (_u16(version) + b"\x00" * 32 + b"\x00"            # version, random, sid_len=0
            + _u16(cipher) + b"\x00"                          # chosen cipher, compression
            + _u16(len(exts)) + exts)
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


# --- client parsing --------------------------------------------------------


def test_parse_client_hello_fields():
    c = parse_client_hello(build_client_hello())
    assert c["version"] == 771
    assert c["ciphers"] == [4865, 47]
    assert c["extensions"] == [0, 10, 11]
    assert c["curves"] == [29, 23]
    assert c["point_formats"] == [0]
    assert c["sni"] == "test.com"


def test_ja3_string_and_hash_reference():
    c = parse_client_hello(build_client_hello())
    assert ja3_string(c) == "771,4865-47,0-10-11,29-23,0"
    # Independently computed (hashlib.md5 of the string above).
    assert md5(ja3_string(c)) == "3531b5ff032a39f9aa3617d1c231b510"


def test_fingerprint_client():
    fp = fingerprint(build_client_hello())
    assert fp["kind"] == "ja3"
    assert fp["hash"] == "3531b5ff032a39f9aa3617d1c231b510"
    assert fp["sni"] == "test.com"
    assert fp["ja4"] == ja4_string(parse_client_hello(build_client_hello()))


def test_ja4_is_order_stable_and_ignores_grease():
    normal = parse_client_hello(build_client_hello(ciphers=(0x1301, 0x002f)))
    reordered = parse_client_hello(build_client_hello(ciphers=(0x002f, 0x0a0a, 0x1301)))
    assert ja4_string(normal) == ja4_string(reordered)
    assert ja4_string(normal).startswith("t12d020300_")


@pytest.mark.parametrize("grease", sorted(GREASE))
def test_ja3_ignores_grease_in_all_reserved_fields(grease):
    payload = build_client_hello(
        ciphers=(grease, 0x1301, 0x002f, grease),
        curves=(grease, 0x001d, 0x0017), extra_extensions=(grease,),
    )
    c = parse_client_hello(payload)
    # Parsing preserves wire evidence; only fingerprint canonicalization filters it.
    assert c["ciphers"] == [grease, 4865, 47, grease]
    assert c["extensions"] == [grease, 0, 10, 11]
    assert c["curves"] == [grease, 29, 23]
    assert ja3_string(c) == "771,4865-47,0-10-11,29-23,0"
    assert fingerprint(payload)["hash"] == "3531b5ff032a39f9aa3617d1c231b510"


def test_ja3_preserves_non_grease_order():
    c = parse_client_hello(build_client_hello(
        ciphers=(0x002f, 0x0a0a, 0x1301),
        curves=(0x0017, 0x1a1a, 0x001d), extra_extensions=(21, 0x2a2a, 13),
    ))
    assert ja3_string(c) == "771,47-4865,21-13-0-10-11,23-29,0"


def test_published_ja3_reference_vector():
    # Salesforce README reference vector, independent of our TLS fixture builder.
    c = {"version": 769, "ciphers": [47, 53, 5, 10, 49161, 49162, 49171,
                                      49172, 50, 56, 19, 4],
         "extensions": [0, 10, 11], "curves": [23, 24, 25], "point_formats": [0]}
    assert md5(ja3_string(c)) == "ada70206e40642a3e4461f35503241d5"


def test_grease_fingerprint_matches_canonical_blocklist():
    fp = fingerprint(build_client_hello(ciphers=(0x0a0a, 0x1301, 0x002f)))
    w = Ja3Watch(blocklist={"3531b5ff032a39f9aa3617d1c231b510"})
    assert w.observe(fp["hash"], fp["kind"], fp["sni"], "10.0.0.5") is not None


# --- server parsing --------------------------------------------------------


def test_parse_server_hello_and_ja3s():
    s = parse_server_hello(build_server_hello())
    assert s["version"] == 771 and s["cipher"] == 4865
    assert s["extensions"] == [0, 11]
    assert ja3s_string(s) == "771,4865,0-11"
    assert md5(ja3s_string(s)) == "5c627a9da639bafc96627858609f9dd4"


def test_fingerprint_server():
    fp = fingerprint(build_server_hello())
    assert fp["kind"] == "ja3s"
    assert fp["hash"] == "5c627a9da639bafc96627858609f9dd4"


def test_ja3s_retains_wire_extension_order_like_upstream():
    # Salesforce's JA3S implementation records all server extension codes.
    s = parse_server_hello(build_server_hello(ext_types=(11, 0x0a0a, 0)))
    assert ja3s_string(s) == "771,4865,11-2570-0"


# --- defensive parsing -----------------------------------------------------


def test_non_tls_returns_none():
    assert fingerprint(b"\x47\x45\x54\x20\x2f hello not tls") is None
    assert fingerprint(b"") is None
    assert parse_client_hello(b"\x16\x03\x01\x00") is None  # too short


def test_truncated_hello_no_crash():
    full = build_client_hello()
    for cut in range(6, len(full)):
        assert fingerprint(full[:cut]) is None


# --- Ja3Watch --------------------------------------------------------------


def test_inventory_counts():
    w = Ja3Watch()
    w.observe("abc123", "ja3", "a.com", "10.0.0.5", now=1.0)
    w.observe("abc123", "ja3", "a.com", "10.0.0.5", now=2.0)
    snap = w.snapshot()
    assert len(snap) == 1 and snap[0]["count"] == 2 and snap[0]["blocklisted"] is False


def test_blocklist_hit():
    w = Ja3Watch(blocklist={"deadbeef"})
    assert w.observe("abc123", "ja3", None, "10.0.0.5", now=1.0) is None
    hit = w.observe("deadbeef", "ja3", "evil.com", "10.0.0.9", now=2.0)
    assert hit is not None and hit["kind"] == "JA3_BLOCKLIST" and hit["severity"] == "alert"
    assert w.snapshot()[0]["blocklisted"] or any(r["blocklisted"] for r in w.snapshot())


def test_load_blocklist(tmp_path):
    p = tmp_path / "bl.json"
    p.write_text(json.dumps({"blocklist": ["AAA111", "bbb222"]}))
    bl = load_blocklist(str(p))
    assert bl == {"aaa111", "bbb222"}                 # normalized lowercase
    assert load_blocklist(str(tmp_path / "missing.json")) == set()


def test_persistence(tmp_path):
    ledger = str(tmp_path / "ja3.json")
    w1 = Ja3Watch(ledger_path=ledger)
    w1.observe("abc123", "ja3", "a.com", "10.0.0.5", now=1.0)
    w1.save()
    w2 = Ja3Watch(ledger_path=ledger)
    assert w2.seen["abc123"]["count"] == 1
    assert json.loads((tmp_path / "ja3.json").read_text())["seen"]["abc123"]["kind"] == "ja3"


def test_legacy_ja3_is_labeled_and_preserved_on_save(tmp_path):
    ledger = tmp_path / "ja3.json"
    old = {"kind": "ja3", "count": 2, "first_seen": 1, "last_seen": 2,
           "sni": "test.com", "peer": "10.0.0.5"}
    ledger.write_text(json.dumps({"seen": {"old-hash": old}}))
    w = Ja3Watch(ledger_path=str(ledger), blocklist={"old-hash"})
    assert w.snapshot()[0]["format"] == "ja3-legacy-grease-v1"
    assert w.snapshot()[0]["blocklisted"] is False
    w.observe("new-hash", "ja3", None, "10.0.0.5", now=3)
    w.save()
    reloaded = Ja3Watch(ledger_path=str(ledger))
    assert reloaded.seen["old-hash"] == {**old, "format": "ja3-legacy-grease-v1"}
    assert reloaded.seen["new-hash"]["format"] == "ja3-canonical-v1"


def test_legacy_ja3_reobserved_as_canonical_is_labeled_mixed(tmp_path):
    ledger = tmp_path / "ja3.json"
    ledger.write_text(json.dumps({"seen": {"same-hash": {
        "kind": "ja3", "count": 2, "first_seen": 1, "last_seen": 2,
        "sni": "", "peer": "10.0.0.5",
    }}}))
    w = Ja3Watch(ledger_path=str(ledger))
    w.observe("same-hash", "ja3", None, "10.0.0.5", now=3)
    assert w.snapshot()[0]["format"] == "ja3-mixed-v1"
    assert w.snapshot()[0]["count"] == 3


def test_eviction_bounds():
    w = Ja3Watch(max_fingerprints=3)
    for i in range(10):
        w.observe(f"h{i}", "ja3", None, "10.0.0.5", now=float(i))
    assert len(w.seen) <= 3


def test_corrupt_ledger_degrades(tmp_path):
    ledger = tmp_path / "ja3.json"
    ledger.write_text("{ not json")
    assert Ja3Watch(ledger_path=str(ledger)).snapshot() == []


def test_non_object_ledger_entries_are_ignored(tmp_path):
    ledger = tmp_path / "ja3.json"
    ledger.write_text(json.dumps({"seen": {"bad": None}}))
    assert Ja3Watch(ledger_path=str(ledger)).snapshot() == []
