"""JA3 / JA3S TLS fingerprinting (roadmap #5).

A TLS ClientHello is sent in the clear even when the rest of the connection is
encrypted. JA3 fingerprints the client by hashing the structural fields of that
ClientHello — TLS version, cipher-suite list, extension list, supported groups
(elliptic curves), and EC point formats — into a single MD5. The same software
produces the same JA3, so it identifies the *client application* (and many malware
families have well-known JA3s) without decrypting anything. JA3S is the equivalent
for the ServerHello (version, chosen cipher, extensions).

This module is pure: a defensive TLS-hello parser plus the JA3/JA3S string + hash,
and a ``Ja3Watch`` inventory that counts fingerprints and matches them against a
blocklist (the seam for a JA3 threat-intel feed — roadmap #6). Hashes follow the
canonical (Salesforce) JA3 definition: GREASE values are excluded, so the
fingerprints line up with published JA3 databases.
"""

import hashlib
import json
import time

from netwatch_core import write_json_atomic

# RFC 8701 GREASE values. Preserve them in parsed wire evidence, but exclude
# them from JA3 and JA4 canonicalization.
GREASE = frozenset((
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
))

_EXT_SERVER_NAME = 0
_EXT_SUPPORTED_GROUPS = 10
_EXT_EC_POINT_FORMATS = 11
_EXT_SIGNATURE_ALGORITHMS = 13
_EXT_ALPN = 16
_EXT_SUPPORTED_VERSIONS = 43


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def _u16_list(b, start, length):
    """Read ``length`` bytes from ``start`` as big-endian uint16s. Returns [] if the
    span doesn't fit."""
    if start + length > len(b) or length < 0:
        return []
    return [_u16(b, start + i) for i in range(0, length - (length % 2), 2)]


def _parse_extensions(data, pos, end):
    """Parse extensions used by JA3 and JA4."""
    exts, curves, point_formats, sni = [], [], [], None
    signature_algorithms, supported_versions, alpn = [], [], None
    while pos + 4 <= end:
        etype = _u16(data, pos)
        elen = _u16(data, pos + 2)
        pos += 4
        if pos + elen > end or pos + elen > len(data):
            break
        edata = data[pos:pos + elen]
        exts.append(etype)
        if etype == _EXT_SUPPORTED_GROUPS and len(edata) >= 2:
            curves = _u16_list(edata, 2, _u16(edata, 0))
        elif etype == _EXT_EC_POINT_FORMATS and len(edata) >= 1:
            plen = edata[0]
            point_formats = list(edata[1:1 + plen])
        elif etype == _EXT_SERVER_NAME and len(edata) >= 5:
            try:
                nlen = _u16(edata, 3)
                sni = edata[5:5 + nlen].decode("utf-8") or None
            except (UnicodeDecodeError, IndexError):
                sni = None
        elif etype == _EXT_SIGNATURE_ALGORITHMS and len(edata) >= 2:
            signature_algorithms = _u16_list(edata, 2, _u16(edata, 0))
        elif etype == _EXT_SUPPORTED_VERSIONS and len(edata) >= 1:
            supported_versions = _u16_list(edata, 1, edata[0])
        elif etype == _EXT_ALPN and len(edata) >= 3:
            first_len = edata[2]
            alpn = bytes(edata[3:3 + first_len]) or None
        pos += elen
    return (
        exts, curves, point_formats, sni,
        signature_algorithms, supported_versions, alpn,
    )


def _hello_body(data, hs_type):
    """Validate the TLS record + handshake header and return (version, pos) where
    pos points just past the 32-byte random + session-id, or None."""
    if len(data) < 44 or data[0] != 0x16 or data[5] != hs_type:
        return None
    version = _u16(data, 9)
    pos = 11 + 32  # past client_version + random
    if pos >= len(data):
        return None
    sid_len = data[pos]
    pos += 1 + sid_len
    return version, pos


def parse_client_hello(data):
    """Parse a TLS record carrying a ClientHello. Returns a component dict
    (version/ciphers/extensions/curves/point_formats/sni) or ``None``."""
    head = _hello_body(data, 0x01)
    if head is None:
        return None
    version, pos = head
    if pos + 2 > len(data):
        return None
    cs_len = _u16(data, pos)
    pos += 2
    ciphers = _u16_list(data, pos, cs_len)
    pos += cs_len
    if pos >= len(data):
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    exts = curves = point_formats = None
    sni = None
    if pos + 2 <= len(data):
        ext_total = _u16(data, pos)
        pos += 2
        (exts, curves, point_formats, sni, signature_algorithms,
         supported_versions, alpn) = _parse_extensions(
            data, pos, min(pos + ext_total, len(data)),
        )
    else:
        signature_algorithms, supported_versions, alpn = [], [], None
    return {
        "version": version,
        "ciphers": ciphers,
        "extensions": exts or [],
        "curves": curves or [],
        "point_formats": point_formats or [],
        "sni": sni,
        "signature_algorithms": signature_algorithms,
        "supported_versions": supported_versions,
        "alpn": alpn,
    }


def parse_server_hello(data):
    """Parse a TLS record carrying a ServerHello. Returns (version, cipher, exts)
    component dict or ``None``."""
    head = _hello_body(data, 0x02)
    if head is None:
        return None
    version, pos = head
    if pos + 3 > len(data):
        return None
    cipher = _u16(data, pos)
    pos += 2 + 1  # chosen cipher + compression method
    exts = []
    if pos + 2 <= len(data):
        ext_total = _u16(data, pos)
        pos += 2
        exts, _, _, _, _, _, _ = _parse_extensions(data, pos, min(pos + ext_total, len(data)))
    return {"version": version, "cipher": cipher, "extensions": exts}


def ja3_string(c):
    """Canonical JA3 string from a parse_client_hello dict."""
    def j(xs):
        return "-".join(str(x) for x in xs if x not in GREASE)
    return f"{c['version']},{j(c['ciphers'])},{j(c['extensions'])},{j(c['curves'])},{j(c['point_formats'])}"


def ja3s_string(s):
    """Canonical JA3S string from a parse_server_hello dict."""
    return f"{s['version']},{s['cipher']},{'-'.join(str(x) for x in s['extensions'])}"


def md5(s):
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()


def _ja4_hash(values):
    if not values:
        return "000000000000"
    return hashlib.sha256(values.encode()).hexdigest()[:12]


def _ja4_alpn(value):
    if not value:
        return "00"
    first, last = value[0], value[-1]
    if all(chr(item).isalnum() and item < 128 for item in (first, last)):
        return f"{chr(first)}{chr(last)}"
    encoded = value.hex()
    return f"{encoded[0]}{encoded[-1]}" if encoded else "00"


def ja4_string(client):
    """FoxIO JA4 TLS-over-TCP fingerprint from parsed ClientHello fields."""
    versions = [value for value in client.get("supported_versions", ()) if value not in GREASE]
    version = max(versions, default=client["version"])
    version_text = {
        0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
        0x0300: "s3", 0x0002: "s2", 0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
    }.get(version, "00")
    ciphers = sorted(value for value in client["ciphers"] if value not in GREASE)
    extensions = sorted(value for value in client["extensions"] if value not in GREASE)
    prefix = (
        f"t{version_text}{'d' if _EXT_SERVER_NAME in client['extensions'] else 'i'}"
        f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}"
        f"{_ja4_alpn(client.get('alpn'))}"
    )
    cipher_text = ",".join(f"{value:04x}" for value in ciphers)
    hash_extensions = [value for value in extensions if value not in {_EXT_SERVER_NAME, _EXT_ALPN}]
    extension_text = ",".join(f"{value:04x}" for value in hash_extensions)
    signatures = ",".join(
        f"{value:04x}" for value in client.get("signature_algorithms", ()) if value not in GREASE
    )
    if signatures:
        extension_text = f"{extension_text}_{signatures}"
    return f"{prefix}_{_ja4_hash(cipher_text)}_{_ja4_hash(extension_text if hash_extensions else '')}"


def fingerprint(payload):
    """Best-effort: if ``payload`` (a TCP segment's bytes) is a TLS ClientHello or
    ServerHello, return its fingerprint dict; else ``None``.

    Returns ``{"kind": "ja3"|"ja3s", "hash": <md5>, "string": <ja3str>, "sni": <str|None>}``."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    record_len = _u16(payload, 3)
    hello_len = int.from_bytes(payload[6:9], "big")
    if len(payload) < 5 + record_len or hello_len + 4 > record_len:
        # Segment-only enrichment cannot fingerprint a split/truncated hello.
        return None
    htype = payload[5]
    if htype == 0x01:
        c = parse_client_hello(payload)
        if c is None:
            return None
        s = ja3_string(c)
        return {
            "kind": "ja3", "hash": md5(s), "string": s,
            "sni": c["sni"], "ja4": ja4_string(c),
        }
    if htype == 0x02:
        sv = parse_server_hello(payload)
        if sv is None:
            return None
        s = ja3s_string(sv)
        return {"kind": "ja3s", "hash": md5(s), "string": s, "sni": None}
    return None


def load_blocklist(path):
    """Load known-bad JA3/JA3S hashes from ``{"blocklist": [...]}`` JSON. Missing/
    corrupt → empty set (no matches), never a crash."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return {str(h).strip().lower() for h in data.get("blocklist", []) if h}
    except (OSError, ValueError):
        return set()


class Ja3Watch:
    """Fingerprint inventory + blocklist matching. ``observe`` records a fingerprint
    and returns a finding dict when the hash is blocklisted."""

    def __init__(self, *, blocklist=None, max_fingerprints=4096, ledger_path=None):
        self.blocklist = {str(h).strip().lower() for h in (blocklist or ())}
        self.max_fingerprints = max_fingerprints
        self.ledger_path = ledger_path
        self.seen = {}   # hash -> {kind, count, first_seen, last_seen, sni, peer}
        self._dirty = False
        if ledger_path:
            self._load()

    def observe(self, fp_hash, kind, sni, peer_ip, now=None):
        now = time.time() if now is None else now
        if not fp_hash:
            return None
        entry = self.seen.get(fp_hash)
        if entry is None:
            if len(self.seen) >= self.max_fingerprints:
                victim = min(self.seen, key=lambda h: self.seen[h]["last_seen"])
                self.seen.pop(victim, None)
            entry = {"kind": kind, "count": 0, "first_seen": now, "last_seen": now,
                     "sni": sni or "", "peer": peer_ip or "",
                     "format": "ja3-canonical-v1" if kind == "ja3" else f"{kind}-v1"}
            self.seen[fp_hash] = entry
        elif kind == "ja3" and entry.get("format") == "ja3-legacy-grease-v1":
            # Same hash, but the retained count includes pre-correction evidence.
            entry["format"] = "ja3-mixed-v1"
        entry["count"] += 1
        entry["last_seen"] = now
        if sni and not entry["sni"]:
            entry["sni"] = sni
        self._dirty = True
        if fp_hash.lower() in self.blocklist:
            label = {"ja3": "JA3", "ja3s": "JA3S", "ja4": "JA4"}.get(kind, kind.upper())
            where = f" (sni {sni})" if sni else ""
            # alert, not critical: feed JA3s are shared by common TLS stacks (phones, TVs), so a hit alone is weak.
            return {"kind": "JA3_BLOCKLIST", "severity": "alert",
                    "message": f"{label} BLOCKLIST HIT: {fp_hash} from {peer_ip}{where}"}
        return None

    def snapshot(self):
        return sorted(
            ({"hash": h, **e, "blocklisted": h.lower() in self.blocklist
              and e.get("format") != "ja3-legacy-grease-v1"}
             for h, e in self.seen.items()),
            key=lambda r: r["count"], reverse=True,
        )

    def save(self):
        if self._dirty:
            self._save()

    def _save(self):
        if not self.ledger_path:
            self._dirty = False
            return
        if write_json_atomic(self.ledger_path, {"seen": self.seen}):
            self._dirty = False

    def _load(self):
        try:
            with open(self.ledger_path, encoding="utf-8") as f:
                self.seen = {
                    h: entry for h, entry in dict(json.load(f).get("seen", {})).items()
                    if isinstance(entry, dict)
                }
            for entry in self.seen.values():
                kind = entry.get("kind", "ja3")
                entry.setdefault("format", "ja3-legacy-grease-v1" if kind == "ja3" else f"{kind}-v1")
        except (OSError, ValueError):
            self.seen = {}
