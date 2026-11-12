"""Threat-intel feed ingestion: parse public blocklists into fast matchers (roadmap #6).

This is the data side of "known-bad" detection. Public feeds (abuse.ch Feodo/SSLBL/
URLhaus, FireHOL, Spamhaus DROP) publish indicators of compromise; this module turns
their text formats into:

- a **CIDR/IP matcher** (bad IPs → match a packet's external endpoint),
- a **domain set** (bad domains → match an SNI/DNS name),
- a **JA3 set** (bad TLS fingerprints → merged into the JA3 blocklist).

Design split: this module is PURE (parsing + matching + (de)serialization, fully
unit-testable with sample snippets, no network). The actual fetching lives in
``threatintel_update.py`` so the live monitor only ever reads a local cache — it
stays passive unless an operator (or an opt-in timer) refreshes the cache. IP
matching is O(log n) per packet via merged, sorted ranges + bisect, so it is safe on
the capture hot path even with tens of thousands of ranges.

Handles both IPv4 and IPv6 indicators: ranges are kept in two parallel sorted
spaces (4-byte and 16-byte address ints) and matched against a packet endpoint by
its address family.
"""

import bisect
import ipaddress
import json
import os
import re

_JA3_RE = re.compile(r"^[0-9a-f]{32}$")
# Feed JA3 entries known to match benign clients here; dropped wherever an IndicatorSet is built.
# 40adfd92...: an SSLBL entry that matched Samsung TV/phone TLS to Samsung, Apple and YouTube CDNs
# (triaged 2026-10-13); still in the SSLBL list after a refresh.
JA3_FEED_IGNORE = frozenset({"40adfd923eb82b89d8836ba37a19bca1"})
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,}$")


def _safe_range(token):
    """A ``(start_int, end_int, version)`` range for a CIDR or bare IP (v4 or v6),
    or None. ``version`` is 4 or 6 so the builder can route it into the right
    address space (a v6 ``::1`` and a v4 ``0.0.0.1`` both map to int 1)."""
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    return int(net.network_address), int(net.broadcast_address), net.version


# --- feed parsers (text -> indicators) -------------------------------------


def parse_ipset(text):
    """FireHOL ``.netset`` / Spamhaus DROP: one CIDR or IP per line; ``#``/``;``
    comments; Spamhaus appends ``; SBLxxx``. Returns a list of (start, end)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        token = line.split()[0]
        r = _safe_range(token)
        if r:
            out.append(r)
    return out


def parse_ip_csv(text):
    """abuse.ch Feodo ``ipblocklist.csv`` (and similar): comma-separated, ``#``
    comments. Takes the first IP-looking field per row. Returns a list of ranges."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for field in line.split(","):
            r = _safe_range(field.strip().strip('"'))
            if r:
                out.append(r)
                break
    return out


def parse_domains(text):
    """Domain blocklist / hostfile (URLhaus etc.): plain domains or ``0.0.0.0 domain``
    lines. Returns a set of lowercase domains."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        token = line.split()[-1].lower().rstrip(".")
        if _DOMAIN_RE.match(token):
            out.add(token)
    return out


def parse_ja3_csv(text):
    """abuse.ch SSLBL ``ja3_fingerprints.csv``: ``#`` comments then ``md5,...``.
    Returns a set of lowercase JA3 MD5 hashes."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split(",")[0].strip().strip('"').lower()
        if _JA3_RE.match(first):
            out.add(first)
    return out


PARSERS = {"ipset": parse_ipset, "ip_csv": parse_ip_csv, "domains": parse_domains, "ja3_csv": parse_ja3_csv}


# --- indicator store -------------------------------------------------------


def _merge_ranges(ranges):
    """Sort and merge overlapping/adjacent (start, end, source) ranges into disjoint
    ones (keeping the first source). Enables correct O(log n) bisect matching."""
    if not ranges:
        return []
    ranges = sorted(ranges)
    merged = [list(ranges[0])]
    for start, end, source in ranges[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end, source])
    return [tuple(m) for m in merged]


class IndicatorSet:
    """Immutable-ish matcher built from parsed feeds. ``match_ip``/``match_domain``/
    ``match_ja3`` return the source feed name on a hit, else None.

    IP ranges live in two parallel sorted spaces — ``_ranges4`` (IPv4) and
    ``_ranges6`` (IPv6) — because a v4 and a v6 address can map to the same int.
    ``match_ip`` picks the space by the queried address's family."""

    def __init__(self, ranges=None, ranges6=None, domains=None, ja3=None, meta=None):
        self._ranges4 = _merge_ranges(ranges or [])
        self._starts4 = [r[0] for r in self._ranges4]
        self._ranges6 = _merge_ranges(ranges6 or [])
        self._starts6 = [r[0] for r in self._ranges6]
        self.domains = dict(domains or {})
        self.ja3 = {h: v for h, v in ((str(k).strip().lower(), v) for k, v in dict(ja3 or {}).items())
                    if h not in JA3_FEED_IGNORE}
        self.meta = dict(meta or {})

    @staticmethod
    def _match(starts, ranges, val):
        i = bisect.bisect_right(starts, val) - 1
        if i >= 0 and val <= ranges[i][1]:
            return ranges[i][2]
        return None

    def match_ip(self, ip):
        """Match a packet endpoint. Accepts packed address bytes (4=v4, 16=v6) or a
        bare int (treated as IPv4, for back-compat with callers/tests that pass
        ``int(ip_address(...))``)."""
        if isinstance(ip, bytes | bytearray):
            val = int.from_bytes(ip, "big")
            if len(ip) == 16:
                return self._match(self._starts6, self._ranges6, val)
            return self._match(self._starts4, self._ranges4, val)
        return self._match(self._starts4, self._ranges4, int(ip))

    def match_domain(self, domain):
        """Match the domain or any of its parent domains (so ``a.b.evil.com`` hits a
        listed ``evil.com``)."""
        if not domain:
            return None
        d = domain.lower().rstrip(".")
        while d:
            if d in self.domains:
                return self.domains[d]
            i = d.find(".")
            if i < 0:
                break
            d = d[i + 1:]
        return None

    def match_ja3(self, fp_hash):
        return self.ja3.get((fp_hash or "").lower())

    def ja3_hashes(self):
        return set(self.ja3.keys())

    def counts(self):
        return {"ip_ranges": len(self._ranges4) + len(self._ranges6),
                "ip_ranges6": len(self._ranges6), "domains": len(self.domains),
                "ja3": len(self.ja3), "sources": self.meta}

    # --- serialization (the on-disk cache) -------------------------------
    def to_dict(self):
        return {
            "ranges": [[s, e, src] for (s, e, src) in self._ranges4],
            "ranges6": [[s, e, src] for (s, e, src) in self._ranges6],
            "domains": self.domains,
            "ja3": self.ja3,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d):
        ranges = [(r[0], r[1], r[2]) for r in d.get("ranges", [])]
        ranges6 = [(r[0], r[1], r[2]) for r in d.get("ranges6", [])]
        return cls(ranges=ranges, ranges6=ranges6, domains=d.get("domains", {}),
                   ja3=d.get("ja3", {}), meta=d.get("meta", {}))

    def save(self, path, extra=None):
        payload = self.to_dict()
        if extra:
            payload.update(extra)
        tmp_path = f"{path}.tmp"  # atomic: the core reloader must never see a torn file
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp_path, path)

    @classmethod
    def load(cls, path):
        """Load a cache file into an IndicatorSet. Missing or wrongly shaped → empty set;
        unparseable JSON or an unreadable file raises ValueError so the caller can keep its last good set."""
        try:
            with open(path, encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except FileNotFoundError:
            return cls()
        except OSError as exc:  # transient (sharing violation, permissions): not the same as "no cache"
            raise ValueError(f"threat-intel cache unreadable: {exc}") from exc
        except (TypeError, KeyError, IndexError):
            return cls()


class IndicatorBuilder:
    """Accumulates parsed feed output, then ``finalize()`` into an IndicatorSet."""

    def __init__(self):
        self.ranges = []   # IPv4 (start, end, source)
        self.ranges6 = []  # IPv6 (start, end, source)
        self.domains = {}
        self.ja3 = {}
        self.meta = {}

    def add(self, source, kind, parsed):
        if kind in ("ipset", "ip_csv"):
            for (s, e, version) in parsed:
                (self.ranges6 if version == 6 else self.ranges).append((s, e, source))
            self.meta[source] = len(parsed)
        elif kind == "domains":
            for d in parsed:
                self.domains.setdefault(d, source)
            self.meta[source] = len(parsed)
        elif kind == "ja3_csv":
            for h in parsed:
                self.ja3.setdefault(h, source)
            self.meta[source] = len(parsed)
        return self

    def finalize(self):
        return IndicatorSet(ranges=self.ranges, ranges6=self.ranges6,
                            domains=self.domains, ja3=self.ja3, meta=self.meta)
