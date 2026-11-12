"""DNS analytics: DGA scoring, NXDOMAIN bursts, and tunneling detection (roadmap #4).

DNS is a favorite covert channel: malware uses domain-generation algorithms (DGA)
to rendezvous with C2, and exfiltrates data by encoding it into DNS query names
(tunneling). Three passive signals, all computed from query names + response codes
the sniffer already sees:

1. **DGA scoring** — algorithmically-generated domains look random: high entropy,
   long, digit-heavy, few pronounceable runs. ``dga_score`` is a transparent
   heuristic over those features (a real deployment would back it with a trained
   model and a public-suffix list / threat-intel feed — roadmap #6).
2. **NXDOMAIN bursts** — a host getting many "no such domain" answers in a short
   window is the classic DGA/C2 footprint (most generated domains don't resolve).
3. **Tunneling** — long, high-entropy subdomain labels and/or TXT/NULL query types
   carry encoded payload data rather than a real lookup.

Pure + JSON-persisted (a per-host counter summary + recent flagged domains for the
CLI; the short NXDOMAIN sliding windows are in-memory only). Findings are alerts,
never auto-mitigation triggers. The analyzer rate-limits repeats so one noisy host
can't flood the log.
"""

import json
import math
import time
from collections import Counter, deque

from netwatch_core import write_json_atomic

# DNS qtype numbers we care about.
QTYPE_NULL = 10
QTYPE_TXT = 16

# Finding kinds.
DGA = "DGA"
NXDOMAIN_BURST = "NXDOMAIN_BURST"
DNS_TUNNEL = "DNS_TUNNEL"

# Query names that are noise for these heuristics (reverse DNS, local/mDNS).
_SKIP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".local", ".lan", ".arpa")
_VOWELS = set("aeiou")


def shannon_entropy(s):
    """Shannon entropy (bits/char) of a string."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _split_labels(qname):
    """(sld, subdomain) for a qname. sld = second-to-last label (the registrable
    label under a naive single-label TLD assumption); subdomain = everything to its
    left. Simplified — a real impl uses the public-suffix list."""
    labels = [x for x in qname.lower().strip(".").split(".") if x]
    if len(labels) < 2:
        return (labels[0] if labels else ""), ""
    return labels[-2], ".".join(labels[:-2])


def _max_consonant_run(s):
    run = best = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def dga_score(label):
    """Heuristic 0..1 likelihood that ``label`` is algorithmically generated. Scores
    the registrable label, not the whole qname. Higher = more random-looking."""
    label = "".join(c for c in label.lower() if c.isalnum())
    L = len(label)
    if L < 8:
        return 0.0  # short labels are dominated by normal domains
    H = shannon_entropy(label)
    digits = sum(c.isdigit() for c in label)
    dr = digits / L
    vowels = sum(c in _VOWELS for c in label)
    vr = vowels / L
    score = 0.0
    if L >= 12:
        score += 0.25
    if H >= 3.5:
        score += 0.35
    if dr >= 0.25:
        score += 0.20
    if vr < 0.20 or vr > 0.60:
        score += 0.10
    if _max_consonant_run(label) >= 5:
        score += 0.10
    return round(min(1.0, score), 3)


def _is_skippable(qname):
    if not qname or qname == "encrypted-payload":
        return True
    q = qname.lower()
    return any(q.endswith(suf) for suf in _SKIP_SUFFIXES)


# Stored with a leading dot; matched against "." + qname, so an entry covers the name itself and its subdomains.
def _dotted(suffixes):
    return tuple(
        suffix if suffix.startswith(".") else f".{suffix}"
        for suffix in (str(value).lower().rstrip(".") for value in suffixes)
        if suffix
    )


class DnsAnalyzer:
    """Stateful DNS analytics with rate-limited findings and a persisted summary."""

    def __init__(
        self,
        *,
        dga_threshold=0.7,
        nxdomain_window_sec=30,
        nxdomain_threshold=10,
        tunnel_subdomain_len=50,
        tunnel_entropy=3.5,
        cooldown_sec=60,
        ignore_suffixes=(),
        tunnel_ignore_suffixes=(),
        tunnel_ignore_device_suffixes=(),
        max_hosts=1024,
        max_recent=100,
        ledger_path=None,
    ):
        self.dga_threshold = dga_threshold
        self.nxdomain_window_sec = nxdomain_window_sec
        self.nxdomain_threshold = nxdomain_threshold
        self.tunnel_subdomain_len = tunnel_subdomain_len
        self.tunnel_entropy = tunnel_entropy
        self.cooldown_sec = cooldown_sec
        self.ignore_suffixes = _SKIP_SUFFIXES + _dotted(ignore_suffixes)
        # Provider-run zones (no attacker authority over them, so no tunnel endpoint): skip only the
        # tunnel check; DGA and NXDOMAIN counting still see these names.
        self.tunnel_ignore_suffixes = _dotted(tunnel_ignore_suffixes)
        # {mac: suffixes}: one device's own telemetry zone, exempt from the tunnel check for that device only.
        self.tunnel_ignore_by_mac = {}
        for entry in tunnel_ignore_device_suffixes:
            mac, suffixes = str(entry.get("mac") or "").strip().lower(), _dotted(entry.get("suffixes") or ())
            if len(mac) == 17 and suffixes:
                self.tunnel_ignore_by_mac[mac] = self.tunnel_ignore_by_mac.get(mac, ()) + suffixes
        self.max_hosts = max_hosts
        self.max_recent = max_recent
        self.ledger_path = ledger_path
        self.hosts = {}            # ip -> {queries, nxdomain, dga_hits, tunnel_hits, last_seen}
        self.recent = []           # capped list of recent flagged-domain dicts
        self._nx_windows = {}      # ip -> deque[ts]  (in-memory only)
        self._cooldown = {}        # (kind, key) -> last_fire_ts
        self._dirty = False
        if ledger_path:
            self._load()

    def observe(self, src_ip, dst_ip, qname, qr, rcode, qtype, now=None, src_mac=None):
        """Analyze one DNS message. ``qr`` 0=query / 1=response. Returns a list of
        finding dicts (possibly empty); each carries ``kind``/``severity``/``message``."""
        now = time.time() if now is None else now
        findings = []
        qname = (qname or "").lower().rstrip(".")

        if qr == 0:  # query: DGA + tunneling, attributed to the querying host (src)
            host = self._host(src_ip, now)
            host["queries"] += 1
            self._dirty = True
            if _is_skippable(qname) or any(f".{qname}".endswith(suffix) for suffix in self.ignore_suffixes):
                return findings
            sld, subdomain = _split_labels(qname)

            score = dga_score(sld)
            if score >= self.dga_threshold and self._fire(DGA, qname, now):
                host["dga_hits"] += 1
                self._record(qname, DGA, score, src_ip, now)
                findings.append({"kind": DGA, "severity": "anomaly", "host": src_ip,
                                 "message": f"DNS DGA: {src_ip} queried {qname} (randomness {score:.2f})"})

            long_sub = len(subdomain) >= self.tunnel_subdomain_len
            txt_like = qtype in (QTYPE_TXT, QTYPE_NULL)
            if ((long_sub or (txt_like and len(subdomain) >= 20))
                    and not any(f".{qname}".endswith(suffix) for suffix in self.tunnel_ignore_suffixes)
                    and not any(f".{qname}".endswith(suffix) for suffix in
                                self.tunnel_ignore_by_mac.get(str(src_mac or "").lower(), ()))
                    and (sub_entropy := shannon_entropy(subdomain)) >= self.tunnel_entropy):
                if self._fire(DNS_TUNNEL, _split_labels(qname)[0] + qname[-8:], now):
                    host["tunnel_hits"] += 1
                    self._record(qname, DNS_TUNNEL, sub_entropy, src_ip, now)
                    qt = "TXT/NULL " if txt_like else ""
                    findings.append({"kind": DNS_TUNNEL, "severity": "alert", "host": src_ip,
                                     "message": f"DNS TUNNEL: {src_ip} {qt}query w/ {len(subdomain)}-char subdomain ({qname[:40]}...)"})

        elif qr == 1 and rcode == 3:  # NXDOMAIN response -> blame the querying host (dst)
            if any(f".{qname}".endswith(suffix) for suffix in self.ignore_suffixes):
                return findings
            host = self._host(dst_ip, now)
            host["nxdomain"] += 1
            self._dirty = True
            win = self._nx_windows.setdefault(dst_ip, deque(maxlen=self.nxdomain_threshold + 1))  # only len > threshold is tested
            win.append(now)
            cutoff = now - self.nxdomain_window_sec
            while win and win[0] < cutoff:
                win.popleft()
            if len(win) > self.nxdomain_threshold and self._fire(NXDOMAIN_BURST, dst_ip, now):
                findings.append({"kind": NXDOMAIN_BURST, "severity": "alert", "host": dst_ip,
                                 "message": f"DNS NXDOMAIN BURST: {dst_ip} got >{self.nxdomain_threshold} NXDOMAIN in {self.nxdomain_window_sec}s (DGA/C2 footprint)"})

        return findings

    def snapshot(self):
        """Per-host DNS summary for the CLI, sorted by suspicion then volume."""
        return sorted(
            ({"ip": ip, **e} for ip, e in self.hosts.items()),
            key=lambda r: (r["dga_hits"] + r["tunnel_hits"] + r["nxdomain"], r["queries"]),
            reverse=True,
        )

    def recent_findings(self):
        return list(self.recent)

    def save(self):
        if self._dirty:
            self._save()

    # --- internals -------------------------------------------------------
    def _host(self, ip, now):
        h = self.hosts.get(ip)
        if h is None:
            if len(self.hosts) >= self.max_hosts:
                victim = min(self.hosts, key=lambda k: self.hosts[k]["last_seen"])
                self.hosts.pop(victim, None)
                self._nx_windows.pop(victim, None)
            h = {"queries": 0, "nxdomain": 0, "dga_hits": 0, "tunnel_hits": 0, "last_seen": now}
            self.hosts[ip] = h
        h["last_seen"] = now
        return h

    def _fire(self, kind, key, now):
        """Rate-limit: True (and arm cooldown) if this (kind,key) hasn't fired within
        ``cooldown_sec``."""
        last = self._cooldown.get((kind, key))
        if last is not None and now - last < self.cooldown_sec:
            return False
        if len(self._cooldown) > 4 * self.max_hosts:
            stale = now - self.cooldown_sec
            self._cooldown = {k: t for k, t in self._cooldown.items() if t >= stale}
        self._cooldown[(kind, key)] = now
        return True

    def _record(self, domain, kind, score, src, now):
        self.recent.append({"domain": domain, "kind": kind, "score": round(score, 3), "src": src, "ts": now})
        if len(self.recent) > self.max_recent:
            self.recent = self.recent[-self.max_recent:]
        self._dirty = True

    def _save(self):
        if not self.ledger_path:
            self._dirty = False
            return
        if write_json_atomic(self.ledger_path, {"hosts": self.hosts, "recent": self.recent}):
            self._dirty = False

    def _load(self):
        try:
            with open(self.ledger_path, encoding="utf-8") as f:
                data = json.load(f)
            self.hosts = dict(data.get("hosts", {}))
            self.recent = list(data.get("recent", []))
        except (OSError, ValueError):
            self.hosts, self.recent = {}, []
