"""Unit tests for DNS analytics: DGA scoring, NXDOMAIN-burst detection, tunneling,
rate-limiting, and persistence."""

import json

from netwatch_dns import (
    DGA,
    DNS_TUNNEL,
    NXDOMAIN_BURST,
    QTYPE_TXT,
    DnsAnalyzer,
    _split_labels,
    dga_score,
    shannon_entropy,
)

# A long, high-entropy base32-ish label used as a tunneling subdomain.
TUNNEL_SUB = "mfrggzdfmztwq2lknnwg23tpobyhc4tjmjuw4zlonfxg64ranvxgg33nmzxw6"


# --- pure scoring ----------------------------------------------------------


def test_shannon_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == 1.0
    assert shannon_entropy("") == 0.0


def test_split_labels():
    assert _split_labels("a.b.example.com") == ("example", "a.b")
    assert _split_labels("example.com") == ("example", "")
    assert _split_labels("localhost") == ("localhost", "")


def test_dga_score_separates_normal_from_random():
    assert dga_score("google") == 0.0          # too short to bother
    assert dga_score("facebook") < 0.7         # pronounceable, normal
    assert dga_score("microsoft") < 0.7
    assert dga_score("kq3v9zx2p1mw") >= 0.7    # random, digit-heavy, no vowels
    assert dga_score("xkqzvwbtndfg") >= 0.7    # long, vowel-poor, consonant run


# --- DGA detection ---------------------------------------------------------


def test_dga_finding():
    a = DnsAnalyzer(dga_threshold=0.7)
    out = a.observe("10.0.0.5", "8.8.8.8", "kq3v9zx2p1mw.com", qr=0, rcode=0, qtype=1, now=1.0)
    assert len(out) == 1 and out[0]["kind"] == DGA and out[0]["severity"] == "anomaly"
    assert a.hosts["10.0.0.5"]["dga_hits"] == 1


def test_normal_query_no_finding():
    a = DnsAnalyzer()
    assert a.observe("10.0.0.5", "8.8.8.8", "www.google.com", qr=0, rcode=0, qtype=1, now=1.0) == []
    assert a.hosts["10.0.0.5"]["queries"] == 1


def test_reverse_dns_skipped():
    a = DnsAnalyzer()
    out = a.observe("10.0.0.5", "8.8.8.8", "1.0.0.10.in-addr.arpa", qr=0, rcode=0, qtype=12, now=1.0)
    assert out == []
    assert a.hosts["10.0.0.5"]["queries"] == 1  # counted, just not scored


# --- tunneling -------------------------------------------------------------


def test_tunnel_long_subdomain():
    a = DnsAnalyzer()
    out = a.observe("10.0.0.5", "8.8.8.8", f"{TUNNEL_SUB}.evil.com", qr=0, rcode=0, qtype=1, now=1.0)
    assert any(f["kind"] == DNS_TUNNEL for f in out)
    assert a.hosts["10.0.0.5"]["tunnel_hits"] == 1


def test_tunnel_ignore_suffixes_skip_only_the_tunnel_check():
    a = DnsAnalyzer(tunnel_ignore_suffixes=("amazonaws.com", ".ts.net"), nxdomain_threshold=1)
    hexsub = "d847870f4ec40488ed2885eed96be12602541c5d87644532d2a6abd4593a4a9"
    assert not a.observe("10.0.0.5", "8.8.8.8", f"{TUNNEL_SUB}.us-east-1.elb.amazonaws.com", qr=0, rcode=0, qtype=1, now=1.0)
    assert not a.observe("10.0.0.5", "8.8.8.8", f"{TUNNEL_SUB}.tail0000.ts.net", qr=0, rcode=0, qtype=1, now=1.0)
    # Amazon's device zone (the UNKNOWN 102-char hex queries) is not covered by amazonaws.com.
    out = a.observe("10.0.0.8", "8.8.8.8", f"{hexsub}.us-east-1.prod.service.minerva.devices.a2z.com",
                    qr=0, rcode=0, qtype=1, now=1.0)
    assert any(f["kind"] == DNS_TUNNEL for f in out)
    # NXDOMAIN counting still sees an ignored suffix.
    for t in (2.0, 3.0):
        out = a.observe("8.8.8.8", "10.0.0.5", "x.elb.amazonaws.com", qr=1, rcode=3, qtype=1, now=t)
    assert any(f["kind"] == NXDOMAIN_BURST for f in out)


def test_device_tunnel_suffix_exempts_only_that_device():
    rule = {"mac": "98:28:A6:00:00:01", "suffixes": ["minerva.devices.a2z.com"]}
    a = DnsAnalyzer(tunnel_ignore_device_suffixes=[rule])
    name = "46acc36bce9a33c2e19f0205c0a94b8a35955814b560532b0ecefbf90a6d055.us-east-1.prod.service.minerva.devices.a2z.com"
    assert not a.observe("10.0.0.8", "75.75.75.75", name, qr=0, rcode=0, qtype=1, now=1.0, src_mac="98:28:a6:00:00:01")
    # The same name from any other device, or another zone from this device, still alerts.
    assert any(f["kind"] == DNS_TUNNEL for f in a.observe(
        "10.0.0.9", "75.75.75.75", name, qr=0, rcode=0, qtype=1, now=100.0, src_mac="00:11:22:33:44:55"))
    assert any(f["kind"] == DNS_TUNNEL for f in a.observe(
        "10.0.0.8", "75.75.75.75", f"{TUNNEL_SUB}.evil.com", qr=0, rcode=0, qtype=1, now=200.0, src_mac="98:28:a6:00:00:01"))



def test_device_tunnel_entry_covers_the_exact_name_not_a_lookalike():
    name = "antigravity-cli-auto-updater-974169037036.us-central1.run.app"
    a = DnsAnalyzer(tunnel_ignore_device_suffixes=[{"mac": "cc:96:e5:00:00:02", "suffixes": [name]}])
    assert not a.observe("10.0.0.15", "75.75.75.75", name, qr=0, rcode=0, qtype=1, now=1.0, src_mac="cc:96:e5:00:00:02")
    assert any(f["kind"] == DNS_TUNNEL for f in a.observe(
        "10.0.0.15", "75.75.75.75", "x" + name, qr=0, rcode=0, qtype=1, now=100.0, src_mac="cc:96:e5:00:00:02"))

def test_tunnel_txt_record():
    a = DnsAnalyzer()
    out = a.observe("10.0.0.5", "8.8.8.8", "mfrggzdfmztwq2lknnwg.evil.com", qr=0, rcode=0, qtype=QTYPE_TXT, now=1.0)
    assert any(f["kind"] == DNS_TUNNEL for f in out)


# --- NXDOMAIN burst --------------------------------------------------------


def test_nxdomain_burst():
    a = DnsAnalyzer(nxdomain_window_sec=30, nxdomain_threshold=10)
    fired = []
    for i in range(12):
        fired += a.observe("8.8.8.8", "10.0.0.5", f"gen{i}.bad.com", qr=1, rcode=3, qtype=1, now=float(i))
    assert any(f["kind"] == NXDOMAIN_BURST for f in fired)
    assert a.hosts["10.0.0.5"]["nxdomain"] == 12


def test_nxdomain_below_threshold_quiet():
    a = DnsAnalyzer(nxdomain_threshold=10)
    fired = False
    for i in range(5):
        if a.observe("8.8.8.8", "10.0.0.5", "x.com", qr=1, rcode=3, qtype=1, now=float(i)):
            fired = True
    assert not fired


def test_nxdomain_ignore_suffix_suppresses_service_discovery_noise():
    analyzer = DnsAnalyzer(
        nxdomain_window_sec=30,
        nxdomain_threshold=2,
        ignore_suffixes=(".temporal",),
    )
    findings = []
    for index in range(6):
        findings += analyzer.observe(
            "10.0.0.1", "10.0.0.15", "_grpc_config.temporal",
            qr=1, rcode=3, qtype=1, now=float(index),
        )
    assert findings == []
    assert "10.0.0.15" not in analyzer.hosts


def test_nxdomain_window_bounded():
    a = DnsAnalyzer(nxdomain_window_sec=30, nxdomain_threshold=10)
    fired = []
    for _ in range(10_000):
        fired += a.observe("8.8.8.8", "10.0.0.5", "x.bad.com", qr=1, rcode=3, qtype=1, now=1.0)
    assert len(a._nx_windows["10.0.0.5"]) <= 11
    assert sum(f["kind"] == NXDOMAIN_BURST for f in fired) == 1


def test_nxdomain_window_expiry():
    a = DnsAnalyzer(nxdomain_window_sec=10, nxdomain_threshold=5)
    # spread sightings 100s apart -> window never accumulates -> never bursts
    fired = any(
        a.observe("8.8.8.8", "10.0.0.5", "x.com", qr=1, rcode=3, qtype=1, now=float(i * 100))
        for i in range(20)
    )
    assert not fired


# --- rate limiting ---------------------------------------------------------


def test_dga_cooldown_dedups():
    a = DnsAnalyzer(dga_threshold=0.7, cooldown_sec=60)
    f1 = a.observe("10.0.0.5", "8.8.8.8", "kq3v9zx2p1mw.com", qr=0, rcode=0, qtype=1, now=1.0)
    f2 = a.observe("10.0.0.5", "8.8.8.8", "kq3v9zx2p1mw.com", qr=0, rcode=0, qtype=1, now=2.0)
    assert len(f1) == 1 and f2 == []          # second within cooldown is suppressed
    f3 = a.observe("10.0.0.5", "8.8.8.8", "kq3v9zx2p1mw.com", qr=0, rcode=0, qtype=1, now=120.0)
    assert len(f3) == 1                         # ...but fires again after cooldown


# --- persistence + bounds --------------------------------------------------


def test_persistence_roundtrip(tmp_path):
    ledger = str(tmp_path / "dns.json")
    a1 = DnsAnalyzer(ledger_path=ledger)
    a1.observe("10.0.0.5", "8.8.8.8", "kq3v9zx2p1mw.com", qr=0, rcode=0, qtype=1, now=1.0)
    a1.save()
    a2 = DnsAnalyzer(ledger_path=ledger)
    assert a2.hosts["10.0.0.5"]["dga_hits"] == 1
    assert any(r["kind"] == DGA for r in a2.recent_findings())
    on_disk = json.loads((tmp_path / "dns.json").read_text())
    assert "10.0.0.5" in on_disk["hosts"]


def test_host_eviction_bounds():
    a = DnsAnalyzer(max_hosts=3)
    for i in range(10):
        a.observe(f"10.0.0.{i}", "8.8.8.8", "www.google.com", qr=0, rcode=0, qtype=1, now=float(i))
    assert len(a.hosts) <= 3


def test_corrupt_ledger_degrades(tmp_path):
    ledger = tmp_path / "dns.json"
    ledger.write_text("{ not json")
    a = DnsAnalyzer(ledger_path=str(ledger))
    assert a.snapshot() == []
