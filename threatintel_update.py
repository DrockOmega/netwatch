"""Threat-intel feed updater for NetWatch.

Fetches public blocklists and writes a consolidated local cache
(``threatintel_cache.json``) that the monitor reads. This is the ONLY component
that makes outbound connections — the monitor itself stays passive and just reads
the cache. Run it on a schedule (Windows Task Scheduler / cron), like updating AV
signatures.

    python threatintel_update.py update     # fetch feeds, rebuild the cache
    python threatintel_update.py status      # show what's currently cached

Feeds are configurable via --feeds-file (a JSON list of {name,url,type}); otherwise
a curated set of well-known free feeds is used. A feed that fails to fetch/parse is
skipped with a warning; the cache is only overwritten when at least one feed yields
indicators, so a transient outage can't wipe your protection.
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request

from netwatch_threatintel import PARSERS, IndicatorBuilder, IndicatorSet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CACHE = os.path.join(BASE_DIR, "threatintel_cache.json")

# Curated free, no-auth feeds. Each: name, type (a key in PARSERS), url.
DEFAULT_FEEDS = [
    {"name": "firehol_level1", "type": "ipset",
     "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
    {"name": "spamhaus_drop", "type": "ipset", "url": "https://www.spamhaus.org/drop/drop.txt"},
    {"name": "feodo_c2", "type": "ip_csv", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"},
    {"name": "sslbl_ja3", "type": "ja3_csv", "url": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"},
    {"name": "urlhaus", "type": "domains", "url": "https://urlhaus.abuse.ch/downloads/hostfile/"},
]


def _fetch(url, timeout):
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {scheme!r}")
    req = urllib.request.Request(url, headers={"User-Agent": "NetWatch-ThreatIntel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _load_feeds(path):
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_FEEDS


def cmd_update(args):
    feeds = _load_feeds(args.feeds_file)
    builder = IndicatorBuilder()
    ok_count, failed = 0, []
    print(f"Fetching {len(feeds)} feed(s)...")
    for feed in feeds:
        if not isinstance(feed, dict):
            print("  [skip] invalid feed format (not a dictionary)")
            continue
        name = feed.get("name", "?")
        ftype = feed.get("type")
        url = feed.get("url")
        if not (ftype and url):
            print(f"  [skip] {name}: missing 'type' or 'url'")
            continue
        if ftype not in PARSERS:
            print(f"  [skip] {name}: unknown type {ftype!r}")
            continue
        try:
            text = _fetch(url, args.timeout)
            parsed = PARSERS[ftype](text)
            builder.add(name, ftype, parsed)
            n = len(parsed)
            ok_count += 1 if n else 0
            if not n:
                failed.append(name)
            print(f"  [ok]   {name}: {n} indicator(s)")
        except Exception as e:  # noqa: BLE001 - network/parse failures are expected, just skip
            failed.append(name)
            print(f"  [FAIL] {name}: {e}")

    if ok_count == 0:
        print("\nNo feed yielded indicators; keeping the existing cache unchanged.", file=sys.stderr)
        return 1
    if failed:
        # A failed feed keeps its previous indicators: a rewrite from the others alone would drop them.
        try:
            old = IndicatorSet.load(args.cache)
        except ValueError:
            old = IndicatorSet()
        for name in failed:
            builder.ranges += [r for r in old._ranges4 if r[2] == name]
            builder.ranges6 += [r for r in old._ranges6 if r[2] == name]
            for kind, table in (("domains", builder.domains), ("ja3", builder.ja3)):
                for key, source in getattr(old, kind).items():
                    if source == name:
                        table.setdefault(key, source)
            if name in old.meta:
                builder.meta[name] = old.meta[name]
        print(f"\n{len(failed)} feed(s) failed; kept their previous indicators: {', '.join(failed)}",
              file=sys.stderr)
    iset = builder.finalize()
    iset.save(args.cache, extra={"fetched_at": time.time()})
    c = iset.counts()
    print(f"\nWrote {args.cache}")
    print(f"  IP ranges: {c['ip_ranges']}  domains: {c['domains']}  JA3: {c['ja3']}")
    return 0


def cmd_status(args):
    if not os.path.exists(args.cache):
        print(f"No cache at {args.cache}. Run: python threatintel_update.py update")
        return 0
    with open(args.cache, encoding="utf-8") as f:
        raw = json.load(f)
    iset = IndicatorSet.from_dict(raw)
    c = iset.counts()
    fetched = raw.get("fetched_at")
    when = f"{int(time.time() - fetched)}s ago" if fetched else "unknown"
    print(f"Cache: {args.cache}  (updated {when})")
    print(f"  IP ranges: {c['ip_ranges']}   domains: {c['domains']}   JA3: {c['ja3']}")
    print("  per-source indicator counts:")
    for src, n in sorted(c["sources"].items()):
        print(f"    {src:<18}{n}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(description="NetWatch threat-intel feed updater")
    p.add_argument("--cache", default=DEFAULT_CACHE, help="consolidated cache path")
    p.add_argument("--feeds-file", default=None, help="JSON list of {name,url,type}; default uses a curated set")
    p.add_argument("--timeout", type=int, default=30, help="per-feed fetch timeout (s)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("update", help="fetch feeds and rebuild the cache").set_defaults(func=cmd_update)
    sub.add_parser("status", help="show the current cache contents").set_defaults(func=cmd_status)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
