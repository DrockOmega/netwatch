"""Passive assets, exposure and ranked findings from committed native records.

Nothing here sends a packet. Assets are keyed by stable link identity (MAC,
DHCP client identifier); an IP address is only an identity interval, so IP
reuse opens a new interval on the new holder and never merges two assets.
Version strings are recorded as unverified hypotheses, never as proof of a
vulnerability. Active owned-scope scanning is a later slice.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid

from netwatch_core import compile_v4_prefixes, compile_v6_prefixes, is_local_ip
from netwatch_inventory import is_usable_mac, normalize_mac, vendor_for
from netwatch_security_store import _encode

CURSOR_PREFIX = "ANALYSIS:ASSETS:v1:"
HEALTH_KEY = "ANALYSIS:ASSETS:v1"
STREAMS = (("CONTROL", "dhcp"), ("CONTROL", "arp"), ("CONTROL", "ipv6_na"), ("CONTROL", "ipv6_ns"),
           ("SURICATA", "http"), ("SURICATA", "tls"))
ANCHORS = ("mac", "dhcp_client_id")
EVIDENCE_REFS = 8  # first plus most recent native references per row
NEW_SERVICE_AFTER_SEC = 86400
READ_LIMIT = 500
MAX_PENDING_CLAIMS = 4096  # unconfirmed ARP rebinds held in memory; oldest dropped first
ASSET_ID = re.compile(r"[0-9a-f]{32}")
HYPOTHESIS = "version string is an unverified claim from observed traffic, not proof of a vulnerability"
# Cleartext protocols commonly used to administer devices.
CLEARTEXT = {("tcp", 21): "FTP", ("tcp", 23): "Telnet", ("udp", 69): "TFTP", ("tcp", 80): "HTTP",
             ("tcp", 8080): "HTTP", ("udp", 161): "SNMP", ("tcp", 512): "rexec", ("tcp", 513): "rlogin",
             ("tcp", 514): "rsh", ("tcp", 5900): "VNC"}
CLEARTEXT_NAMES = {"ftp": "FTP", "telnet": "Telnet", "tftp": "TFTP", "http": "HTTP", "snmp": "SNMP", "vnc": "VNC"}


def _refs(existing, ref):
    refs = list(existing)
    if ref and ref not in refs:
        refs.append(ref)
    return refs[:1] + refs[1:][-(EVIDENCE_REFS - 1):]


def _merge(body, ref, source, **lists):
    body["evidence"] = _refs(body.get("evidence", []), ref)
    body["sources"] = sorted(set(body.get("sources", [])) | {source})
    for name, values in lists.items():
        body[name] = sorted(set(body.get(name, [])) | {str(v) for v in values if v not in (None, "")})[:32]
    return body


def _text(value):
    if isinstance(value, bytes | bytearray):
        value = bytes(value).decode("utf-8", "replace")
    value = str(value).strip() if value is not None else ""
    return value[:255] or None


def rank(protocol, port, body):
    """Explainable additive score; each reason names its points."""
    reasons = []
    if "NMAP" in body.get("sources", []):
        reasons.append((10, "open port found by an active scan of an owned scope"))
    if body.get("external_peers"):  # independent of the scan: internet-facing outranks LAN-only
        reasons.append((50, f"answered {body['external_peers']} inbound connection(s) from external peers"))
    elif "NMAP" not in body.get("sources", []):
        if body.get("lan_peers"):
            reasons.append((10, f"answered {body['lan_peers']} connection(s) from LAN peers only"))
        else:
            reasons.append((5, "listening service reported by a passive source; peer scope not observed"))
    names = {name.lower() for name in body.get("names", [])}
    label = CLEARTEXT.get((protocol, port)) or (None if names & {"ssl", "tls"} else next(
        (CLEARTEXT_NAMES[name] for name in sorted(names) if name in CLEARTEXT_NAMES), None))
    if label:
        reasons.append((30, f"cleartext protocol commonly used for administration: {label}"))
    if body.get("new_on_known_asset"):
        reasons.append((20, "new listening service on an asset known for at least a day"))
    return sum(points for points, _ in reasons), [{"points": p, "reason": r} for p, r in reasons]


def local_ip(value, v4, v6):
    """Canonical local unicast address, or None (remote, multicast, broadcast or malformed)."""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if (address.is_multicast or address.is_unspecified or address.is_loopback
            or str(address) == "255.255.255.255"):
        return None
    return str(address) if is_local_ip(address.packed, v4, v6) else None


def holder(read, ip, t):
    """The asset holding ``ip`` at ``t``; an observation older than every interval uses the first holder."""
    # ponytail: an observation before the first known holder is attributed to it; keep
    # a separate address-only asset instead if early misattribution is measured.
    rows = read("""SELECT asset_id FROM security_asset_identities WHERE kind='ip'
        AND value=? ORDER BY first_seen<=? DESC, CASE WHEN first_seen<=? THEN -first_seen ELSE first_seen END,
        interval_id DESC LIMIT 1""", (ip, t, t))
    return rows[0]["asset_id"] if rows else None


class DurableAssetAnalyzer:
    """Replay committed native records into assets, exposure and findings with per-stream cursors."""

    def __init__(self, store, config, oui_db=None):
        self.store = store
        self.oui_db = oui_db or {}
        networks = (*config.get("LOCAL_PREFIXES", ()), *config.get("LOCAL_PREFIXES6", ()))
        self.v4, self.v6 = compile_v4_prefixes(networks), compile_v6_prefixes(networks)
        self.ignored_macs = {normalize_mac(config.get("QUARANTINE_SINK_MAC", "02:00:00:00:de:ad"))}
        self.last_error = None
        self.skipped = 0
        self._inventory_seen = {}  # mac -> last_seen already recorded
        # ARP is unauthenticated: a different MAC takes an address only after the same proof
        # the ARP analyzer needs before it believes a rebind (netwatch_arp.ArpWatch).
        self.rebind_confirmations = int(config.get("ARP_REBIND_CONFIRMATIONS", 3))
        self.rebind_min_sec = float(config.get("ARP_REBIND_MIN_SEC", 2.0))
        self.rebind_window_sec = float(config.get("ARP_REBIND_WINDOW_SEC", 10.0))
        self._claims = {}  # ip -> pending rebind {mac, first, last, count}

    def health(self):
        return {"status": "DEGRADED" if self.last_error else "RUNNING", "last_error": self.last_error,
                "skipped_records": self.skipped,
                "cursors": {f"{s}:{t}": (self.store.cursor(CURSOR_PREFIX + f"{s}:{t}") or {}).get("sequence", 0)
                            for s, t in STREAMS}}

    # --- input normalization --------------------------------------------
    def _local(self, value):
        return local_ip(value, self.v4, self.v6)

    def _mac(self, value):
        mac = normalize_mac(value)
        return mac if is_usable_mac(mac) and mac not in self.ignored_macs else None

    # --- identity -------------------------------------------------------
    def _interval(self, asset_id, kind, value, t, ref, source):
        """Extend the interval in force at ``t`` when it is this asset's; otherwise open a new one."""
        conn = self.store.conn
        if kind == "hostname":  # one current name per asset
            row = conn.execute("""SELECT * FROM security_asset_identities WHERE asset_id=? AND kind=?
                AND first_seen<=? ORDER BY first_seen DESC, interval_id DESC LIMIT 1""",
                               (asset_id, kind, t)).fetchone()
            same = row is not None and row["value"] == value
        else:  # an address or anchor belongs to one asset at a time
            row = conn.execute("""SELECT * FROM security_asset_identities WHERE kind=? AND value=?
                AND first_seen<=? ORDER BY first_seen DESC, interval_id DESC LIMIT 1""",
                               (kind, value, t)).fetchone()
            same = row is not None and row["asset_id"] == asset_id
        if same:
            conn.execute("""UPDATE security_asset_identities SET last_seen=max(last_seen, ?),
                observations=observations+1, body=? WHERE interval_id=?""",
                         (t, _encode(_merge(json.loads(row["body"]), ref, source)), row["interval_id"]))
        else:
            conn.execute("""INSERT INTO security_asset_identities
                (asset_id, kind, value, first_seen, last_seen, observations, body) VALUES (?,?,?,?,?,1,?)""",
                         (asset_id, kind, value, t, t, _encode(_merge({}, ref, source))))

    def _holder(self, ip, t):
        return holder(lambda sql, params: self.store.conn.execute(sql, params).fetchall(), ip, t)

    def _arp_ip(self, t, mac, ip):
        """``ip`` when this ARP claim may extend or move its holder; None while a rebind is unconfirmed."""
        mac, ip = self._mac(mac), self._local(ip)
        current = self._holder(ip, t) if mac and ip else None
        if current is None:
            return ip
        row = self.store.conn.execute("""SELECT count(*) AS macs, max(value=?) AS mine
            FROM security_asset_identities WHERE asset_id=? AND kind='mac'""", (mac, current)).fetchone()
        if not row["macs"] or row["mine"]:  # address-only holder, or the claimant already holds it
            self._claims.pop(ip, None)
            return ip
        claim = self._claims.pop(ip, None)
        if claim is None or claim["mac"] != mac or t - claim["last"] > self.rebind_window_sec:
            claim = {"mac": mac, "first": t, "last": t, "count": 0}
        claim["count"] += 1
        claim["last"] = max(claim["last"], t)
        if claim["count"] >= self.rebind_confirmations and t - claim["first"] >= self.rebind_min_sec:
            return ip
        self._claims[ip] = claim
        while len(self._claims) > MAX_PENDING_CLAIMS:
            self._claims.pop(next(iter(self._claims)))
        return None

    def observe(self, t, source, ref, *, mac=None, client_id=None, hostname=None, ip=None, vendor=None):
        """Resolve one identity observation to an asset; only MAC/client-id anchors identity.

        An address alone never joins an anchored asset: an unknown address gets an
        address-only asset, and later anchored evidence for it opens a new interval.
        """
        mac, ip, hostname = self._mac(mac), self._local(ip) if ip else None, _text(hostname)
        client_id = _text(client_id)
        anchors = [(kind, value) for kind, value in zip(ANCHORS, (mac, client_id), strict=True) if value]
        if not anchors and not ip:
            return None
        conn = self.store.conn
        asset_id = None
        for kind, value in anchors:
            row = conn.execute("""SELECT asset_id FROM security_asset_identities WHERE kind=? AND value=?
                ORDER BY first_seen DESC, interval_id DESC LIMIT 1""", (kind, value)).fetchone()
            if row:
                asset_id = row["asset_id"]
                break
        if asset_id is None and not anchors:
            asset_id = self._holder(ip, t)
        if asset_id is None:
            asset_id = uuid.uuid4().hex
            body = {"identity": anchors[0][0] if anchors else "address-only",
                    "vendor": vendor or (vendor_for(mac, self.oui_db) if mac else None)}
            conn.execute("INSERT INTO security_assets VALUES (?,?,?,?)", (asset_id, t, t, _encode(body)))
        else:
            conn.execute("UPDATE security_assets SET first_seen=min(first_seen,?), last_seen=max(last_seen,?) "
                         "WHERE asset_id=?", (t, t, asset_id))
        for kind, value in (*anchors, ("hostname", hostname), ("ip", ip)):
            if value:
                self._interval(asset_id, kind, value, t, ref, source)
        return asset_id

    # --- exposure -------------------------------------------------------
    def _service(self, ip, t, source, ref, protocol, port, *, names=(), peer=None, verification=None):
        protocol = str(protocol or "").lower()
        if protocol not in {"tcp", "udp"} or not isinstance(port, int) or isinstance(port, bool) \
                or not 0 < port <= 65535:
            return None
        asset_id = self.observe(t, source, ref, ip=ip)
        if asset_id is None:
            return None
        conn = self.store.conn
        row = conn.execute("SELECT * FROM security_asset_services WHERE asset_id=? AND protocol=? AND port=?",
                           (asset_id, protocol, port)).fetchone()
        if row:
            body = json.loads(row["body"])
        else:
            known = conn.execute("SELECT first_seen FROM security_assets WHERE asset_id=?", (asset_id,)).fetchone()
            body = {"new_on_known_asset": known["first_seen"] <= t - NEW_SERVICE_AFTER_SEC,
                    "external_peers": 0, "lan_peers": 0}
        _merge(body, ref, source, names=names)
        if peer is not None:
            body["external_peers" if peer == "external" else "lan_peers"] += 1
        first, last = (min(row["first_seen"], t), max(row["last_seen"], t)) if row else (t, t)
        conn.execute("""INSERT INTO security_asset_services VALUES (?,?,?,?,?,?) ON CONFLICT(asset_id, protocol, port)
            DO UPDATE SET first_seen=excluded.first_seen, last_seen=excluded.last_seen, body=excluded.body""",
                     (asset_id, protocol, port, first, last, _encode(body)))
        score, reasons = rank(protocol, port, body)
        finding_id = hashlib.sha256(_encode(["service", asset_id, protocol, port]).encode()).hexdigest()[:32]
        finding = {"finding_id": finding_id, "asset_id": asset_id, "kind": "exposed_service",
                   "protocol": protocol, "port": port, "ip": self._local(ip), "score": score, "reasons": reasons,
                   "names": body.get("names", []), "evidence": body["evidence"], "sources": body["sources"],
                   "status": "open", "verification": verification or "passive observation; no active check"}
        conn.execute("""INSERT INTO security_exposure_findings VALUES (?,?,?,?,?,1,?)
            ON CONFLICT(finding_id) DO UPDATE SET score=excluded.score, first_seen=min(first_seen, excluded.first_seen),
            last_seen=max(last_seen, excluded.last_seen), observations=observations+1, body=excluded.body""",
                     (finding_id, asset_id, score, first, last, _encode(finding)))
        return finding_id

    def _software(self, ip, t, source, ref, name, version, *, kind=None, port=None):
        name, version = _text(name), _text(version) or ""
        if not name:
            return None
        asset_id = self.observe(t, source, ref, ip=ip)
        if asset_id is None:
            return None
        conn = self.store.conn
        row = conn.execute("SELECT * FROM security_asset_software WHERE asset_id=? AND name=? AND version=?",
                           (asset_id, name, version)).fetchone()
        body = _merge(json.loads(row["body"]) if row else {"assertion": "hypothesis", "note": HYPOTHESIS},
                      ref, source, types=[kind], ports=[port])
        conn.execute("""INSERT INTO security_asset_software VALUES (?,?,?,?,?,?) ON CONFLICT(asset_id, name, version)
            DO UPDATE SET first_seen=min(first_seen, excluded.first_seen),
            last_seen=max(last_seen, excluded.last_seen), body=excluded.body""",
                     (asset_id, name, version, t, t, _encode(body)))
        return asset_id

    # --- native record handlers -----------------------------------------
    def _handle(self, source, event_type, row):
        n, native, ref = row["normalized"], row["native"], row["event_id"]
        t = float(n["event_time"])
        if source == "CONTROL" and event_type == "dhcp":
            s = n.get("summary") or {}
            self.observe(t, "CONTROL", ref, mac=s.get("client_mac"), client_id=s.get("client_id"),
                         hostname=s.get("hostname"), ip=s.get("offered_ip") if s.get("message_type") == 5 else None)
        elif source == "CONTROL" and event_type == "arp":
            from netwatch_capture import parse_ethernet_frame

            parsed = parse_ethernet_frame(bytes.fromhex(native["frame"]), t)
            if parsed and parsed[0] == "arp" and parsed[1]["op"] in (1, 2):
                mac = parsed[1]["sender_mac"]
                self.observe(t, "CONTROL", ref, mac=mac, ip=self._arp_ip(t, mac, parsed[1]["sender_ip"]))
        elif source == "CONTROL" and event_type in ("ipv6_na", "ipv6_ns"):
            # NDP is IPv6's ARP: the advertiser's MAC holds the target address, so a rotating
            # temporary address joins its device instead of minting an address-only asset.
            # Solicitations matter too: a new temporary address is announced by duplicate-address
            # detection (NS from ::, target = the new address), and any other NS comes from the
            # sender's own address. Devices often never send an NA the mirror can see.
            name = "ICMPv6ND_NA" if event_type == "ipv6_na" else "ICMPv6ND_NS"
            target = next((layer.get("fields", {}).get("tgt") for layer in (n.get("summary") or {}).get("layers", ())
                           if layer.get("layer") == name), None)
            src = n.get("src_ip")
            if event_type == "ipv6_ns" and not (src and ipaddress.ip_address(src).is_unspecified):
                target = src
            mac = n.get("mac_src")
            if target and self._mac(mac):
                self.observe(t, "CONTROL", ref, mac=mac, ip=self._arp_ip(t, mac, target))
        elif source == "SURICATA" and self._local(native.get("dest_ip")):
            # App-layer metadata on a local destination means the local server answered.
            peer = "lan" if self._local(native.get("src_ip")) else "external"
            self._service(native.get("dest_ip"), t, "SURICATA", ref, native.get("proto"), native.get("dest_port"),
                          names=[native.get("app_proto") or event_type], peer=peer)
            meta = native.get(event_type) if isinstance(native.get(event_type), dict) else {}
            if event_type == "tls" and meta.get("version"):
                self._software(native["dest_ip"], t, "SURICATA", ref, "TLS", meta["version"],
                               kind="tls-protocol", port=native.get("dest_port"))
            if event_type == "http" and meta.get("server"):
                self._software(native["dest_ip"], t, "SURICATA", ref, meta["server"], "",
                               kind="http-server-header", port=native.get("dest_port"))
        if source == "SURICATA" and event_type == "http":
            agent = (native.get("http") or {}).get("http_user_agent") if isinstance(native.get("http"), dict) else None
            if agent and self._local(native.get("src_ip")):
                self._software(native["src_ip"], t, "SURICATA", ref, agent, "", kind="http-user-agent")

    def poll(self, limit=256):
        # Pages are read outside the writer lock (this analyzer is the only writer of its cursors)
        # and every stream with work commits in one transaction: a lock wait per stream, nine
        # streams every 2 s, kept the core loop from turning for 30 s on the sensor VM.
        work = []
        for source, event_type in STREAMS:
            key = CURSOR_PREFIX + f"{source}:{event_type}"
            after = (self.store.cursor(key) or {"sequence": 0})["sequence"]
            rows, scanned_to = self.store.source_stream_page(source, event_type, after, limit)
            if scanned_to > after:
                work.append((key, source, event_type, rows, scanned_to))
        if work:
            with self.store._transaction():
                for key, source, event_type, rows, scanned_to in work:
                    for row in rows:
                        try:
                            self._handle(source, event_type, row)
                        except (ValueError, TypeError, KeyError, AttributeError):
                            self.skipped += 1  # One malformed record must not stall the stream.
                    self.store._checkpoint(key, {"sequence": scanned_to})
        return sum(len(rows) for *_, rows, _ in work)

    def observe_inventory(self, devices):
        """NetWatch inventory rows contribute MAC identity and vendor; their IP lists carry no times."""
        seen = {}
        with self.store._transaction():
            for device in devices:
                last = device["last_seen"]
                seen[device["mac"]] = last
                if self._inventory_seen.get(device["mac"]) == last:
                    continue  # unchanged since the last cycle: no new sighting to record
                for t in ((last,) if device["mac"] in self._inventory_seen else (device["first_seen"], last)):
                    self.observe(float(t), "INVENTORY", None, mac=device["mac"], vendor=device.get("vendor"))
        self._inventory_seen = seen


# --- bounded reads for the API ---------------------------------------------
def _limit(value, default=200):
    return max(1, min(READ_LIMIT, int(default if value is None else value)))


def _rows(store, sql, params=()):
    return [dict(row) | {"body": json.loads(row["body"])} for row in store._read(sql, params)]


def _labels(body, current):
    from netwatch_wireless import wireless_labels

    return wireless_labels(current["mac"], body.get("vendor"), current.get("hostname")) if current.get("mac") else None


def node_name(nodes, mac, ip):
    """Configured SECURE_NODES name for a MAC, else (no MAC known) for an IP; None when unlisted."""
    for name, node in (nodes or {}).items():
        if mac:
            if mac.lower() in (m.lower() for m in node.get("macs") or ()):
                return name
        elif ip and ip in (node.get("ips") or ()):
            return name
    return None


def list_assets(store, limit=None, nodes=None):
    assets = _rows(store, "SELECT * FROM security_assets ORDER BY last_seen DESC, asset_id LIMIT ?", (_limit(limit),))
    if assets:
        marks = ",".join("?" * len(assets))
        ids = [asset["asset_id"] for asset in assets]
        current = {}
        # SQLite returns the bare columns of the MAX(last_seen) row in each group.
        for row in store._read(f"""SELECT asset_id, kind, value, MAX(last_seen) AS last_seen
                FROM security_asset_identities WHERE asset_id IN ({marks}) GROUP BY asset_id, kind""", ids):
            current.setdefault(row["asset_id"], {})[row["kind"]] = row["value"]
        scores = {row[0]: row[1] for row in store._read(
            f"SELECT asset_id, MAX(score) FROM security_exposure_findings WHERE asset_id IN ({marks}) "
            "GROUP BY asset_id", ids)}
        for asset in assets:
            asset["current"] = current.get(asset["asset_id"], {})
            asset["labels"] = _labels(asset["body"], asset["current"])
            asset["node_name"] = node_name(nodes, asset["current"].get("mac"), asset["current"].get("ip"))
            asset["max_finding_score"] = scores.get(asset["asset_id"])
    return assets


def asset_detail(store, asset_id, nodes=None):
    if not isinstance(asset_id, str) or not ASSET_ID.fullmatch(asset_id):
        raise ValueError("invalid asset id")
    asset = _rows(store, "SELECT * FROM security_assets WHERE asset_id=?", (asset_id,))
    if not asset:
        return None
    mac = _rows(store, "SELECT * FROM security_asset_identities WHERE asset_id=? AND kind='mac' "
                       "ORDER BY last_seen DESC LIMIT 1", (asset_id,))
    name = _rows(store, "SELECT * FROM security_asset_identities WHERE asset_id=? AND kind='hostname' "
                        "ORDER BY last_seen DESC LIMIT 1", (asset_id,))
    ip = _rows(store, "SELECT * FROM security_asset_identities WHERE asset_id=? AND kind='ip' "
                      "ORDER BY last_seen DESC LIMIT 1", (asset_id,))
    return asset[0] | {"node_name": node_name(nodes, mac[0]["value"] if mac else None, ip[0]["value"] if ip else None),
                       "limit": READ_LIMIT, "labels": _labels(asset[0]["body"], {
        "mac": mac[0]["value"] if mac else None, "hostname": name[0]["value"] if name else None})} | {
        name: _rows(store, f"SELECT * FROM {table} WHERE asset_id=? ORDER BY {order} LIMIT ?", (asset_id, READ_LIMIT))
        for name, table, order in (
            ("identities", "security_asset_identities", "first_seen, interval_id"),
            ("services", "security_asset_services", "protocol, port"),
            ("software", "security_asset_software", "last_seen DESC"),
            ("findings", "security_exposure_findings", "score DESC, last_seen DESC"))}


def exposure(store, limit=None):
    return _rows(store, "SELECT * FROM security_exposure_findings ORDER BY score DESC, last_seen DESC, finding_id "
                        "LIMIT ?", (_limit(limit),))


# --- retention ---------------------------------------------------------------
ASSET_CHILDREN = ("security_asset_identities", "security_asset_services", "security_asset_software",
                  "security_exposure_findings")


def prune_assets(store, *, retention_days, batch=500, now):
    """Delete one batch of assets idle since the cutoff with their child rows; ``(removed, more)``.

    An asset is kept while a case links it, an unclosed response action targets one of its
    MAC or IP identities, or it has an open exposure finding seen since the cutoff.
    """
    if retention_days <= 0:
        return 0, False
    with store._transaction():
        ids = [row[0] for row in store.conn.execute("""SELECT asset_id FROM security_assets a
            WHERE a.last_seen < :cutoff
            AND a.asset_id NOT IN (SELECT reference FROM security_case_links WHERE kind='asset')
            AND a.asset_id NOT IN (SELECT i.asset_id FROM security_response_actions r
                JOIN security_asset_identities i ON i.kind IN ('mac', 'ip') AND i.value=r.target
                WHERE r.state IN ('requested', 'approved', 'applied'))
            AND NOT EXISTS (SELECT 1 FROM security_exposure_findings f WHERE f.asset_id=a.asset_id
                AND f.last_seen >= :cutoff AND json_extract(f.body, '$.status')='open')
            ORDER BY a.last_seen LIMIT :limit""",
            {"cutoff": float(now) - float(retention_days) * 86400, "limit": batch}).fetchall()]
        if ids:
            marks = ",".join("?" * len(ids))
            for table in (*ASSET_CHILDREN, "security_assets"):  # children first: foreign keys are on
                store.conn.execute(f"DELETE FROM {table} WHERE asset_id IN ({marks})", ids)
    return len(ids), len(ids) >= batch


# --- record -> asset join ----------------------------------------------------
# Resolved at read time: identities are intervals that later evidence extends or splits, so a
# link stored at ingest would go stale; the holder of the address at the record's time is
# looked up on every read instead. Only local addresses resolve (remote peers own no asset).
RECORD_SCAN = 5000


def record_ips(normalized):
    """Addresses a source record can be pivoted by: its endpoints."""
    return [normalized.get(key) for key in ("src_ip", "dst_ip")]


class AssetResolver:
    def __init__(self, store, config):
        networks = (*config.get("LOCAL_PREFIXES", ()), *config.get("LOCAL_PREFIXES6", ()))
        self.store = store
        self.v4, self.v6 = compile_v4_prefixes(networks), compile_v6_prefixes(networks)

    def resolve(self, ips, t):
        """Asset ids holding the local addresses among ``ips`` at time ``t``, in order, without repeats."""
        found = []
        for ip in ips:
            ip = local_ip(ip, self.v4, self.v6) if ip else None
            asset = holder(self.store._read, ip, t) if ip else None
            if asset and asset not in found:
                found.append(asset)
        return found

    def annotate(self, rows):
        """Fill ``normalized.asset_ids`` on source-event rows."""
        for row in rows:
            row["normalized"]["asset_ids"] = self.resolve(record_ips(row["normalized"]), row["event_time"])
        return rows

    def annotate_detections(self, rows):
        for row in rows:
            data = row["payload"].get("data") or {}
            row["asset_ids"] = self.resolve([data.get("src_ip"), data.get("dst_ip"), data.get("offender_ip"),
                                             row["payload"].get("target_id")], row["event_time"])
        return rows

    def asset_records(self, asset_id, limit=100):
        """Newest records among the last ``RECORD_SCAN`` committed that resolve to the asset."""
        rows = self.store._read("""SELECT s.* FROM security_source_order o
            CROSS JOIN security_source_events s ON s.event_id=o.event_id
            WHERE o.sequence > (SELECT COALESCE(MAX(sequence), 0) FROM security_source_order) - ?
            ORDER BY o.sequence DESC""", (RECORD_SCAN,))
        out = []
        for row in rows:
            row = dict(row) | {"normalized": json.loads(row["normalized"])}
            if asset_id in self.resolve(record_ips(row["normalized"]), row["event_time"]):
                out.append(row | {"native": None})
                if len(out) >= limit:
                    break
        return {"asset_id": asset_id, "scanned": RECORD_SCAN, "records": self.annotate(out)}
