"""Ingest nmap XML from a scan of an owned scope into assets and exposure findings.

Nothing here sends a packet. The XML is untrusted: only hosts inside
EXPOSURE_OWNED_SCOPES are recorded; any other host is refused and reported.
Usage: python netwatch_scan.py SCAN.xml DB_PATH [CIDR ...]   (scopes default to the config default)
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time
import xml.etree.ElementTree as ET

from netwatch_assets import DurableAssetAnalyzer
from netwatch_config import build_config
from netwatch_core import make_message
from netwatch_security_store import _encode

MAX_BYTES = 32 * 1024 * 1024
VERIFICATION = "active nmap scan of an owned scope; open port observed"


def _open_findings(conn, asset_id):
    """Open exposure findings for one asset, keyed by (protocol, port)."""
    rows = conn.execute("SELECT finding_id, body FROM security_exposure_findings WHERE asset_id=?", (asset_id,))
    bodies = [(r["finding_id"], json.loads(r["body"])) for r in rows]
    return {(b["protocol"], b["port"]): (fid, b) for fid, b in bodies if b.get("status") == "open"}


def _drift(store, action, ip, ref, port_key, severity, message):
    proto, port = port_key
    store._add(make_message("NMAP", action, ip, {
        "message": message, "severity": severity, "protocol": proto, "port": port,
        "source_event_id": f"{ref}:{action}:{proto}/{port}"}), severity=severity)


def _scan_ranges(root):
    """(protocol, lo, hi) spans the scan declared probing, from <scaninfo services="1-1024,8080">."""
    spans = []
    for info in root.iter("scaninfo"):
        for part in (info.get("services") or "").split(","):
            lo, _, hi = part.partition("-")
            if lo.isdigit() and (not hi or hi.isdigit()):
                spans.append(((info.get("protocol") or "").lower(), int(lo), int(hi or lo)))
    return spans


def _record_drift(store, out, ip, ref, t, new_host, before, seen, probed):
    """Compare one covered host's scan to its open findings from before this scan."""
    if new_host and seen:
        _drift(store, "EXPOSURE_NEW_HOST", ip, ref, min(seen), "alert", f"New host {ip} with {len(seen)} open service(s)")
        out["drift"].append(("new_host", ip))
    elif not new_host:
        for key in sorted(seen - before.keys()):
            _drift(store, "EXPOSURE_NEW_SERVICE", ip, ref, key, "alert", f"New open service {key[0]}/{key[1]} on {ip}")
            out["drift"].append(("new_service", ip, *key))
    for key, (fid, body) in sorted(before.items()):
        # Only a service this scanner saw open, on a host and port this scan probed, counts as remediated.
        if key not in seen and probed(key) and "NMAP" in body.get("sources", []):
            body |= {"status": "resolved", "resolved_at": t, "verification": "rescan of an owned scope; port no longer open"}
            store.conn.execute("UPDATE security_exposure_findings SET body=? WHERE finding_id=?", (_encode(body), fid))
            _drift(store, "EXPOSURE_SERVICE_CLOSED", ip, ref, key, "info",
                   f"Remediation verified: {key[0]}/{key[1]} on {ip} no longer open")
            out["drift"].append(("closed", ip, *key))


def ingest_nmap(analyzer, xml_bytes, scopes):
    """Record open ports from nmap XML; returns counts and the refused addresses."""
    if len(xml_bytes) > MAX_BYTES or b"<!ENTITY" in xml_bytes.upper():
        raise ValueError("nmap XML is too large or declares entities")
    try:
        root = ET.fromstring(xml_bytes)  # noqa: S314 - entity declarations refused above; nmap emits a plain DOCTYPE
    except ET.ParseError as exc:
        raise ValueError(f"not valid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ValueError("not an nmap XML document")
    spans = _scan_ranges(root)
    nets = [ipaddress.ip_network(s) for s in scopes]
    out = {"hosts": 0, "services": 0, "refused": [], "drift": []}
    conn = analyzer.store.conn
    with analyzer.store._transaction():
        # The first scan into a store is the baseline: nothing to drift from yet.
        baselined = conn.execute("SELECT 1 FROM security_exposure_findings WHERE body LIKE '%\"NMAP\"%' LIMIT 1"
                                 ).fetchone() is not None
        for host in root.iter("host"):
            addrs = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
            try:
                ip = ipaddress.ip_address(addrs.get("ipv4") or addrs.get("ipv6") or "")
            except ValueError:
                out["refused"].append("unparseable address")
                continue
            if not any(ip in net for net in nets):
                out["refused"].append(str(ip))
                continue
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            try:
                t = float(int(host.get("endtime") or host.get("starttime")))
            except (TypeError, ValueError):
                t = time.time()
            ref = f"nmap:{ip}:{int(t)}"
            holder = analyzer._holder(str(ip), t)
            before = _open_findings(conn, holder) if holder else {}
            name = next((h.get("name") for h in host.iter("hostname")), None)
            analyzer.observe(t, "NMAP", ref, mac=addrs.get("mac"), hostname=name, ip=str(ip))
            out["hosts"] += 1
            seen, listed = set(), set()
            for port in host.iter("port"):
                state, svc = port.find("state"), port.find("service")
                if (port.get("portid") or "").isdigit():
                    listed.add((str(port.get("protocol")).lower(), int(port.get("portid"))))
                if state is None or state.get("state") != "open" or not (port.get("portid") or "").isdigit():
                    continue
                number = int(port.get("portid"))
                seen.add((str(port.get("protocol")).lower(), number))
                names = [svc.get("name")] if svc is not None and svc.get("name") else []
                if analyzer._service(str(ip), t, "NMAP", ref, port.get("protocol"), number, names=names,
                                     verification=VERIFICATION):
                    out["services"] += 1
                    if svc is not None and svc.get("product"):
                        analyzer._software(str(ip), t, "NMAP", ref, svc.get("product"), svc.get("version") or "",
                                           kind="nmap-service-version", port=number)
            if baselined:
                _record_drift(analyzer.store, out, str(ip), ref, t, holder is None, before, seen,
                              lambda k, listed=listed: k in listed or any(k[0] == p and lo <= k[1] <= hi for p, lo, hi in spans))
    return out


def main(argv):
    from netwatch_security_store import DurableIncidentStore

    xml_path, db_path, *scopes = argv[1:]
    scopes = scopes or build_config(os.path.dirname(os.path.abspath(__file__)))[0]["EXPOSURE_OWNED_SCOPES"]
    store = DurableIncidentStore(db_path, sensor_id="nmap-ingest")
    try:
        analyzer = DurableAssetAnalyzer(store, {"LOCAL_PREFIXES": scopes})
        data = sys.stdin.buffer.read(MAX_BYTES + 1) if xml_path == "-" else open(xml_path, "rb").read()  # noqa: SIM115
        print(ingest_nmap(analyzer, data, scopes))
    finally:
        store.close()


if __name__ == "__main__":
    main(sys.argv)
