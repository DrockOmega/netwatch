"""Wireless/IoT slice that needs nothing from the AP: device appeared / went quiet, AP-mode guard, labels.

Everything comes from what the uplink mirror already gives NetWatch (assets, inventory, DHCP).
Radio-level telemetry (association, deauthentication, rogue AP) is not collected and `COVERAGE`
says so; that statement is published in the source health row.
"""

from __future__ import annotations

import json
import time

from netwatch_core import make_message
from netwatch_inventory import is_locally_administered, normalize_mac
from netwatch_security_store import note_notify_failure

STATE_KEY = "ANALYSIS:WIRELESS:v1"
HEALTH_KEY = "ANALYSIS:WIRELESS:v1"
AP_DHCP_REPEAT_SEC = 3600
COVERAGE = {
    "observed": "Ethernet frames on the uplink mirror: Wi-Fi clients' own MACs, DHCP leases, ARP, DNS and flows",
    "unsupported": ["association and disassociation events", "deauthentication/disassociation bursts",
                    "rogue AP / evil-twin detection", "SSID, channel and radio security posture",
                    "per-radio client signal and roaming"],
    "blind_spots": ["Wi-Fi-to-LAN traffic that does not cross the uplink mirror (same-AP client-to-client, "
                    "AP-to-switch local traffic) is invisible"],
    "reason": "the access point exports no remote syslog or SNMP",
}

# Best-effort inference only: OUI vendor / DHCP hostname substrings that usually mean a Wi-Fi client.
WIRELESS_VENDORS = ("espressif", "tuya", "shelly", "murata", "azurewave", "liteon", "lite-on", "wyze", "ring ",
                    "sonos", "roku", "nest", "amazon", "google", "samsung", "apple", "intel corporate",
                    "realtek semiconductor", "hon hai", "ecobee", "chamberlain", "sharkninja", "irobot")
WIRELESS_HOSTNAMES = ("iphone", "ipad", "android", "galaxy", "pixel", "esp32", "esp8266", "esp-", "echo", "roku",
                      "chromecast", "wyze", "ring-", "shelly", "tasmota", "sonos", "kindle", "fire-", "wlan", "wifi")


def wireless_labels(mac, vendor=None, hostname=None):
    """`private_mac` is read off the MAC; `likely_wireless` is a guess and says so."""
    private = is_locally_administered(mac)
    reasons = []
    if private:
        reasons.append("randomized (locally-administered) MAC, typical of phones and laptops")
    if vendor and any(word in vendor.lower() for word in WIRELESS_VENDORS):
        reasons.append(f"vendor OUI '{vendor}' commonly makes Wi-Fi devices")
    if hostname and any(word in hostname.lower() for word in WIRELESS_HOSTNAMES):
        reasons.append(f"DHCP hostname '{hostname}' suggests a Wi-Fi device")
    return {"private_mac": {"value": private, "basis": "observed: locally-administered bit of the MAC"},
            "likely_wireless": {"value": bool(reasons), "basis": "inference, not observation", "reasons": reasons}}


class WirelessWatch:
    def __init__(self, store, config, notify=None):
        self.store, self.notify, self.last_error = store, notify, None
        self.notify_failures = 0
        self.quiet_sec = float(config.get("WIRELESS_QUIET_SEC", 86400))
        self.ap_macs = {m for v in config.get("WIRELESS_AP_MACS", ()) if (m := normalize_mac(v))}
        self.ap_addresses = {str(v) for v in config.get("WIRELESS_AP_ADDRESSES", ())}
        self.sensor_id = config.get("SENSOR_ID", "unknown")

    def health(self):
        state = self.store.cursor(STATE_KEY) or {}
        return {"status": "DEGRADED" if self.last_error else "RUNNING", "last_error": self.last_error,
                "baseline_at": state.get("baseline_at"), "quiet_sec": self.quiet_sec,
                "ap_macs": sorted(self.ap_macs), "ap_addresses": sorted(self.ap_addresses), "coverage": COVERAGE,
                "notify_failures": self.notify_failures}

    def _detect(self, action, key, t, message, severity, **data):
        return make_message("WIRELESS_WATCH", action, "UI_SHELL", {
            "source_event_id": key, "sensor_id": self.sensor_id, "timestamp": t, "message": message,
            "severity": severity, "confidence": "Observed", "containment_eligible": False,
            "correlation_entity": key, **data}, correlation_id=key)

    def _devices(self, where, params):
        """MAC-anchored assets (AP excluded) with rowid, times, body and MAC."""
        rows = self.store._read(f"""SELECT a.rowid AS rid, a.asset_id, a.first_seen, a.last_seen, a.body, i.value AS mac
            FROM security_assets a JOIN security_asset_identities i ON i.asset_id=a.asset_id AND i.kind='mac'
            WHERE {where} GROUP BY a.asset_id ORDER BY a.rowid""", params)
        return [r for r in rows if r["mac"] not in self.ap_macs]

    def poll(self, now=None, devices=()):
        now = time.time() if now is None else float(now)
        out = []
        state = self.store.cursor(STATE_KEY)
        if state is None:  # First run: everything already known is baseline, never an alert.
            top = self.store._read("SELECT COALESCE(MAX(rowid), 0) FROM security_assets")[0][0]
            quiet = {r["asset_id"]: r["last_seen"] for r in self._devices("a.last_seen<?", (now - self.quiet_sec,))}
            state = {"baseline_at": now, "rowid": top, "quiet": quiet, "ap_ips": [], "dhcp_seq": 0,
                     "dhcp_alert_t": 0}
        # A new asset needs both a row after the baseline and a first sighting after it, so a
        # history replay into a fresh store cannot flood.
        for r in self._devices("a.rowid>? AND a.first_seen>=?", (state["rowid"], state["baseline_at"])):
            labels = wireless_labels(r["mac"], json.loads(r["body"]).get("vendor"))
            out.append(self._detect("WIRELESS_DEVICE_NEW", f"wireless-new:{r['asset_id']}", r["first_seen"],
                                    f"WIRELESS: new device {r['mac']} first seen", "notice",
                                    offender_mac=r["mac"], asset_id=r["asset_id"], labels=labels))
        state["rowid"] = self.store._read("SELECT COALESCE(MAX(rowid), 0) FROM security_assets")[0][0]
        for r in self._devices("a.last_seen<?", (now - self.quiet_sec,)):
            if is_locally_administered(r["mac"]) or state["quiet"].get(r["asset_id"]) == r["last_seen"]:
                continue  # private MACs rotate, so silence is expected; one report per quiet spell
            state["quiet"][r["asset_id"]] = r["last_seen"]
            since = time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["last_seen"]))
            out.append(self._detect("WIRELESS_DEVICE_QUIET", f"wireless-quiet:{r['asset_id']}:{r['last_seen']}",
                                    now, f"WIRELESS: {r['mac']} silent since {since} UTC", "info",
                                    offender_mac=r["mac"], asset_id=r["asset_id"], last_seen=r["last_seen"]))
        out += self._guard(state, devices)
        # Reads above run outside the writer lock (the dhcp scan can be slow); this is the only writer.
        with self.store._transaction():
            for payload in out:  # committed with the state; the notify below is presentation only
                self.store._add(payload)
            self.store._checkpoint(STATE_KEY, state)
        for payload in out:
            if self.notify:
                try:
                    self.notify(payload)
                except Exception:
                    note_notify_failure(self)  # the detection is re-derivable; a failed presentation must not stall the watch
        return len(out)

    def _guard(self, state, devices):
        """The AP must stay a bridge: it must not serve DHCP or present more than one IP."""
        if not (self.ap_macs or self.ap_addresses):
            return []
        out = []
        rows, scanned_to = self.store.source_stream_page("CONTROL", "dhcp", state["dhcp_seq"], 256)
        state["dhcp_seq"] = max(state["dhcp_seq"], scanned_to)
        for row in rows:
            n, s = row["normalized"], row["normalized"].get("summary") or {}
            if s.get("message_type") in (2, 5) and (normalize_mac(n.get("mac_src")) in self.ap_macs
                                                    or n.get("src_ip") in self.ap_addresses
                                                    or s.get("server_id") in self.ap_addresses):
                t = float(n["event_time"])
                if t - state["dhcp_alert_t"] >= AP_DHCP_REPEAT_SEC:
                    state["dhcp_alert_t"] = t
                    out.append(self._detect("WIRELESS_AP_MODE", f"wireless-ap-dhcp:{row['event_id']}", t,
                                            "WIRELESS: access point is answering DHCP; it may have left AP mode",
                                            "alert", offender_mac=n.get("mac_src"), native_event_id=row["event_id"]))
        for device in devices:
            ips = sorted(set(device.get("ips", ())))
            if normalize_mac(device["mac"]) in self.ap_macs and len(ips) > 1 and ips != state["ap_ips"]:
                state["ap_ips"] = ips
                out.append(self._detect("WIRELESS_AP_MODE", f"wireless-ap-ips:{device['mac']}:{','.join(ips)}",
                                        device["last_seen"], f"WIRELESS: {len(ips)} IPs ({', '.join(ips)}) behind the "
                                        f"access point MAC {device['mac']}; it may be NAT'ing", "alert",
                                        offender_mac=device["mac"], ips=ips))
        return out
