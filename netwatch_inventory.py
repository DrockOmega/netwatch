"""Passive device inventory: MAC-keyed sightings, OUI vendor lookup, new-device
detection.

This is the first "deeper monitoring" capability (roadmap #1). It follows the same
shape as ``netwatch_mitigation``: the logic is pure and unit-testable (no Qt / GL /
scapy), and state is persisted to a plain JSON ledger. That JSON ledger is a
deliberate seam — today it is a local file; tomorrow the same ``snapshot()`` /
``observe()`` surface could back onto a cloud store without touching the hot path.

Inventory itself is passive: it records only what crosses the capture NIC, so it
adds no traffic of its own. That is a property of this module, not a project-wide
ban on emitting — active response lives in ``netwatch_mitigation`` (firewall) and
``netwatch_quarantine`` (ARP isolation of a LAN device). On a switched network the
passive view is primarily this host, the gateway, and broadcast/multicast peers
unless a SPAN/mirror port feeds the NIC.
"""

import functools
import json
import logging
import time

from netwatch_core import write_json_atomic

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
_HEXSET = set("0123456789abcdef")
# IPs that are never a device's own address — don't attribute them to a MAC.
# 0.0.0.0 = DHCP-discover source / "unspecified"; 255.255.255.255 = limited broadcast.
_NON_DEVICE_IPS = {"0.0.0.0", "255.255.255.255"}


def normalize_mac(mac):
    """Canonicalize a MAC to lowercase colon form ``aa:bb:cc:dd:ee:ff``.

    Accepts ``:``/``-``/``.`` separators or none. Returns ``None`` if the input is
    not exactly 48 bits of hex (i.e. not a usable MAC string)."""
    if not isinstance(mac, str):
        return None
    return _normalize_mac_text(mac)


@functools.lru_cache(maxsize=65536)  # the core normalizes every packet's MACs several times
def _normalize_mac_text(mac):
    h = mac.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    if len(h) != 12 or any(c not in _HEXSET for c in h):
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_usable_mac(mac):
    """True if a MAC is a real, individual device address worth inventorying:
    parseable, not broadcast, not all-zero, and not a group/multicast address
    (I/G bit, the low bit of the first octet, clear)."""
    n = normalize_mac(mac)
    if n is None or n == BROADCAST_MAC or n == ZERO_MAC:
        return False
    return not (int(n[0:2], 16) & 0x01)  # I/G bit set => multicast/group


def oui_of(mac):
    """Uppercase 24-bit OUI key ``AABBCC`` for a MAC, or ``None``."""
    n = normalize_mac(mac)
    return None if n is None else n.replace(":", "")[:6].upper()


def is_locally_administered(mac):
    """True if the U/L bit (bit 2 of the first octet) is set — i.e. a randomized /
    locally-assigned MAC (common on modern phones doing MAC privacy). These have no
    meaningful OUI vendor."""
    n = normalize_mac(mac)
    return n is not None and bool(int(n[0:2], 16) & 0x02)


def vendor_for(mac, oui_db):
    """Resolve a MAC to a vendor string via OUI lookup.

    Order: exact OUI hit wins; otherwise a locally-administered address is labelled
    ``Locally-administered`` (randomized MAC); otherwise ``Unknown``."""
    oui = oui_of(mac)
    if oui is None:
        return "Unknown"
    if oui in oui_db:
        return oui_db[oui]
    if is_locally_administered(mac):
        return "Locally-administered"
    return "Unknown"


def load_oui_db(path):
    """Load an OUI→vendor map from JSON (``{"AABBCC": "Vendor", ...}``). Tolerant of
    separators/case in keys. Missing/corrupt file → empty map (vendors become
    ``Unknown``; never a crash), mirroring the GeoIP-missing degradation."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for k, v in data.items():
        key = str(k).replace(":", "").replace("-", "").replace(".", "").upper()[:6]
        if len(key) == 6:
            out[key] = str(v)
    return out


class DeviceInventory:
    """MAC-keyed passive inventory with new-device detection and JSON persistence.

    ``observe()`` is the per-packet entry point; it is cheap (dict ops only, no
    allocation-heavy work) and never writes to disk. ``save()`` flushes new devices
    and last-seen/IP/count updates and is meant to be called on a periodic cadence
    by the core loop, not per packet.
    """

    MAX_IPS_PER_DEVICE = 32  # cap the per-device IP list so the ledger stays bounded
    MAX_DEVICES = 4096  # refuse (not evict) new MACs past this: evicting would re-feed junk to assets

    def __init__(self, oui_db=None, ledger_path=None, *, alert_on_new=True):
        self.oui_db = oui_db or {}
        self.ledger_path = ledger_path
        self.alert_on_new = alert_on_new
        self.devices = {}  # mac -> {vendor, first_seen, last_seen, ips:[...], count}
        self._dirty = False
        self.refused = 0  # new MACs turned away at MAX_DEVICES
        if ledger_path:
            self._load()
            if len(self.devices) > self.MAX_DEVICES:
                logging.getLogger(__name__).warning(
                    "device ledger holds %d devices (cap %d): no new MACs will be tracked",
                    len(self.devices), self.MAX_DEVICES)

    def observe(self, mac, ip_dotted=None, now=None):
        """Record one sighting of ``mac`` (optionally associated with a LAN IP).

        Returns ``None`` for broadcast/multicast/invalid MACs (nothing inventoried).
        Otherwise returns a small dict; ``new_device`` is True only the first time a
        usable MAC is seen *and* ``alert_on_new`` is enabled — that is the signal the
        core turns into a NEW-DEVICE notice."""
        now = time.time() if now is None else now
        n = normalize_mac(mac)
        if not is_usable_mac(mac):
            return None
        if ip_dotted in _NON_DEVICE_IPS:
            ip_dotted = None  # a MAC's IP is never the unspecified/broadcast address

        entry = self.devices.get(n)
        new_device = entry is None
        if new_device:
            if len(self.devices) >= self.MAX_DEVICES:
                self.refused += 1
                return None
            entry = {
                "vendor": vendor_for(n, self.oui_db),
                "first_seen": now,
                "last_seen": now,
                "ips": [ip_dotted] if ip_dotted else [],
                "count": 1,
            }
            self.devices[n] = entry
            self._dirty = True  # flushed by the periodic save(), not per device
        else:
            entry["last_seen"] = now
            entry["count"] += 1
            if ip_dotted and ip_dotted not in entry["ips"]:
                entry["ips"].append(ip_dotted)
                if len(entry["ips"]) > self.MAX_IPS_PER_DEVICE:
                    entry["ips"] = entry["ips"][-self.MAX_IPS_PER_DEVICE:]
            self._dirty = True

        return {
            "mac": n,
            "vendor": entry["vendor"],
            "ip": ip_dotted,
            "new_device": new_device and self.alert_on_new,
        }

    def snapshot(self):
        """Stable, sorted, copied view of the inventory for the UI/CLI (no internal
        references escape)."""
        return [
            {
                "mac": m,
                "vendor": e["vendor"],
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
                "ips": list(e["ips"]),
                "count": e["count"],
            }
            for m, e in sorted(self.devices.items())
        ]

    def save(self):
        """Flush pending updates to the ledger if anything changed since last write.
        Cheap no-op when clean; call on a periodic cadence."""
        if self._dirty:
            self._save()

    # --- persistence -----------------------------------------------------
    def _save(self):
        if not self.ledger_path:
            self._dirty = False
            return
        if write_json_atomic(self.ledger_path, {"devices": self.devices}):
            self._dirty = False

    def _load(self):
        try:
            with open(self.ledger_path, encoding="utf-8") as f:
                data = json.load(f)
            raw = data.get("devices", {})
            required = {"vendor", "first_seen", "last_seen", "ips", "count"}
            self.devices = {
                m: e for m, e in raw.items()
                if isinstance(e, dict) and required <= e.keys()
                and isinstance(e["ips"], list) and isinstance(e["count"], int)
                and isinstance(e["last_seen"], int | float)
            }
        except (OSError, ValueError):
            self.devices = {}
