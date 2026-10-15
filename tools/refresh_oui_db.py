"""Regenerate ``oui_db.json`` (the MAC OUI -> vendor map) from the official IEEE
MA-L registry.

The IEEE OUI registry is public and freely redistributable, so the generated map
can be committed. Run this to refresh vendor coverage:

    python tools/refresh_oui_db.py

It writes ``oui_db.json`` next to the repo root as a compact ``{"AABBCC": "Vendor"}``
object. If the download fails (offline/CI), it still writes the small curated
``_SEED`` map below so the feature degrades gracefully rather than shipping nothing.
"""

import csv
import io
import json
import os
import sys
import urllib.request

IEEE_MA_L_CSV = "https://standards-oui.ieee.org/oui/oui.csv"
OUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "oui_db.json")

# Curated fallback: common consumer / networking / IoT vendors, plus the OUIs of
# this development host's own NICs so the live demo resolves to real names even
# offline. Overwritten by the full IEEE set on a successful download.
_SEED = {
    "6C1FF7": "Realtek (USB 2.5GbE)",       # common USB 2.5GbE capture NIC
    "381428": "Rivet Networks (Killer)",    # gaming laptop wired NIC
    "E02BE9": "Rivet Networks (Killer)",    # gaming laptop Wi-Fi / BT
    "00155D": "Microsoft (Hyper-V vNIC)",
    "001A11": "Google",
    "3C5AB4": "Google",
    "F0EF86": "Google",
    "001D0F": "TP-Link",
    "50C7BF": "TP-Link",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi (Trading)",
    "001132": "Synology",
    "0050F2": "Microsoft",
    "F4F5D8": "Google (Nest)",
    "18B430": "Nest Labs",
    "00177A": "ASSA ABLOY (August)",
    "ACDE48": "Private",
    "001451": "Apple",
    "3C0754": "Apple",
    "A4B197": "Apple",
    "F0766F": "Apple",
    "D8BB2C": "Apple",
    "001E52": "Apple",
    "5CF938": "Apple",
    "AC1F6B": "Super Micro",
    "001517": "Intel",
    "3CA9F4": "Intel",
    "A0C589": "Intel",
    "0C8BFD": "Intel",
    "001956": "Cisco",
    "00000C": "Cisco",
    "F8E4FB": "Actiontec (ISP gateway)",
    "207759": "Amazon Technologies",
    "FC65DE": "Amazon (Echo)",
    "44650D": "Amazon Technologies",
    "ECFABC": "Espressif (ESP IoT)",
    "246F28": "Espressif (ESP IoT)",
    "A020A6": "Espressif (ESP IoT)",
    "D8A01D": "Espressif (ESP IoT)",
    "B4E62D": "Espressif (ESP IoT)",
    "001788": "Philips Hue",
    "00125A": "Microsoft (Xbox)",
    "7C1E52": "Microsoft",
    "002241": "Dell",
    "F8BC12": "Dell",
    "B083FE": "Dell",
    "001CC4": "Hewlett Packard",
    "3863BB": "Hewlett Packard",
    "94188C": "Samsung",
    "8425DB": "Samsung",
    "5CE8EB": "Samsung",
    "0021D1": "Sony",
    "FCF152": "Sony",
}


def build_from_ieee():
    """Download + parse the IEEE MA-L CSV into {assignment: organization}. Raises on
    any network/parse failure so the caller can fall back to the seed."""
    req = urllib.request.Request(IEEE_MA_L_CSV, headers={"User-Agent": "NetWatch-OUI/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    out = {}
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        assignment = (row.get("Assignment") or "").strip().upper()
        org = (row.get("Organization Name") or "").strip()
        if len(assignment) == 6 and org:
            out[assignment] = org
    if len(out) < 1000:  # sanity: a healthy registry has tens of thousands
        raise ValueError(f"IEEE parse yielded only {len(out)} entries; refusing")
    return out


def main():
    try:
        db = build_from_ieee()
        # Keep the host-NIC labels from the seed for a nicer demo even with full data.
        for k, v in _SEED.items():
            db.setdefault(k, v)
        source = f"IEEE MA-L ({len(db)} entries)"
    except Exception as e:  # noqa: BLE001 - any failure → graceful curated fallback
        if os.path.exists(OUT_PATH):  # a stub seed must never replace an existing db
            print(f"[refresh_oui_db] IEEE download failed ({e}); leaving {OUT_PATH} untouched.", file=sys.stderr)
            return 1
        print(f"[refresh_oui_db] IEEE download failed ({e}); writing curated seed.", file=sys.stderr)
        db = dict(_SEED)
        source = f"curated seed ({len(db)} entries)"
    tmp = f"{OUT_PATH}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, OUT_PATH)
    print(f"[refresh_oui_db] wrote {OUT_PATH} from {source}")


if __name__ == "__main__":
    sys.exit(main())
