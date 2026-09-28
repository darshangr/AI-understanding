"""Device identification: MAC vendor lookup and device-type heuristics."""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

# Small built-in OUI table for vendors that are common on home networks.
# Run ``python -m netmon update-oui`` to download the full IEEE registry.
_BUILTIN_OUI = {
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "F0:D5:BF": "Google", "F4:F5:D8": "Google", "54:60:09": "Google", "3C:5A:B4": "Google", "1C:F2:9A": "Google",
    "18:B4:30": "Nest Labs", "64:16:66": "Nest Labs",
    "44:65:0D": "Amazon", "68:54:FD": "Amazon", "FC:65:DE": "Amazon", "74:C2:46": "Amazon",
    "F0:27:2D": "Amazon", "A0:02:DC": "Amazon", "0C:47:C9": "Amazon", "84:D6:D0": "Amazon",
    "B0:A7:37": "Roku", "D8:31:34": "Roku", "CC:6D:A0": "Roku", "AC:3A:7A": "Roku", "08:05:81": "Roku",
    "34:3E:A4": "Ring", "9C:76:13": "Ring",
    "D8:F1:5B": "Espressif (IoT)", "24:0A:C4": "Espressif (IoT)", "30:AE:A4": "Espressif (IoT)",
    "84:F3:EB": "Espressif (IoT)", "A4:CF:12": "Espressif (IoT)", "BC:DD:C2": "Espressif (IoT)",
    "68:57:2D": "Tuya (IoT)", "10:D5:61": "Tuya (IoT)", "D8:1F:12": "Tuya (IoT)",
    "50:C7:BF": "TP-Link", "B0:95:75": "TP-Link", "60:32:B1": "TP-Link", "98:DA:C4": "TP-Link",
    "00:1A:11": "Google", "F8:0F:F9": "Google",
    "8C:85:90": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple", "3C:22:FB": "Apple", "AC:BC:32": "Apple",
    "BC:D0:74": "Apple", "F4:0F:24": "Apple", "DC:A9:04": "Apple", "88:66:5A": "Apple", "14:7D:DA": "Apple",
    "8C:79:F5": "Samsung", "F8:04:2E": "Samsung", "5C:49:7D": "Samsung", "A0:CB:FD": "Samsung", "84:A4:66": "Samsung",
    "00:1D:BA": "Sony", "FC:F1:52": "Sony", "70:9E:29": "Sony",
    "7C:1E:52": "Microsoft", "98:5F:D3": "Microsoft", "C8:3F:26": "Microsoft",
    "00:24:E4": "Withings", "00:04:20": "Logitech (Harmony)",
    "3C:28:6D": "Google", "A4:77:33": "Google",
    "00:0E:58": "Sonos", "5C:AA:FD": "Sonos", "B8:E9:37": "Sonos", "48:A6:B8": "Sonos",
    "00:1E:C2": "Apple", "C8:D0:83": "Apple",
    "30:05:5C": "Brother", "00:80:77": "Brother", "3C:2A:F4": "Brother",
    "00:1E:0B": "HP", "A0:8C:FD": "HP", "10:1F:74": "HP",
    "00:00:48": "Epson", "64:EB:8C": "Epson",
    "B4:79:A7": "Samsung SmartThings", "28:6D:97": "Samsung SmartThings",
    "E8:9F:80": "Belkin (Wemo)", "94:10:3E": "Belkin (Wemo)",
    "2C:AA:8E": "Wyze", "7C:78:B2": "Wyze",
    "00:62:6E": "Arlo", "A4:11:62": "Arlo",
    "00:1F:A7": "Sony PlayStation", "00:D9:D1": "Sony PlayStation",
    "98:B6:E9": "Nintendo", "E8:4E:CE": "Nintendo",
    "E0:37:17": "AT&T (Arris)", "D0:39:B3": "AT&T (Arris)", "08:9B:B9": "AT&T (Nokia)",
    "18:9C:27": "AT&T (Arris)", "F8:2C:18": "AT&T (Arris)",
    "A8:6E:84": "LG Electronics", "64:95:6C": "LG Electronics", "CC:2D:8C": "LG Electronics",
    "00:04:4B": "NVIDIA Shield", "48:B0:2D": "NVIDIA",
    "BC:30:7D": "Vizio", "E4:F0:42": "Vizio",
    "00:A0:DE": "Yamaha", "E8:EB:1B": "Microchip (IoT)",
}

# (regex on "hostname vendor mdns-services", device type)
_TYPE_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"iphone|galaxy|pixel|android|oneplus|motorola|moto-", re.I), "phone"),
    (re.compile(r"ipad|tablet|kindle|fire-?hd|galaxy-?tab", re.I), "tablet"),
    (re.compile(r"macbook|laptop|thinkpad|xps|surface|chromebook|notebook", re.I), "laptop"),
    (re.compile(r"imac|desktop|-pc\b|windows|mac-?mini|mac-?studio|workstation", re.I), "computer"),
    (re.compile(r"roku|fire-?tv|firestick|aft[a-z]|chromecast|apple-?tv|appletv|shield|tivo|_googlecast|_airplay|vizio|webos|lg-?tv|samsung-?tv|bravia|smart-?tv|tv\b", re.I), "tv/streaming"),
    (re.compile(r"playstation|ps[345]|xbox|nintendo|switch", re.I), "game console"),
    (re.compile(r"echo|alexa|google-?home|nest-?(mini|hub|audio)|homepod|sonos|_spotify-connect", re.I), "smart speaker"),
    (re.compile(r"ring|arlo|wyze|blink|camera|cam\b|doorbell|eufy", re.I), "camera/doorbell"),
    (re.compile(r"printer|brother|epson|canon|laserjet|officejet|_ipp|_printer", re.I), "printer"),
    (re.compile(r"nest|thermostat|ecobee|hue|wemo|kasa|tuya|smart-?plug|espressif|esp[-_]|shelly|meross|switchbot|smartthings|iot|lifx|govee|myq|roomba|irobot", re.I), "iot"),
    (re.compile(r"raspberry|synology|qnap|nas\b|server", re.I), "server"),
    (re.compile(r"at&t|arris|nokia|router|gateway|eero|orbi|deco|mesh", re.I), "network"),
]


class OuiDatabase:
    def __init__(self, data_dir: Path | None = None) -> None:
        self._table: dict[str, str] = dict(_BUILTIN_OUI)
        if data_dir is not None:
            self._load_ieee(data_dir / "oui.csv")

    def _load_ieee(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    assignment = (row.get("Assignment") or "").strip().upper()
                    org = (row.get("Organization Name") or "").strip()
                    if len(assignment) == 6 and org:
                        key = ":".join(assignment[i:i + 2] for i in range(0, 6, 2))
                        self._table.setdefault(key, org)
            log.info("loaded %d OUI entries", len(self._table))
        except (OSError, csv.Error) as exc:
            log.warning("could not read OUI file %s: %s", path, exc)

    def vendor(self, mac: str) -> str | None:
        mac = normalize_mac(mac) or ""
        if not mac:
            return None
        first_octet = int(mac[:2], 16)
        if first_octet & 0x02:
            # Locally administered = randomised "private Wi-Fi address"
            # (iOS 14+, Android 10+, Windows). Vendor is unknowable.
            return "Randomized MAC"
        return self._table.get(mac[:8])


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    parts = re.split(r"[:-]", mac.strip())
    if len(parts) == 6 and all(1 <= len(p) <= 2 for p in parts):
        # macOS `arp -an` drops leading zeros: 0:17:88:a:2b:c
        hexdigits = "".join(p.zfill(2) for p in parts)
    else:
        hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexdigits) != 12 or not re.fullmatch(r"[0-9a-fA-F]{12}", hexdigits):
        return None
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)).upper()


def guess_device_type(hostname: str | None, vendor: str | None, services: str | None = None) -> str:
    haystack = " ".join(filter(None, [hostname, vendor, services]))
    if not haystack:
        return "unknown"
    for pattern, device_type in _TYPE_RULES:
        if pattern.search(haystack):
            return device_type
    if vendor and "apple" in vendor.lower():
        return "apple device"
    if vendor and "randomized" in vendor.lower():
        return "phone/tablet/laptop"
    return "unknown"
