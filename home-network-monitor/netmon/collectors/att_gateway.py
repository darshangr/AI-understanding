"""AT&T residential gateway (BGW320 / BGW210 / Pace 5268AC / NVG599) scraper.

The gateway's web UI at http://192.168.1.254 exposes, without logging in:

* ``/cgi-bin/devices.ha`` - every device the gateway has leased an address to,
  with MAC, IP, hostname, on/off status and Wi-Fi band.
* ``/cgi-bin/broadbandstatistics.ha`` - WAN interface counters. Where the
  firmware reports byte counters, their deltas give whole-home upload and
  download per day.

Firmware versions differ in layout, so the parser works on generic
``<th>label</th><td>value</td>`` rows and matches labels with regexes.
"""

from __future__ import annotations

import logging
import re
import time
from html.parser import HTMLParser

import httpx

from .base import PollingCollector

log = logging.getLogger(__name__)

TX_LABEL = re.compile(r"(transmit|tx|sent|upstream).*(bytes|octets)|(bytes|octets).*(sent|transmit|tx)", re.I)
RX_LABEL = re.compile(r"(receive|rx|received|downstream).*(bytes|octets)|(bytes|octets).*(received|receive|rx)", re.I)
_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_INT_RE = re.compile(r"^\s*(\d[\d,]*)\s*$")


class _RowParser(HTMLParser):
    """Collects table rows as lists of cell texts (th and td alike)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[str]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" | ")

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._row is not None and self._cell is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip(" |"))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if any(self._row):
                self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def table_rows(html: str) -> list[list[str]]:
    parser = _RowParser()
    parser.feed(html)
    parser.close()
    return parser.rows


def parse_devices(html: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for row in table_rows(html):
        if len(row) < 2:
            continue
        key, value = row[0].strip().lower(), row[1].strip()
        if key.startswith("mac address"):
            if current and current.get("mac"):
                devices.append(current)
            match = _MAC_RE.search(value)
            current = {"mac": match.group(0) if match else ""}
        elif current is None:
            continue
        elif key.startswith("ipv4 address"):
            ip_match = _IP_RE.search(value)
            if ip_match:
                current["ip"] = ip_match.group(1)
            if "/" in value:
                name = value.split("/", 1)[1].strip()
                if name and name.lower() not in ("unknown", "--"):
                    current["hostname"] = name
        elif key.startswith("name") and "hostname" not in current and value:
            current["hostname"] = value
        elif key.startswith("status"):
            current["status"] = value.lower()
        elif key.startswith("last activity"):
            current["last_activity"] = value
        elif key.startswith("connection type"):
            current["connection"] = value
    if current and current.get("mac"):
        devices.append(current)
    return devices


def parse_wan_counters(html: str) -> tuple[int, int] | None:
    tx = rx = None
    for row in table_rows(html):
        if len(row) < 2:
            continue
        label = row[0]
        numbers = [int(m.group(1).replace(",", "")) for cell in row[1:] if (m := _INT_RE.match(cell))]
        if not numbers:
            continue
        if tx is None and TX_LABEL.search(label):
            tx = numbers[0]
        elif rx is None and RX_LABEL.search(label):
            rx = numbers[0]
    if tx is None or rx is None:
        return None
    return tx, rx


def _parse_last_activity(text: str | None) -> float | None:
    if not text:
        return None
    for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return time.mktime(time.strptime(re.sub(r"\s+", " ", text.strip()), fmt))
        except ValueError:
            continue
    return None


def _connection_tag(connection: str | None) -> str | None:
    if not connection:
        return None
    lower = connection.lower()
    if "wi-fi" in lower or "wireless" in lower or "wifi" in lower:
        band = "5ghz" if "5" in lower and "ghz" in lower else ("2.4ghz" if "2.4" in lower else "")
        return f"conn:wifi{('-' + band) if band else ''}"
    if "ethernet" in lower or "lan" in lower:
        return "conn:ethernet"
    return None


class AttGatewayCollector(PollingCollector):
    name_prefix = "att_gateway"

    def __init__(self, monitor, cfg):
        super().__init__(monitor, cfg, cfg.get("interval_seconds", 300))
        base = str(cfg.get("base_url", "http://192.168.1.254")).rstrip("/")
        # SECURITY-REVIEW: the gateway URL comes from the local config file only.
        self.client = httpx.Client(base_url=base, timeout=15, headers={"User-Agent": "netmon/0.1"})
        self.devices_path = cfg.get("devices_path", "/cgi-bin/devices.ha")
        self.broadband_path = cfg.get("broadband_path", "/cgi-bin/broadbandstatistics.ha")
        self._warned_counters = False

    def poll(self) -> str:
        now = time.time()
        resp = self.client.get(self.devices_path)
        resp.raise_for_status()
        devices = parse_devices(resp.text)
        online = 0
        for dev in devices:
            is_on = dev.get("status", "on") in ("on", "online", "active", "connected")
            online += is_on
            ts = now if is_on else (_parse_last_activity(dev.get("last_activity")) or now - 86400)
            self.monitor.on_device(
                dev["mac"], ip=dev.get("ip"), hostname=dev.get("hostname"),
                source="att_gateway", services=_connection_tag(dev.get("connection")), ts=ts,
            )

        counters_msg = "no WAN byte counters"
        try:
            bb = self.client.get(self.broadband_path)
            bb.raise_for_status()
            counters = parse_wan_counters(bb.text)
            if counters:
                self.monitor.on_wan_counters(*counters, ts=now)
                counters_msg = "WAN counters ok"
            elif not self._warned_counters:
                self._warned_counters = True
                log.warning("gateway broadband page has no recognisable byte counters; "
                            "whole-home totals will come from sniffer/netflow instead")
        except httpx.HTTPError as exc:
            counters_msg = f"broadband page error: {type(exc).__name__}"
        return f"{len(devices)} devices ({online} online); {counters_msg}"
