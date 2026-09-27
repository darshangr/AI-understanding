"""Active LAN discovery: which devices are connected right now.

Uses a scapy ARP scan when running as root; otherwise nudges every address
with a tiny UDP datagram (which forces the kernel to ARP for it) and reads the
kernel neighbour table. Hostnames come from reverse DNS against the gateway,
which on AT&T gateways returns the DHCP hostname (e.g. ``Pixel-8.attlocal.net``).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

from .base import PollingCollector

log = logging.getLogger(__name__)

_ARP_LINE = re.compile(r"\((?P<ip>[\d.]+)\) at (?P<mac>[0-9a-fA-F:]{11,17})")


def read_proc_arp(path: str = "/proc/net/arp") -> list[tuple[str, str]]:
    entries = []
    try:
        lines = Path(path).read_text().splitlines()[1:]
    except OSError:
        return entries
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[2] != "0x0" and parts[3] != "00:00:00:00:00:00":
            entries.append((parts[0], parts[3]))
    return entries


def read_dnsmasq_leases(path: str) -> list[tuple[str, str, str | None]]:
    """dnsmasq lease lines: ``<expiry> <mac> <ip> <hostname|*> <client-id>``."""
    leases = []
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return leases
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and ":" in parts[1]:
            leases.append((parts[2], parts[1], None if parts[3] == "*" else parts[3]))
    return leases


def read_arp_command() -> list[tuple[str, str]]:
    # SECURITY-REVIEW: fixed argv, no shell, no user input.
    try:
        out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [(m["ip"], m["mac"]) for m in _ARP_LINE.finditer(out)]


class DiscoveryCollector(PollingCollector):
    name_prefix = "discovery"

    def __init__(self, monitor, cfg):
        super().__init__(monitor, cfg, cfg.get("interval_seconds", 120))
        self.network = monitor.lan
        self.gateway_ip = monitor.cfg.get_path("lan.gateway_ip")
        self.interface = monitor.cfg.get_path("lan.interface")
        self._hostname_checked: dict[str, float] = {}
        self._pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="rdns")

    def _arp_scan_scapy(self) -> list[tuple[str, str]] | None:
        if not self.cfg.get("use_arp_scan", True) or os.geteuid() != 0:
            return None
        try:
            from scapy.all import ARP, Ether, srp  # type: ignore
        except ImportError:
            return None
        kwargs = {"timeout": 3, "verbose": False, "retry": 1}
        if self.interface:
            kwargs["iface"] = self.interface
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.network)), **kwargs)
        return [(rcv.psrc, rcv.hwsrc) for _snd, rcv in answered]

    def _nudge_and_read(self) -> list[tuple[str, str]]:
        if self.network.num_addresses <= 1024:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                for host in self.network.hosts():
                    try:
                        sock.sendto(b"", (str(host), 9))  # discard port; only the ARP matters
                    except OSError:
                        pass
            finally:
                sock.close()
            time.sleep(3)
        entries = read_proc_arp() or read_arp_command()
        return [(ip, mac) for ip, mac in entries if ipaddress.ip_address(ip) in self.network]

    def _reverse_dns(self, ip: str) -> str | None:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
        if not name or name == ip:
            return None
        return name.split(".")[0]

    def poll(self) -> str:
        found = self._arp_scan_scapy()
        method = "arp-scan"
        if found is None:
            found = self._nudge_and_read()
            method = "neighbor-table"
        now = time.time()
        need_names = [ip for ip, _ in found if now - self._hostname_checked.get(ip, 0) > 3600]
        names: dict[str, str | None] = {}
        if need_names:
            futures = {self._pool.submit(self._reverse_dns, ip): ip for ip in need_names}
            done, _ = wait(futures, timeout=10)
            for fut in done:
                names[futures[fut]] = fut.result()
                self._hostname_checked[futures[fut]] = now
        lease_names: dict[str, str] = {}
        leases_file = self.cfg.get("dhcp_leases_file")
        if leases_file:
            for ip, mac, hostname in read_dnsmasq_leases(leases_file):
                if hostname:
                    lease_names[mac.lower()] = hostname
        for ip, mac in found:
            hostname = lease_names.get(mac.lower()) or names.get(ip)
            self.monitor.on_device(mac, ip=ip, hostname=hostname, source=method, ts=now)
        return f"{len(found)} devices via {method}"
