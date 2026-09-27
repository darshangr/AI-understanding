"""Passive packet capture (requires root / CAP_NET_RAW and scapy).

What it can see depends on where the monitor sits:

* **Any LAN port**: broadcast/multicast only - DHCP hostnames and mDNS
  service announcements. Useful for naming devices.
* **Switch mirror (SPAN) port, or the monitor is the router**: all traffic -
  per-device upload/download, remote hosts, DNS answers and TLS SNI names.
"""

from __future__ import annotations

import logging
import threading
import time

from .. import dnsparse
from ..tls import extract_sni
from .discovery import read_proc_arp

log = logging.getLogger(__name__)


class Sniffer(threading.Thread):
    name_prefix = "sniffer"

    def __init__(self, monitor, cfg) -> None:
        super().__init__(name="sniffer", daemon=True)
        self.monitor = monitor
        self.iface = cfg.get("interface") or monitor.cfg.get_path("lan.interface")
        self.bpf = cfg.get("bpf_filter") or ""
        self.gateway_ip = monitor.cfg.get_path("lan.gateway_ip")
        self.gateway_mac: str | None = None
        self.packets = 0
        self._gw_checked = 0.0
        self.proxy_enabled = bool(monitor.cfg.get_path("collectors.dns_proxy.enabled"))
        self.own_ips: set[str] = set()

    def _refresh_gateway_mac(self) -> None:
        now = time.time()
        if now - self._gw_checked < 300:
            return
        self._gw_checked = now
        for ip, mac in read_proc_arp():
            if ip == self.gateway_ip:
                self.gateway_mac = mac.lower()

    def run(self) -> None:
        try:
            from scapy.all import conf, get_if_addr, sniff  # type: ignore
        except ImportError:
            self.monitor.set_status(self.name, False, "scapy not installed")
            return
        try:
            self.own_ips = {get_if_addr(self.iface or conf.iface)} - {"0.0.0.0"}
        except (OSError, ValueError):
            self.own_ips = set()
        self.monitor.set_status(self.name, True, f"capturing on {self.iface or 'default interface'}")
        while not self.monitor.stop_event.is_set():
            try:
                sniff(iface=self.iface, filter=self.bpf or None, prn=self._handle, store=False, timeout=30)
                self.monitor.set_status(self.name, True, f"{self.packets} packets seen")
            except PermissionError:
                self.monitor.set_status(self.name, False, "needs root / CAP_NET_RAW")
                log.error("packet capture needs root or CAP_NET_RAW")
                return
            except Exception as exc:
                log.exception("sniffer error")
                self.monitor.set_status(self.name, False, type(exc).__name__)
                self.monitor.stop_event.wait(10)

    # --------------------------------------------------------------- packets
    def _handle(self, pkt) -> None:
        from scapy.layers.dhcp import DHCP, BOOTP  # type: ignore
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
        from scapy.layers.inet6 import IPv6  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore

        self.packets += 1
        try:
            if DHCP in pkt:
                self._handle_dhcp(pkt, BOOTP, DHCP)
                return
            if Ether not in pkt:
                return
            eth = pkt[Ether]
            if IP in pkt:
                ip = pkt[IP]
                src, dst, length = ip.src, ip.dst, int(ip.len or len(ip))
            elif IPv6 in pkt:
                ip = pkt[IPv6]
                src, dst, length = ip.src, ip.dst, int(ip.plen or 0) + 40
            else:
                return

            if self.monitor.is_lan(src):
                self.monitor.on_sighting(eth.src, src, "sniffer")

            sport = dport = 0
            proto = "other"
            if TCP in pkt:
                sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, "tcp"
                payload = bytes(pkt[TCP].payload)
                if dport == 443 and payload[:1] == b"\x16":
                    sni = extract_sni(payload)
                    if sni:
                        self.monitor.on_dns(src, sni, "SNI", "NOERROR", source="sni")
            elif UDP in pkt:
                sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, "udp"
                if sport == 53 or sport == 5353 or dport == 5353:
                    self._handle_dns(pkt[UDP], src, dst, sport, eth.src)

            flow_start = proto == "tcp" and (pkt[TCP].flags & 0x12) == 0x02
            if IPv6 in pkt and IP not in pkt:
                self._handle_v6_flow(eth, src, dst, sport, dport, proto, length, flow_start)
            else:
                self.monitor.on_flow(src, dst, sport, dport, proto, length, flows=int(flow_start))
        except Exception:
            log.debug("packet handling error", exc_info=True)

    def _handle_v6_flow(self, eth, src, dst, sport, dport, proto, length, flow_start) -> None:
        # IPv6 addresses aren't in the LAN CIDR, so use MACs to find direction:
        # frames from the gateway are downloads, frames to it are uploads.
        self._refresh_gateway_mac()
        gw = self.gateway_mac
        if not gw:
            return
        src_mac, dst_mac = eth.src.lower(), eth.dst.lower()
        store = self.monitor.store
        if dst_mac == gw and src_mac != gw:
            store.learn_ip(src, src_mac.upper())
            self.monitor.on_flow_directed(src, dst, dport, proto, length, 0, int(flow_start))
        elif src_mac == gw and dst_mac != gw:
            store.learn_ip(dst, dst_mac.upper())
            self.monitor.on_flow_directed(dst, src, sport, proto, 0, length, 0)

    def _handle_dns(self, udp, src, dst, sport, src_mac) -> None:
        try:
            msg = dnsparse.parse(bytes(udp.payload))
        except dnsparse.DnsParseError:
            return
        if sport == 53 and msg.is_response:
            if self.proxy_enabled and (src in self.own_ips or dst in self.own_ips):
                return  # the DNS proxy already logs these with the real client
            self.monitor.on_dns(dst, msg.qname, msg.qtype, msg.rcode, msg.answers, source="sniffer")
        elif msg.qname.endswith("._tcp.local") or msg.qname.endswith("._udp.local"):
            service = msg.qname.rsplit(".", 3)[-3] if msg.qname.count(".") >= 3 else msg.qname
            if msg.is_response and self.monitor.is_lan(src):
                self.monitor.on_device(src_mac, ip=src, source="mdns", services=service)

    def _handle_dhcp(self, pkt, BOOTP, DHCP) -> None:
        options = {}
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                options[opt[0]] = opt[1]
        msg_type = options.get("message-type")
        if msg_type not in (1, 3, 8):  # discover, request, inform
            return
        chaddr = bytes(pkt[BOOTP].chaddr)[:6]
        mac = ":".join(f"{b:02x}" for b in chaddr)
        hostname = options.get("hostname")
        if isinstance(hostname, bytes):
            hostname = hostname.decode("utf-8", errors="replace")
        vendor_class = options.get("vendor_class_id")
        if isinstance(vendor_class, bytes):
            vendor_class = vendor_class.decode("utf-8", errors="replace")
        ip = options.get("requested_addr") or (pkt[BOOTP].ciaddr if pkt[BOOTP].ciaddr != "0.0.0.0" else None)
        services = f"dhcp:{vendor_class[:40]}" if vendor_class else None
        self.monitor.on_device(mac, ip=ip, hostname=hostname, source="dhcp", services=services)
