from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..service import Monitor


def build_collectors(monitor: "Monitor") -> list[Any]:
    cfg = monitor.cfg["collectors"]
    collectors: list[Any] = []
    if cfg["discovery"].get("enabled"):
        from .discovery import DiscoveryCollector
        collectors.append(DiscoveryCollector(monitor, cfg["discovery"]))
    if cfg["att_gateway"].get("enabled"):
        from .att_gateway import AttGatewayCollector
        collectors.append(AttGatewayCollector(monitor, cfg["att_gateway"]))
    if cfg["dns_proxy"].get("enabled"):
        from .dns_proxy import DnsProxy
        collectors.append(DnsProxy(monitor, cfg["dns_proxy"]))
    if cfg["pihole"].get("enabled"):
        from .dns_logs import PiholeCollector
        collectors.append(PiholeCollector(monitor, cfg["pihole"]))
    if cfg["adguard"].get("enabled"):
        from .dns_logs import AdGuardCollector
        collectors.append(AdGuardCollector(monitor, cfg["adguard"]))
    if cfg["sniffer"].get("enabled"):
        from .sniffer import Sniffer
        collectors.append(Sniffer(monitor, cfg["sniffer"]))
    if cfg["netflow"].get("enabled"):
        from .netflow import NetflowCollector
        collectors.append(NetflowCollector(monitor, cfg["netflow"]))
    return collectors
