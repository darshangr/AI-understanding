"""NetFlow v5 receiver.

If you put your own router behind the AT&T gateway (IP Passthrough mode) -
OpenWrt + softflowd, pfSense/OPNsense + softflowd, etc. - export NetFlow v5
from the router's **LAN** interface to this collector (UDP 2055). Exporting
from the LAN side matters: after NAT every flow looks like it came from the
router itself.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)

HEADER = struct.Struct("!HHIIIIBBH")
RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")
PROTOS = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def parse_v5(data: bytes) -> tuple[float, list[dict]]:
    if len(data) < HEADER.size:
        raise ValueError("short NetFlow packet")
    version, count, sys_uptime, unix_secs, unix_nsecs, *_ = HEADER.unpack_from(data)
    if version != 5:
        raise ValueError(f"unsupported NetFlow version {version}")
    if HEADER.size + count * RECORD.size > len(data):
        raise ValueError("truncated NetFlow packet")
    export_ts = unix_secs + unix_nsecs / 1e9
    records = []
    for i in range(count):
        (src, dst, _nexthop, _in, _out, packets, octets, _first, last, sport, dport,
         _pad1, _flags, proto, _tos, _sas, _das, _smask, _dmask, _pad2) = RECORD.unpack_from(
            data, HEADER.size + i * RECORD.size)
        records.append({
            "src": str(ipaddress.IPv4Address(src)),
            "dst": str(ipaddress.IPv4Address(dst)),
            "sport": sport,
            "dport": dport,
            "proto": PROTOS.get(proto, str(proto)),
            "bytes": octets,
            "packets": packets,
            # 'last' is router uptime (ms) when the flow ended
            "ts": export_ts - max(0, sys_uptime - last) / 1000.0,
        })
    return export_ts, records


class NetflowCollector(threading.Thread):
    name_prefix = "netflow"

    def __init__(self, monitor, cfg) -> None:
        super().__init__(name="netflow", daemon=True)
        self.monitor = monitor
        self.addr = (cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen_port", 2055)))
        self.flows = 0

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(self.addr)
        except OSError as exc:
            self.monitor.set_status(self.name, False, f"bind failed: {exc.strerror}")
            return
        sock.settimeout(2)
        self.monitor.set_status(self.name, True, f"listening on udp {self.addr[0]}:{self.addr[1]}")
        last_status = 0.0
        while not self.monitor.stop_event.is_set():
            try:
                data, _peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                _ts, records = parse_v5(data)
            except ValueError as exc:
                log.debug("dropping NetFlow packet: %s", exc)
                continue
            for r in records:
                self.monitor.on_flow(r["src"], r["dst"], r["sport"], r["dport"], r["proto"], r["bytes"],
                                     flows=1, ts=min(r["ts"], time.time()))
            self.flows += len(records)
            if time.time() - last_status > 30:
                last_status = time.time()
                self.monitor.set_status(self.name, True, f"{self.flows} flows received")
        sock.close()
