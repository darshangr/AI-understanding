"""Built-in logging DNS forwarder.

Point your devices' DNS at the machine running netmon (see README for how to
do that on an AT&T gateway) and every lookup is attributed to the device that
made it. Queries are relayed byte-for-byte to the configured upstream
resolvers, so behaviour is unchanged for clients.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import struct
import threading
import time

from .. import dnsparse

log = logging.getLogger(__name__)

MAX_UDP = 4096

# Answering NXDOMAIN for these tells Firefox to disable DNS-over-HTTPS and
# Apple devices to disable iCloud Private Relay, both of which would otherwise
# hide lookups from the monitor.
DOH_CANARIES = frozenset({"use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"})


class _Forwarder:
    def __init__(self, upstreams: list[str], timeout: float) -> None:
        self.upstreams = [(host, 53) for host in upstreams]
        self.timeout = timeout

    def udp(self, query: bytes) -> bytes | None:
        for upstream in self.upstreams:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(query, upstream)
                    while True:
                        data, addr = sock.recvfrom(MAX_UDP)
                        if addr[0] == upstream[0] and data[:2] == query[:2]:
                            return data
                except OSError:
                    continue
        return None

    def tcp(self, query: bytes) -> bytes | None:
        for upstream in self.upstreams:
            try:
                with socket.create_connection(upstream, timeout=self.timeout) as sock:
                    sock.sendall(struct.pack("!H", len(query)) + query)
                    header = _recv_exact(sock, 2)
                    if not header:
                        continue
                    return _recv_exact(sock, struct.unpack("!H", header)[0])
            except OSError:
                continue
        return None


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class DnsProxy:
    name = "dns_proxy"

    def __init__(self, monitor, cfg) -> None:
        self.monitor = monitor
        self.host = cfg.get("listen_host", "0.0.0.0")
        self.port = int(cfg.get("listen_port", 53))
        self.forwarder = _Forwarder(list(cfg.get("upstream", ["1.1.1.1"])), float(cfg.get("timeout_seconds", 3)))
        self.block_canaries = bool(cfg.get("disable_doh_canaries", True))
        self._servers: list[socketserver.BaseServer] = []
        self._threads: list[threading.Thread] = []
        self.queries = 0

    def resolve(self, query: bytes, transport: str) -> tuple[bytes | None, bytes | None]:
        """Returns (reply to send, upstream response or None)."""
        if self.block_canaries:
            try:
                if dnsparse.parse(query).qname in DOH_CANARIES:
                    reply = dnsparse.build_nxdomain(query)
                    return reply, reply
            except dnsparse.DnsParseError:
                pass
        response = self.forwarder.udp(query) if transport == "udp" else self.forwarder.tcp(query)
        return (response or dnsparse.build_servfail(query)), response

    def _log(self, client_ip: str, query: bytes, response: bytes | None) -> None:
        self.queries += 1
        try:
            if response:
                msg = dnsparse.parse(response)
                self.monitor.on_dns(client_ip, msg.qname, msg.qtype, msg.rcode,
                                    msg.answers, source="dns_proxy", ts=time.time())
            else:
                msg = dnsparse.parse(query)
                self.monitor.on_dns(client_ip, msg.qname, msg.qtype, "TIMEOUT", source="dns_proxy")
        except dnsparse.DnsParseError:
            log.debug("unparseable DNS packet from %s", client_ip)

    def _make_servers(self) -> None:
        proxy = self

        class UdpHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                reply, response = proxy.resolve(data, "udp")
                if reply:
                    sock.sendto(reply, self.client_address)
                proxy._log(self.client_address[0], data, response)

        class TcpHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(10)
                try:
                    header = _recv_exact(self.request, 2)
                    if not header:
                        return
                    query = _recv_exact(self.request, struct.unpack("!H", header)[0])
                    if not query:
                        return
                    reply, response = proxy.resolve(query, "tcp")
                    if reply:
                        self.request.sendall(struct.pack("!H", len(reply)) + reply)
                    proxy._log(self.client_address[0], query, response)
                except OSError:
                    return

        class UdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
            daemon_threads = True
            allow_reuse_address = True

        class TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._servers = [UdpServer((self.host, self.port), UdpHandler),
                         TcpServer((self.host, self.port), TcpHandler)]

    def start(self) -> None:
        try:
            self._make_servers()
        except OSError as exc:
            log.error("DNS proxy cannot bind %s:%s (%s). Port 53 needs root/CAP_NET_BIND_SERVICE "
                      "and must not be used by systemd-resolved/dnsmasq.", self.host, self.port, exc)
            self.monitor.set_status(self.name, False, f"bind failed: {exc.strerror}")
            return
        for server in self._servers:
            thread = threading.Thread(target=server.serve_forever, name=f"dns-{type(server).__name__}", daemon=True)
            thread.start()
            self._threads.append(thread)
        self.monitor.set_status(self.name, True, f"listening on {self.host}:{self.port}")
        log.info("DNS proxy listening on %s:%s", self.host, self.port)

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()

    # Present a Thread-like surface to Monitor.start()
    def is_alive(self) -> bool:
        return any(t.is_alive() for t in self._threads)
