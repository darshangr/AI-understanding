"""The Monitor: glue between collectors, storage and anomaly detection."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Any

from .anomaly import AnomalyEngine
from .config import Config, detect_lan_cidr
from .db import Store
from .devices import OuiDatabase, guess_device_type, normalize_mac
from .domains import is_local, normalize
from .feeds import ThreatFeeds

log = logging.getLogger(__name__)

FLUSH_SECONDS = 5
PERIODIC_SECONDS = 300
PRUNE_SECONDS = 6 * 3600


class Monitor:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.store = Store(cfg.db_path, cfg.get("timezone"))
        self.oui = OuiDatabase(cfg.data_dir)
        cidr = cfg.get_path("lan.cidr") or "auto"
        if cidr == "auto":
            cidr = detect_lan_cidr()
            log.info("home network detected as %s (set lan.cidr to override)", cidr)
        self.lan = ipaddress.ip_network(cidr, strict=False)
        feeds_cfg = cfg["feeds"]
        self.feeds: ThreatFeeds | None = None
        if feeds_cfg.get("enabled"):
            self.feeds = ThreatFeeds(cfg.data_dir, feeds_cfg.get("sources", []), feeds_cfg.get("local_files", []))
            self.feeds.load_cached()
        self.anomaly = AnomalyEngine(self.store, cfg["anomaly"], self.feeds)
        self.status: dict[str, dict[str, Any]] = {}
        self.collectors: list[threading.Thread] = []
        self.stop_event = threading.Event()
        self._flow_seen: dict[tuple[str, str, int, str], int] = {}
        self._sighting_seen: dict[str, float] = {}
        self._lock = threading.Lock()

    # --------------------------------------------------------------- helpers
    def is_lan(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.lan
        except ValueError:
            return False

    def set_status(self, name: str, ok: bool, message: str = "") -> None:
        self.status[name] = {"ok": ok, "message": message, "updated": int(time.time())}

    # ---------------------------------------------------------------- events
    def on_device(
        self,
        mac: str,
        ip: str | None = None,
        hostname: str | None = None,
        source: str = "unknown",
        services: str | None = None,
        ts: float | None = None,
    ) -> None:
        mac_n = normalize_mac(mac)
        if not mac_n or mac_n in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or int(mac_n[:2], 16) & 0x01:
            return
        if ip and not self.is_lan(ip):
            ip = None
        ts = ts or time.time()
        hostname = hostname.strip()[:128] if hostname else None
        existing = self.store.get_device(mac_n)
        vendor = self.oui.vendor(mac_n)
        device_type = guess_device_type(
            hostname or (existing or {}).get("hostname"),
            vendor,
            ",".join(filter(None, [services, (existing or {}).get("services")])),
        )
        is_new = self.store.upsert_device(
            mac_n, ts, ip=ip, hostname=hostname, vendor=vendor,
            device_type=device_type, services=services, source=source,
        )
        if is_new:
            self.anomaly.on_new_device(mac_n, ip, hostname, vendor)

    def on_dns(
        self,
        client_ip: str,
        domain: str,
        qtype: str | None = None,
        rcode: str | None = None,
        answers: list[str] | tuple[str, ...] = (),
        source: str = "dns",
        ts: float | None = None,
    ) -> None:
        name = normalize(domain)
        if not name:
            return
        ts = ts or time.time()
        if qtype == "PTR" or name.endswith(".arpa"):
            return
        device = self.store.record_dns(ts, client_ip, name, qtype, rcode, answers, source)
        if not is_local(name):
            self.anomaly.check_dns(ts, device, name, rcode)

    def on_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
        nbytes: int,
        flows: int = 0,
        ts: float | None = None,
    ) -> None:
        src_lan, dst_lan = self.is_lan(src_ip), self.is_lan(dst_ip)
        if src_lan == dst_lan:
            return  # LAN-to-LAN or transit traffic: not internet usage
        if src_lan:
            self.on_flow_directed(src_ip, dst_ip, dst_port, proto, nbytes, 0, flows, ts)
        else:
            self.on_flow_directed(dst_ip, src_ip, src_port, proto, 0, nbytes, flows, ts)

    def on_flow_directed(
        self,
        local_ip: str,
        remote_ip: str,
        remote_port: int,
        proto: str,
        up: int,
        down: int,
        flows: int = 0,
        ts: float | None = None,
    ) -> None:
        ts = ts or time.time()
        try:
            remote = ipaddress.ip_address(remote_ip)
        except ValueError:
            return
        if remote.is_multicast or remote.is_link_local or remote.is_loopback:
            return
        device = self.store.add_traffic(ts, local_ip, remote_ip, remote_port, proto, up, down, flows)
        hour = int(ts) // 3600
        key = (device, remote_ip, remote_port, proto)
        with self._lock:
            first_this_hour = self._flow_seen.get(key) != hour
            if first_this_hour:
                self._flow_seen[key] = hour
                if len(self._flow_seen) > 200000:
                    self._flow_seen = {k: v for k, v in self._flow_seen.items() if v == hour}
        if first_this_hour:
            self.anomaly.check_flow(ts, device, remote_ip, remote_port, proto)

    def on_sighting(self, mac: str, ip: str, source: str) -> None:
        """Cheap, throttled 'this MAC is alive at this IP' signal from packet capture."""
        now = time.time()
        key = f"{mac}|{ip}"
        with self._lock:
            if now - self._sighting_seen.get(key, 0) < 60:
                return
            self._sighting_seen[key] = now
        self.on_device(mac, ip=ip, source=source, ts=now)

    def on_wan_counters(self, tx_bytes: int, rx_bytes: int, ts: float | None = None) -> None:
        self.store.record_wan_counters(ts or time.time(), tx_bytes, rx_bytes)

    # ------------------------------------------------------------- lifecycle
    def _maintenance_loop(self) -> None:
        last_periodic = 0.0
        last_prune = 0.0
        last_feeds = 0.0
        while not self.stop_event.wait(FLUSH_SECONDS):
            now = time.time()
            try:
                self.store.flush()
                if now - last_periodic >= PERIODIC_SECONDS:
                    last_periodic = now
                    self.anomaly.run_periodic(now)
                if now - last_prune >= PRUNE_SECONDS:
                    last_prune = now
                    removed = self.store.prune(self.cfg["retention"], now)
                    log.info("retention prune: %s", removed)
                refresh_hours = float(self.cfg.get_path("feeds.refresh_hours", 24))
                if self.feeds and now - last_feeds >= refresh_hours * 3600:
                    last_feeds = now
                    threading.Thread(target=self.feeds.refresh, args=(refresh_hours,), daemon=True).start()
                self.set_status("maintenance", True, "flushing")
            except Exception:  # keep the loop alive; details go to the server log only
                log.exception("maintenance loop error")
                self.set_status("maintenance", False, "error, see server log")

    def start(self) -> None:
        from .collectors import build_collectors

        self.collectors = build_collectors(self)
        for collector in self.collectors:
            collector.start()
        maint = threading.Thread(target=self._maintenance_loop, name="maintenance", daemon=True)
        maint.start()
        log.info("monitor started with collectors: %s", ", ".join(c.name for c in self.collectors) or "none")

    def stop(self) -> None:
        self.stop_event.set()
        for collector in self.collectors:
            stop = getattr(collector, "stop", None)
            if callable(stop):
                stop()
        self.store.close()
