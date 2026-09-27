"""Suspicious-activity detection.

Real-time checks run on each DNS query and traffic flow; baseline checks
(bandwidth spikes) run periodically. Alerts are de-duplicated by key with a
cooldown so a chatty device does not flood the dashboard.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import defaultdict
from typing import Any

from .db import Store
from .domains import base_domain, dga_score, is_local, tld
from .feeds import ThreatFeeds

log = logging.getLogger(__name__)


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast


class AnomalyEngine:
    def __init__(self, store: Store, cfg: dict[str, Any], feeds: ThreatFeeds | None = None) -> None:
        self.store = store
        self.cfg = cfg
        self.feeds = feeds
        self.cooldown = int(cfg.get("alert_cooldown_hours", 24) * 3600)
        self.suspicious_tlds = {t.lower().lstrip(".") for t in cfg.get("suspicious_tlds", [])}
        self.suspicious_ports = {int(p) for p in cfg.get("suspicious_ports", [])}
        self.allowlist = {d.lower().strip(".") for d in cfg.get("allowlist_domains", [])}
        self.trusted_resolvers = set(cfg.get("trusted_resolvers", []))
        self._lock = threading.Lock()
        self._recent: dict[str, float] = {}
        self._hour = 0
        self._nxdomain: dict[str, int] = defaultdict(int)
        self._subdomains: dict[tuple[str, str], set[str]] = defaultdict(set)

    # -------------------------------------------------------------- helpers
    def in_learning_period(self, now: float | None = None) -> bool:
        installed = int(self.store.get_meta("installed_at") or 0)
        hours = float(self.cfg.get("learning_period_hours", 48))
        return (now or time.time()) - installed < hours * 3600

    def _allowlisted(self, domain: str) -> bool:
        labels = domain.split(".")
        return any(".".join(labels[i:]) in self.allowlist for i in range(len(labels)))

    def _alert(self, severity: str, category: str, title: str, detail: str, key: str,
               device: str | None, ts: float | None = None) -> bool:
        now = time.time()
        with self._lock:
            last = self._recent.get(key)
            if last and now - last < self.cooldown:
                return False
            self._recent[key] = now
            if len(self._recent) > 50000:
                cutoff = now - self.cooldown
                self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        created = self.store.add_alert(severity, category, title, detail, key, device,
                                       cooldown_seconds=self.cooldown, ts=ts)
        if created:
            log.warning("ALERT [%s] %s: %s", severity, category, title)
        return created

    def _label(self, device: str) -> str:
        if device.startswith("ip:"):
            return device[3:]
        info = self.store.get_device(device)
        if not info:
            return device
        if info.get("alias") or info.get("hostname"):
            return info.get("alias") or info.get("hostname")
        vendor = info.get("vendor")
        where = info.get("ip") or device
        return f"{vendor} device {where}" if vendor and "randomized" not in vendor.lower() else f"device {where}"

    def _roll_hour(self, ts: float) -> None:
        hour = int(ts) // 3600
        if hour != self._hour:
            self._hour = hour
            self._nxdomain.clear()
            self._subdomains.clear()

    # --------------------------------------------------------------- events
    def on_new_device(self, mac: str, ip: str | None, hostname: str | None, vendor: str | None) -> None:
        learning = self.in_learning_period()
        self._alert(
            "info" if learning else "medium",
            "new_device",
            f"New device joined: {hostname or ip or mac}" + (f" · {vendor}" if vendor else ""),
            f"MAC {mac}, IP {ip or '?'}, vendor {vendor or 'unknown'}"
            + (" (seen during initial learning period)" if learning else
               ". If you don't recognise it, check who is on your Wi-Fi and consider changing the password."),
            f"new_device:{mac}",
            mac,
        )

    def check_dns(self, ts: float, device: str, domain: str, rcode: str | None = None) -> None:
        if is_local(domain) or self._allowlisted(domain):
            return
        who = None

        def label() -> str:
            nonlocal who
            if who is None:
                who = self._label(device)
            return who

        if self.feeds:
            feed = self.feeds.match_domain(domain)
            if feed:
                self._alert("high", "threat_feed", f"{label()} contacted known-malicious domain {domain}",
                            f"Domain is listed in threat feed '{feed}'.", f"feed:{device}:{domain}", device, ts)

        suspicious, reason = dga_score(domain, float(self.cfg.get("dga_entropy_threshold", 3.6)))
        if suspicious:
            self._alert("medium", "dga_domain", f"{label()} looked up a random-looking domain {domain}",
                        f"Possible malware (domain generation algorithm): {reason}",
                        f"dga:{device}:{base_domain(domain)}", device, ts)

        if tld(domain) in self.suspicious_tlds:
            self._alert("low", "suspicious_tld", f"{label()} contacted {domain}",
                        f"The .{tld(domain)} TLD is frequently abused for phishing and malware.",
                        f"tld:{device}:{base_domain(domain)}", device, ts)

        longest = max(len(part) for part in domain.split("."))
        if longest > 50 or len(domain) > 180:
            self._alert("medium", "dns_tunneling", f"{label()} sent an unusually long DNS name",
                        f"{domain[:120]}... ({len(domain)} chars). Long encoded labels can indicate DNS tunneling.",
                        f"longname:{device}:{base_domain(domain)}", device, ts)

        with self._lock:
            self._roll_hour(ts)
            nx_count = 0
            if rcode == "NXDOMAIN":
                self._nxdomain[device] += 1
                nx_count = self._nxdomain[device]
            base = base_domain(domain)
            subs = self._subdomains[(device, base)]
            if len(subs) <= int(self.cfg.get("unique_subdomains_per_hour_threshold", 150)):
                subs.add(domain)
            sub_count = len(subs)

        nx_threshold = int(self.cfg.get("nxdomain_per_hour_threshold", 60))
        if nx_count == nx_threshold:
            self._alert("medium", "nxdomain_burst", f"{label()} has many failed DNS lookups",
                        f"{nx_count} NXDOMAIN responses this hour. Malware cycling through generated "
                        "domains often looks like this.", f"nx:{device}", device, ts)
        sub_threshold = int(self.cfg.get("unique_subdomains_per_hour_threshold", 150))
        if sub_count == sub_threshold:
            self._alert("medium", "dns_tunneling", f"{label()} queried {sub_count}+ unique names under {base}",
                        "High subdomain churn under one domain can indicate DNS tunneling or data exfiltration "
                        "(some CDNs/ad networks also do this; allowlist the domain if it's expected).",
                        f"subs:{device}:{base}", device, ts)

    def check_flow(self, ts: float, device: str, remote_ip: str, remote_port: int, proto: str) -> None:
        if _is_private(remote_ip):
            return
        remote_host = self.store.domain_for_ip(remote_ip)
        if remote_host and self._allowlisted(remote_host):
            return
        target = f"{remote_host or remote_ip}:{remote_port}/{proto}"
        if self.feeds:
            feed = self.feeds.match_ip(remote_ip)
            if feed:
                self._alert("high", "threat_feed", f"{self._label(device)} connected to known-malicious IP {remote_ip}",
                            f"{target} is listed in threat feed '{feed}' (botnet C2 / malware infrastructure).",
                            f"feedip:{device}:{remote_ip}", device, ts)
        if remote_port in self.suspicious_ports:
            self._alert("medium", "suspicious_port", f"{self._label(device)} connected to {target}",
                        f"Port {remote_port} is commonly used by remote-access tools, IRC botnets, Telnet "
                        "brute-forcing or Tor.", f"port:{device}:{remote_ip}:{remote_port}", device, ts)
        if remote_port in (53, 853) and remote_ip not in self.trusted_resolvers:
            self._alert("low", "dns_bypass", f"{self._label(device)} is using its own DNS server {remote_ip}",
                        f"Traffic to {target} bypasses your monitored DNS, so its domains won't appear here.",
                        f"dnsbypass:{device}:{remote_ip}", device, ts)

    # ------------------------------------------------------------- periodic
    def run_periodic(self, now: float | None = None) -> None:
        now = now or time.time()
        if self.in_learning_period(now):
            return
        today = self.store.day_of(now)
        prior = self.store.days_back(8, today)[:-1]
        multiplier = float(self.cfg.get("traffic_spike_multiplier", 3.0))
        min_bytes = int(self.cfg.get("traffic_spike_min_bytes", 500 * 1024 * 1024))

        placeholders = ",".join("?" * len(prior))
        baselines = {
            r["device"]: r for r in self.store.query(
                f"SELECT device, AVG(bytes_up) AS avg_up, AVG(bytes_down) AS avg_down, COUNT(*) AS n"
                f" FROM traffic_daily WHERE day IN ({placeholders}) GROUP BY device",
                prior,
            )
        }
        for row in self.store.query("SELECT device, bytes_up, bytes_down FROM traffic_daily WHERE day = ?", (today,)):
            base = baselines.get(row["device"])
            if not base or base["n"] < 3:
                continue
            for direction, value, avg in (("upload", row["bytes_up"], base["avg_up"]),
                                          ("download", row["bytes_down"], base["avg_down"])):
                if value >= min_bytes and value > multiplier * max(avg or 0, 1):
                    severity = "high" if direction == "upload" else "low"
                    self._alert(severity, "traffic_spike",
                                f"{self._label(row['device'])} {direction} is {value / max(avg, 1):.0f}x its normal",
                                f"{_fmt_bytes(value)} {direction}ed today vs a 7-day average of {_fmt_bytes(avg)}."
                                + (" Large unexpected uploads can mean data exfiltration or a compromised "
                                   "camera/IoT device." if direction == "upload" else ""),
                                f"spike:{direction}:{row['device']}:{today}", row["device"])

        wan_prior = self.store.query(
            f"SELECT AVG(bytes_up) AS avg_up, COUNT(*) AS n FROM wan_daily WHERE day IN ({placeholders})", prior
        )
        wan_today = self.store.query_one("SELECT bytes_up FROM wan_daily WHERE day = ?", (today,))
        if wan_prior and wan_today and (wan_prior[0]["n"] or 0) >= 3:
            avg = wan_prior[0]["avg_up"] or 0
            if wan_today["bytes_up"] >= min_bytes and wan_today["bytes_up"] > multiplier * max(avg, 1):
                self._alert("medium", "traffic_spike", "Whole-home upload is unusually high today",
                            f"{_fmt_bytes(wan_today['bytes_up'])} uploaded vs 7-day average {_fmt_bytes(avg)}.",
                            f"spike:wan:{today}", None)
