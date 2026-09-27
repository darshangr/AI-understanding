"""Configuration loading.

Values come from a YAML file (see ``config.example.yaml``) merged over the
defaults below. Secrets (gateway access code, dashboard password, Pi-hole /
AdGuard credentials) are only ever read from environment variables.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "data_dir": "./data",
    "timezone": None,  # None = system local time; used for "day" buckets
    "lan": {
        "cidr": "192.168.1.0/24",
        "interface": None,  # None = scapy default interface
        "gateway_ip": "192.168.1.254",
    },
    "web": {
        "host": "0.0.0.0",
        "port": 8080,
        # When false, NETMON_DASHBOARD_PASSWORD must be set or the server
        # refuses to start on a non-loopback address.
        "allow_unauthenticated": False,
    },
    "collectors": {
        "discovery": {"enabled": True, "interval_seconds": 120, "use_arp_scan": True, "dhcp_leases_file": None},
        "att_gateway": {
            "enabled": True,
            "base_url": "http://192.168.1.254",
            "interval_seconds": 300,
            "devices_path": "/cgi-bin/devices.ha",
            "broadband_path": "/cgi-bin/broadbandstatistics.ha",
        },
        "dns_proxy": {
            "enabled": False,
            "listen_host": "0.0.0.0",
            "listen_port": 53,
            "upstream": ["1.1.1.1", "9.9.9.9"],
            "timeout_seconds": 3.0,
            "disable_doh_canaries": True,
        },
        "pihole": {"enabled": False, "base_url": "http://127.0.0.1:8081", "interval_seconds": 60},
        "adguard": {"enabled": False, "base_url": "http://127.0.0.1:3000", "interval_seconds": 60},
        "sniffer": {"enabled": False, "interface": None, "bpf_filter": ""},
        "netflow": {"enabled": False, "listen_host": "0.0.0.0", "listen_port": 2055},
    },
    "anomaly": {
        "learning_period_hours": 48,
        "traffic_spike_multiplier": 3.0,
        "traffic_spike_min_bytes": 500 * 1024 * 1024,
        "nxdomain_per_hour_threshold": 60,
        "unique_subdomains_per_hour_threshold": 150,
        "dga_entropy_threshold": 3.6,
        "suspicious_tlds": [
            "zip", "mov", "top", "xyz", "gq", "tk", "ml", "cf", "ga", "work",
            "click", "country", "kim", "loan", "men", "party", "racing", "stream",
            "download", "review", "cam", "rest", "icu",
        ],
        "suspicious_ports": [23, 2323, 4444, 5555, 6667, 6697, 1080, 9001, 9030, 31337, 3389, 5900],
        "allowlist_domains": [],
        "trusted_resolvers": [],
        "alert_cooldown_hours": 24,
    },
    "feeds": {
        "enabled": True,
        "refresh_hours": 24,
        "sources": [
            {"name": "urlhaus", "url": "https://urlhaus.abuse.ch/downloads/hostfile/", "format": "hosts"},
            {"name": "feodo-ips", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "format": "ips"},
        ],
        "local_files": [],
    },
    "retention": {
        "raw_dns_days": 30,
        "hourly_traffic_days": 90,
        "wan_samples_days": 90,
        "host_traffic_days": 180,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config(dict):
    """Dict with attribute-free, path-style access: ``cfg.get_path("web.port")``."""

    def get_path(self, dotted: str, default: Any = None) -> Any:
        node: Any = self
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def data_dir(self) -> Path:
        path = Path(self["data_dir"]).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netmon.sqlite3"


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    raw: dict[str, Any] = {}
    candidate = path or os.getenv("NETMON_CONFIG")
    if candidate:
        with open(candidate, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ValueError("config file must contain a YAML mapping")
    cfg = Config(_deep_merge(DEFAULTS, raw))
    if os.getenv("NETMON_DATA_DIR"):
        cfg["data_dir"] = os.environ["NETMON_DATA_DIR"]
    return cfg


def secret(name: str) -> str | None:
    """Read a secret from the environment; empty strings count as unset."""
    value = os.getenv(name)
    return value if value else None
