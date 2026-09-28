"""Threat-intelligence feeds: known-malicious domains and IPs.

Feeds are downloaded from fixed URLs in the config (never user-supplied at
runtime), cached under ``<data_dir>/feeds`` and reloaded into memory.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

import httpx

from .domains import normalize

log = logging.getLogger(__name__)

_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")
MAX_FEED_BYTES = 50 * 1024 * 1024


class ThreatFeeds:
    def __init__(self, data_dir: Path, sources: list[dict[str, Any]], local_files: list[str] | None = None) -> None:
        self.cache_dir = data_dir / "feeds"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.sources = [s for s in sources if _SAFE_NAME.match(str(s.get("name", "")))]
        self.local_files = local_files or []
        self._lock = threading.Lock()
        self.domains: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.loaded_at: float | None = None

    # ---------------------------------------------------------------- lookup
    def match_domain(self, domain: str) -> str | None:
        """Return the feed name if the domain or any parent domain is listed."""
        labels = domain.split(".")
        with self._lock:
            for i in range(len(labels) - 1):
                hit = self.domains.get(".".join(labels[i:]))
                if hit:
                    return hit
        return None

    def match_ip(self, ip: str) -> str | None:
        with self._lock:
            return self.ips.get(ip)

    # --------------------------------------------------------------- loading
    @staticmethod
    def parse(text: str, fmt: str) -> tuple[set[str], set[str]]:
        domains: set[str] = set()
        ips: set[str] = set()
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            token = parts[1] if fmt == "hosts" and len(parts) >= 2 else parts[0]
            if fmt == "ips":
                try:
                    ips.add(str(ipaddress.ip_address(token)))
                except ValueError:
                    continue
            else:
                name = normalize(token)
                if name and name not in ("localhost", "0.0.0.0", "127.0.0.1") and "." in name:
                    domains.add(name)
        return domains, ips

    def load_cached(self) -> None:
        domains: dict[str, str] = {}
        ips: dict[str, str] = {}
        entries = [(s["name"], self.cache_dir / f"{s['name']}.txt", s.get("format", "domains")) for s in self.sources]
        for path_str in self.local_files:
            path = Path(path_str).expanduser()
            fmt = "ips" if "ip" in path.stem.lower() else "domains"
            entries.append((f"local:{path.name}", path, fmt))
        for name, path, fmt in entries:
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                log.warning("cannot read feed %s: %s", path, exc)
                continue
            d, i = self.parse(text, fmt)
            domains.update(dict.fromkeys(d, name))
            ips.update(dict.fromkeys(i, name))
        with self._lock:
            self.domains, self.ips = domains, ips
            self.loaded_at = time.time()
        log.info("threat feeds loaded: %d domains, %d IPs", len(domains), len(ips))

    def refresh(self, max_age_hours: float = 24, force: bool = False) -> None:
        with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "netmon/0.1"}) as client:
            for source in self.sources:
                path = self.cache_dir / f"{source['name']}.txt"
                if not force and path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
                    continue
                url = str(source.get("url", ""))
                if not url.startswith("https://"):
                    log.warning("skipping feed %s: only https URLs are allowed", source["name"])
                    continue
                try:
                    resp = client.get(url)
                    resp.raise_for_status()
                    if len(resp.content) > MAX_FEED_BYTES:
                        log.warning("feed %s too large, skipped", source["name"])
                        continue
                    tmp = path.with_suffix(".tmp")
                    tmp.write_bytes(resp.content)
                    tmp.replace(path)
                    log.info("downloaded feed %s (%d bytes)", source["name"], len(resp.content))
                except httpx.HTTPError as exc:
                    log.warning("feed %s download failed: %s", source["name"], exc)
        self.load_cached()
