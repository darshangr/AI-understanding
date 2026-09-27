"""Import DNS query logs from an existing Pi-hole or AdGuard Home install."""

from __future__ import annotations

import logging
import time
from datetime import datetime

import httpx

from ..config import secret
from .base import PollingCollector

log = logging.getLogger(__name__)

PIHOLE_BLOCKED = {"GRAVITY", "REGEX", "DENYLIST", "BLACKLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL",
                  "EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "SPECIAL_DOMAIN"}
# Pi-hole v5 numeric status codes that mean "blocked".
PIHOLE_V5_BLOCKED = {"1", "4", "5", "6", "7", "8", "9", "10", "11", "15", "16"}


class PiholeCollector(PollingCollector):
    """Supports the Pi-hole v6 REST API, falling back to the v5 ``api.php``.

    Password (v6) or API token (v5) comes from ``NETMON_PIHOLE_PASSWORD``.
    """

    name_prefix = "pihole"

    def __init__(self, monitor, cfg):
        super().__init__(monitor, cfg, cfg.get("interval_seconds", 60))
        # SECURITY-REVIEW: URL comes from the local config file only.
        self.client = httpx.Client(base_url=str(cfg.get("base_url")).rstrip("/"), timeout=20)
        self.password = secret("NETMON_PIHOLE_PASSWORD")
        self.sid: str | None = None
        self.cursor = float(monitor.store.get_meta("pihole_cursor") or time.time() - 3600)

    def _auth_v6(self) -> None:
        resp = self.client.post("/api/auth", json={"password": self.password or ""})
        resp.raise_for_status()
        self.sid = (resp.json().get("session") or {}).get("sid")

    def _poll_v6(self, until: float) -> int:
        if self.sid is None and self.password:
            self._auth_v6()
        headers = {"X-FTL-SID": self.sid} if self.sid else {}
        resp = self.client.get("/api/queries", params={"from": int(self.cursor), "until": int(until),
                                                       "length": 10000}, headers=headers)
        if resp.status_code == 401 and self.password:
            self._auth_v6()
            resp = self.client.get("/api/queries", params={"from": int(self.cursor), "until": int(until),
                                                           "length": 10000}, headers={"X-FTL-SID": self.sid or ""})
        resp.raise_for_status()
        count = 0
        for q in resp.json().get("queries", []):
            ts = float(q.get("time", 0))
            if ts <= self.cursor:
                continue
            status = str(q.get("status") or "")
            reply = (q.get("reply") or {}).get("type")
            rcode = "BLOCKED" if status in PIHOLE_BLOCKED else ("NXDOMAIN" if reply == "NXDOMAIN" else "NOERROR")
            client = (q.get("client") or {}).get("ip")
            if client and q.get("domain"):
                self.monitor.on_dns(client, q["domain"], q.get("type"), rcode, source="pihole", ts=ts)
                count += 1
        return count

    def _poll_v5(self, until: float) -> int:
        params = {"getAllQueries": "", "from": int(self.cursor), "until": int(until)}
        if self.password:
            params["auth"] = self.password
        resp = self.client.get("/admin/api.php", params=params)
        resp.raise_for_status()
        count = 0
        for row in resp.json().get("data", []):
            if len(row) < 5:
                continue
            ts = float(row[0])
            if ts <= self.cursor:
                continue
            rcode = "BLOCKED" if str(row[4]) in PIHOLE_V5_BLOCKED else "NOERROR"
            self.monitor.on_dns(str(row[3]), str(row[2]), str(row[1]), rcode, source="pihole", ts=ts)
            count += 1
        return count

    def poll(self) -> str:
        until = time.time()
        try:
            count = self._poll_v6(until)
        except (httpx.HTTPStatusError, ValueError):
            count = self._poll_v5(until)
        self.cursor = until
        self.monitor.store.set_meta("pihole_cursor", str(self.cursor))
        return f"imported {count} queries"


class AdGuardCollector(PollingCollector):
    """AdGuard Home ``/control/querylog``. Credentials from
    ``NETMON_ADGUARD_USER`` / ``NETMON_ADGUARD_PASSWORD``."""

    name_prefix = "adguard"

    def __init__(self, monitor, cfg):
        super().__init__(monitor, cfg, cfg.get("interval_seconds", 60))
        user, password = secret("NETMON_ADGUARD_USER"), secret("NETMON_ADGUARD_PASSWORD")
        auth = httpx.BasicAuth(user, password) if user and password else None
        # SECURITY-REVIEW: URL comes from the local config file only.
        self.client = httpx.Client(base_url=str(cfg.get("base_url")).rstrip("/"), timeout=20, auth=auth)
        self.cursor = float(monitor.store.get_meta("adguard_cursor") or time.time() - 3600)

    def poll(self) -> str:
        newest = self.cursor
        older_than = ""
        count = 0
        for _page in range(20):
            params = {"limit": 500}
            if older_than:
                params["older_than"] = older_than
            resp = self.client.get("/control/querylog", params=params)
            resp.raise_for_status()
            body = resp.json()
            entries = body.get("data") or []
            reached_cursor = False
            for entry in entries:
                ts = datetime.fromisoformat(str(entry.get("time")).replace("Z", "+00:00")).timestamp()
                if ts <= self.cursor:
                    reached_cursor = True
                    break
                newest = max(newest, ts)
                question = entry.get("question") or {}
                reason = str(entry.get("reason") or "")
                rcode = "BLOCKED" if reason.startswith("Filtered") and "White" not in reason else entry.get("status")
                answers = [a.get("value") for a in entry.get("answer") or [] if a.get("type") in ("A", "AAAA")]
                if entry.get("client") and question.get("name"):
                    self.monitor.on_dns(entry["client"], question["name"], question.get("type"), rcode,
                                        answers=[a for a in answers if a], source="adguard", ts=ts)
                    count += 1
            older_than = body.get("oldest") or ""
            if reached_cursor or not entries or not older_than:
                break
        self.cursor = newest
        self.monitor.store.set_meta("adguard_cursor", str(self.cursor))
        return f"imported {count} queries"
