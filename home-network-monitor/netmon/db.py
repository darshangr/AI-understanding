"""SQLite storage.

High-volume events (DNS queries, traffic counters) are buffered in memory and
written in batches by :meth:`Store.flush`, which the service calls every few
seconds. All SQL uses bound parameters.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from .domains import base_domain

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac          TEXT PRIMARY KEY,
    ip           TEXT,
    hostname     TEXT,
    vendor       TEXT,
    device_type  TEXT,
    services     TEXT,
    alias        TEXT,
    trusted      INTEGER NOT NULL DEFAULT 0,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    sources      TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS dns_queries (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    client_ip  TEXT NOT NULL,
    device     TEXT NOT NULL,
    domain     TEXT NOT NULL,
    qtype      TEXT,
    rcode      TEXT,
    source     TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS idx_dns_device_ts ON dns_queries(device, ts);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(domain);

CREATE TABLE IF NOT EXISTS domain_stats (
    day          TEXT NOT NULL,
    device       TEXT NOT NULL,
    domain       TEXT NOT NULL,
    base_domain  TEXT NOT NULL,
    queries      INTEGER NOT NULL DEFAULT 0,
    blocked      INTEGER NOT NULL DEFAULT 0,
    first_ts     INTEGER NOT NULL,
    last_ts      INTEGER NOT NULL,
    PRIMARY KEY (day, device, domain)
);
CREATE INDEX IF NOT EXISTS idx_domain_stats_domain ON domain_stats(domain);
CREATE INDEX IF NOT EXISTS idx_domain_stats_base ON domain_stats(day, base_domain);

CREATE TABLE IF NOT EXISTS domains (
    domain         TEXT PRIMARY KEY,
    base_domain    TEXT NOT NULL,
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    total_queries  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ip_domain (
    ip         TEXT PRIMARY KEY,
    domain     TEXT NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_hourly (
    hour_ts     INTEGER NOT NULL,
    device      TEXT NOT NULL,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour_ts, device)
);

CREATE TABLE IF NOT EXISTS traffic_daily (
    day         TEXT NOT NULL,
    device      TEXT NOT NULL,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, device)
);

CREATE TABLE IF NOT EXISTS host_traffic (
    day          TEXT NOT NULL,
    device       TEXT NOT NULL,
    remote_ip    TEXT NOT NULL,
    remote_port  INTEGER NOT NULL,
    proto        TEXT NOT NULL,
    remote_host  TEXT,
    bytes_up     INTEGER NOT NULL DEFAULT 0,
    bytes_down   INTEGER NOT NULL DEFAULT 0,
    flows        INTEGER NOT NULL DEFAULT 0,
    last_ts      INTEGER NOT NULL,
    PRIMARY KEY (day, device, remote_ip, remote_port, proto)
);

CREATE TABLE IF NOT EXISTS wan_samples (
    ts        INTEGER PRIMARY KEY,
    tx_bytes  INTEGER NOT NULL,
    rx_bytes  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS wan_daily (
    day         TEXT PRIMARY KEY,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    bytes_down  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    severity      TEXT NOT NULL,
    category      TEXT NOT NULL,
    device        TEXT,
    title         TEXT NOT NULL,
    detail        TEXT,
    dedupe_key    TEXT NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_key ON alerts(dedupe_key, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

EXPORTABLE_TABLES = {
    "devices": "last_seen",
    "dns_queries": "ts",
    "domain_stats": "day",
    "traffic_daily": "day",
    "traffic_hourly": "hour_ts",
    "host_traffic": "day",
    "wan_daily": "day",
    "alerts": "ts",
}


def device_key(mac: str | None, ip: str) -> str:
    return mac if mac else f"ip:{ip}"


class Store:
    def __init__(self, db_path: str | Path, timezone: str | None = None) -> None:
        self.db_path = str(db_path)
        self.tz = ZoneInfo(timezone) if timezone else None
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

        self._ip_to_mac: dict[str, str] = {}
        self._ip_to_domain: dict[str, str] = {}
        self._dns_buf: list[tuple[Any, ...]] = []
        self._ip_domain_buf: dict[str, tuple[str, int]] = {}
        self._traffic_buf: dict[tuple[int, str], list[int]] = defaultdict(lambda: [0, 0])
        self._host_buf: dict[tuple[str, str, str, int, str], list[Any]] = {}

        for row in self._conn.execute("SELECT mac, ip FROM devices WHERE ip IS NOT NULL"):
            self._ip_to_mac[row["ip"]] = row["mac"]
        for row in self._conn.execute(
            "SELECT ip, domain FROM ip_domain ORDER BY last_seen DESC LIMIT 200000"
        ):
            self._ip_to_domain.setdefault(row["ip"], row["domain"])
        if self.get_meta("installed_at") is None:
            self.set_meta("installed_at", str(int(time.time())))

    # ------------------------------------------------------------------ time
    def _dt(self, ts: float) -> datetime:
        return datetime.fromtimestamp(ts, self.tz) if self.tz else datetime.fromtimestamp(ts)

    def day_of(self, ts: float) -> str:
        return self._dt(ts).strftime("%Y-%m-%d")

    def hour_of(self, ts: float) -> int:
        return int(ts) - int(ts) % 3600

    def today(self) -> str:
        return self.day_of(time.time())

    def days_back(self, n: int, end: str | None = None) -> list[str]:
        end_dt = datetime.strptime(end, "%Y-%m-%d") if end else self._dt(time.time())
        return [(end_dt - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n - 1, -1, -1)]

    def day_bounds(self, day: str) -> tuple[int, int]:
        start = datetime.strptime(day, "%Y-%m-%d")
        if self.tz:
            start = start.replace(tzinfo=self.tz)
        end = start + timedelta(days=1)
        return int(start.timestamp()), int(end.timestamp())

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    # --------------------------------------------------------------- devices
    def upsert_device(
        self,
        mac: str,
        ts: float,
        ip: str | None = None,
        hostname: str | None = None,
        vendor: str | None = None,
        device_type: str | None = None,
        services: str | None = None,
        source: str | None = None,
    ) -> bool:
        """Insert or update a device. Returns True if the MAC is new."""
        ts = int(ts)
        with self._lock:
            row = self._conn.execute(
                "SELECT mac, sources, services, device_type FROM devices WHERE mac = ?", (mac,)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO devices(mac, ip, hostname, vendor, device_type, services,"
                    " first_seen, last_seen, sources) VALUES (?,?,?,?,?,?,?,?,?)",
                    (mac, ip, hostname, vendor, device_type, services, ts, ts, source),
                )
                is_new = True
            else:
                sources = set(filter(None, (row["sources"] or "").split(",")))
                if source:
                    sources.add(source)
                merged_services = row["services"]
                if services:
                    parts = set(filter(None, (merged_services or "").split(",")))
                    parts.update(services.split(","))
                    merged_services = ",".join(sorted(parts))
                new_type = device_type
                if row["device_type"] and row["device_type"] != "unknown" and device_type == "unknown":
                    new_type = None
                self._conn.execute(
                    "UPDATE devices SET ip = COALESCE(?, ip), hostname = COALESCE(?, hostname),"
                    " vendor = COALESCE(?, vendor), device_type = COALESCE(?, device_type),"
                    " services = ?, last_seen = MAX(last_seen, ?), sources = ? WHERE mac = ?",
                    (ip, hostname, vendor, new_type, merged_services, ts, ",".join(sorted(sources)), mac),
                )
                is_new = False
            if ip:
                self._ip_to_mac[ip] = mac
            self._conn.commit()
        return is_new

    def get_device(self, mac: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return dict(row) if row else None

    def update_device_fields(self, mac: str, fields: dict[str, Any]) -> bool:
        allowed = {"alias", "device_type", "trusted"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        assignments = ", ".join(f"{column} = ?" for column in updates)  # columns are allowlisted
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE devices SET {assignments} WHERE mac = ?", (*updates.values(), mac)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def learn_ip(self, ip: str, mac: str) -> None:
        """Remember an extra address (e.g. IPv6) for a device, in memory only."""
        self._ip_to_mac.setdefault(ip, mac)

    def mac_for_ip(self, ip: str) -> str | None:
        return self._ip_to_mac.get(ip)

    def device_for_ip(self, ip: str) -> str:
        return device_key(self._ip_to_mac.get(ip), ip)

    # ------------------------------------------------------------------- dns
    def record_dns(
        self,
        ts: float,
        client_ip: str,
        domain: str,
        qtype: str | None = None,
        rcode: str | None = None,
        answers: Iterable[str] = (),
        source: str = "dns",
    ) -> str:
        device = self.device_for_ip(client_ip)
        with self._lock:
            self._dns_buf.append((int(ts), client_ip, device, domain, qtype, rcode, source))
            for ip in answers:
                self._ip_to_domain[ip] = domain
                self._ip_domain_buf[ip] = (domain, int(ts))
        return device

    def domain_for_ip(self, ip: str) -> str | None:
        return self._ip_to_domain.get(ip)

    # --------------------------------------------------------------- traffic
    def add_traffic(
        self,
        ts: float,
        local_ip: str,
        remote_ip: str,
        remote_port: int,
        proto: str,
        bytes_up: int,
        bytes_down: int,
        flows: int = 0,
    ) -> str:
        device = self.device_for_ip(local_ip)
        day = self.day_of(ts)
        with self._lock:
            bucket = self._traffic_buf[(self.hour_of(ts), device)]
            bucket[0] += bytes_up
            bucket[1] += bytes_down
            key = (day, device, remote_ip, int(remote_port), proto)
            entry = self._host_buf.get(key)
            if entry is None:
                entry = [0, 0, 0, int(ts), self._ip_to_domain.get(remote_ip)]
                self._host_buf[key] = entry
            entry[0] += bytes_up
            entry[1] += bytes_down
            entry[2] += flows
            entry[3] = max(entry[3], int(ts))
            if entry[4] is None:
                entry[4] = self._ip_to_domain.get(remote_ip)
        return device

    def record_wan_counters(self, ts: float, tx_bytes: int, rx_bytes: int) -> tuple[int, int] | None:
        """Store a gateway WAN counter sample; returns the (up, down) delta added."""
        ts = int(ts)
        with self._lock:
            prev = self._conn.execute(
                "SELECT ts, tx_bytes, rx_bytes FROM wan_samples ORDER BY ts DESC LIMIT 1"
            ).fetchone()
            self._conn.execute(
                "INSERT OR REPLACE INTO wan_samples(ts, tx_bytes, rx_bytes) VALUES (?,?,?)",
                (ts, tx_bytes, rx_bytes),
            )
            delta = None
            if prev is not None and ts > prev["ts"]:
                # Counters reset when the gateway reboots; treat the new value as the delta.
                up = tx_bytes - prev["tx_bytes"] if tx_bytes >= prev["tx_bytes"] else tx_bytes
                down = rx_bytes - prev["rx_bytes"] if rx_bytes >= prev["rx_bytes"] else rx_bytes
                self._conn.execute(
                    "INSERT INTO wan_daily(day, bytes_up, bytes_down) VALUES (?,?,?) "
                    "ON CONFLICT(day) DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up,"
                    " bytes_down = bytes_down + excluded.bytes_down",
                    (self.day_of(ts), up, down),
                )
                delta = (up, down)
            self._conn.commit()
        return delta

    # ----------------------------------------------------------------- flush
    def flush(self) -> None:
        with self._lock:
            dns_rows, self._dns_buf = self._dns_buf, []
            ip_domains, self._ip_domain_buf = self._ip_domain_buf, {}
            traffic, self._traffic_buf = self._traffic_buf, defaultdict(lambda: [0, 0])
            hosts, self._host_buf = self._host_buf, {}
            if not (dns_rows or ip_domains or traffic or hosts):
                return
            cur = self._conn.cursor()
            if dns_rows:
                cur.executemany(
                    "INSERT INTO dns_queries(ts, client_ip, device, domain, qtype, rcode, source)"
                    " VALUES (?,?,?,?,?,?,?)",
                    dns_rows,
                )
                stats: dict[tuple[str, str, str], list[int]] = {}
                domain_totals: dict[str, list[int]] = {}
                for ts, _ip, device, domain, _qt, rcode, _src in dns_rows:
                    key = (self.day_of(ts), device, domain)
                    s = stats.setdefault(key, [0, 0, ts, ts])
                    s[0] += 1
                    s[1] += 1 if rcode == "BLOCKED" else 0
                    s[2] = min(s[2], ts)
                    s[3] = max(s[3], ts)
                    d = domain_totals.setdefault(domain, [0, ts, ts])
                    d[0] += 1
                    d[1] = min(d[1], ts)
                    d[2] = max(d[2], ts)
                cur.executemany(
                    "INSERT INTO domain_stats(day, device, domain, base_domain, queries, blocked,"
                    " first_ts, last_ts) VALUES (?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(day, device, domain) DO UPDATE SET"
                    " queries = queries + excluded.queries, blocked = blocked + excluded.blocked,"
                    " first_ts = MIN(first_ts, excluded.first_ts), last_ts = MAX(last_ts, excluded.last_ts)",
                    [(k[0], k[1], k[2], base_domain(k[2]), *v) for k, v in stats.items()],
                )
                cur.executemany(
                    "INSERT INTO domains(domain, base_domain, first_seen, last_seen, total_queries)"
                    " VALUES (?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET"
                    " last_seen = MAX(last_seen, excluded.last_seen),"
                    " total_queries = total_queries + excluded.total_queries",
                    [(dom, base_domain(dom), v[1], v[2], v[0]) for dom, v in domain_totals.items()],
                )
            if ip_domains:
                cur.executemany(
                    "INSERT INTO ip_domain(ip, domain, last_seen) VALUES (?,?,?) "
                    "ON CONFLICT(ip) DO UPDATE SET domain = excluded.domain, last_seen = excluded.last_seen",
                    [(ip, dom, ts) for ip, (dom, ts) in ip_domains.items()],
                )
            if traffic:
                cur.executemany(
                    "INSERT INTO traffic_hourly(hour_ts, device, bytes_up, bytes_down) VALUES (?,?,?,?) "
                    "ON CONFLICT(hour_ts, device) DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up,"
                    " bytes_down = bytes_down + excluded.bytes_down",
                    [(h, dev, up, down) for (h, dev), (up, down) in traffic.items()],
                )
                daily: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
                for (h, dev), (up, down) in traffic.items():
                    agg = daily[(self.day_of(h), dev)]
                    agg[0] += up
                    agg[1] += down
                cur.executemany(
                    "INSERT INTO traffic_daily(day, device, bytes_up, bytes_down) VALUES (?,?,?,?) "
                    "ON CONFLICT(day, device) DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up,"
                    " bytes_down = bytes_down + excluded.bytes_down",
                    [(d, dev, up, down) for (d, dev), (up, down) in daily.items()],
                )
            if hosts:
                cur.executemany(
                    "INSERT INTO host_traffic(day, device, remote_ip, remote_port, proto, remote_host,"
                    " bytes_up, bytes_down, flows, last_ts) VALUES (?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(day, device, remote_ip, remote_port, proto) DO UPDATE SET"
                    " bytes_up = bytes_up + excluded.bytes_up, bytes_down = bytes_down + excluded.bytes_down,"
                    " flows = flows + excluded.flows, last_ts = MAX(last_ts, excluded.last_ts),"
                    " remote_host = COALESCE(excluded.remote_host, remote_host)",
                    [(*k, v[4], v[0], v[1], v[2], v[3]) for k, v in hosts.items()],
                )
            activity: dict[str, int] = {}
            for row in dns_rows:
                activity[row[2]] = max(activity.get(row[2], 0), row[0])
            for (_d, dev, _rip, _port, _proto), v in hosts.items():
                activity[dev] = max(activity.get(dev, 0), v[3])
            cur.executemany(
                "UPDATE devices SET last_seen = MAX(last_seen, ?) WHERE mac = ?",
                [(ts, dev) for dev, ts in activity.items() if not dev.startswith("ip:")],
            )
            self._conn.commit()

    # ---------------------------------------------------------------- alerts
    def add_alert(
        self,
        severity: str,
        category: str,
        title: str,
        detail: str,
        dedupe_key: str,
        device: str | None = None,
        cooldown_seconds: int = 86400,
        ts: float | None = None,
    ) -> bool:
        ts = int(ts if ts is not None else time.time())
        with self._lock:
            recent = self._conn.execute(
                "SELECT 1 FROM alerts WHERE dedupe_key = ? AND ts > ? LIMIT 1",
                (dedupe_key, ts - cooldown_seconds),
            ).fetchone()
            if recent:
                return False
            self._conn.execute(
                "INSERT INTO alerts(ts, severity, category, device, title, detail, dedupe_key)"
                " VALUES (?,?,?,?,?,?,?)",
                (ts, severity, category, device, title, detail, dedupe_key),
            )
            self._conn.commit()
        return True

    def ack_alerts(self, alert_id: int | None = None) -> int:
        with self._lock:
            if alert_id is None:
                cur = self._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
            else:
                cur = self._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            self._conn.commit()
        return cur.rowcount

    # --------------------------------------------------------------- queries
    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, tuple(params)).fetchone()
        return dict(row) if row else None

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
        return cur.rowcount

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, rows)
            self._conn.commit()

    # ------------------------------------------------------------- retention
    def prune(self, retention: dict[str, int], now: float | None = None) -> dict[str, int]:
        now = now or time.time()
        removed = {}
        with self._lock:
            removed["dns_queries"] = self._conn.execute(
                "DELETE FROM dns_queries WHERE ts < ?", (now - retention["raw_dns_days"] * 86400,)
            ).rowcount
            removed["traffic_hourly"] = self._conn.execute(
                "DELETE FROM traffic_hourly WHERE hour_ts < ?",
                (now - retention["hourly_traffic_days"] * 86400,),
            ).rowcount
            removed["wan_samples"] = self._conn.execute(
                "DELETE FROM wan_samples WHERE ts < ?", (now - retention["wan_samples_days"] * 86400,)
            ).rowcount
            removed["host_traffic"] = self._conn.execute(
                "DELETE FROM host_traffic WHERE day < ?",
                (self.day_of(now - retention["host_traffic_days"] * 86400),),
            ).rowcount
            removed["ip_domain"] = self._conn.execute(
                "DELETE FROM ip_domain WHERE last_seen < ?", (now - 30 * 86400,)
            ).rowcount
            self._conn.commit()
        return removed

    def close(self) -> None:
        self.flush()
        with self._lock:
            self._conn.close()
