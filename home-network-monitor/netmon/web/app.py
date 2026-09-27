"""Dashboard + JSON API."""

from __future__ import annotations

import base64
import binascii
import csv
import io
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import Body, FastAPI, HTTPException, Path as PathParam, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ..db import EXPORTABLE_TABLES, Store

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
ONLINE_SECONDS = 15 * 60
DAY_RE = r"^\d{4}-\d{2}-\d{2}$"
MAC_RE = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^ip:[0-9a-fA-F.:]{3,45}$"
DEVICE_TYPES = {"phone", "tablet", "laptop", "computer", "tv/streaming", "game console", "smart speaker",
                "camera/doorbell", "printer", "iot", "server", "network", "apple device",
                "phone/tablet/laptop", "unknown"}

def label_sql(fallback: str) -> str:
    return (f"COALESCE(d.alias, d.hostname, CASE WHEN d.vendor = 'Randomized MAC' THEN d.ip END,"
            f" d.vendor, {fallback})")


LABEL_SQL = label_sql("x.device")


def _basic_auth_ok(header: str | None, user: str, password: str) -> bool:
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    given_user, _, given_pw = decoded.partition(":")
    # SECURITY-REVIEW: constant-time comparison of the shared dashboard secret.
    return secrets.compare_digest(given_user.encode(), user.encode()) & secrets.compare_digest(
        given_pw.encode(), password.encode())


def create_app(store: Store, status_provider: Callable[[], dict[str, Any]] | None = None,
               auth: tuple[str, str] | None = None) -> FastAPI:
    app = FastAPI(title="Home Network Monitor", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security(request: Request, call_next):
        if auth and not _basic_auth_ok(request.headers.get("authorization"), *auth):
            return Response("Authentication required", status_code=401,
                            headers={"WWW-Authenticate": 'Basic realm="netmon"'})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'")
        return response

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception):
        log.exception("API error", exc_info=exc)
        return JSONResponse({"error": "internal error"}, status_code=500)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    def _day(day: str | None) -> str:
        return day or store.today()

    # ----------------------------------------------------------------- health
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "collectors": status_provider() if status_provider else {},
                "installed_at": int(store.get_meta("installed_at") or 0), "now": int(time.time())}

    # ---------------------------------------------------------------- summary
    @app.get("/api/summary")
    def summary(day: str | None = Query(None, pattern=DAY_RE)) -> dict[str, Any]:
        day = _day(day)
        start, end = store.day_bounds(day)
        now = time.time()
        wan = store.query_one("SELECT bytes_up, bytes_down FROM wan_daily WHERE day = ?", (day,))
        dev = store.query_one(
            "SELECT COALESCE(SUM(bytes_up),0) AS bytes_up, COALESCE(SUM(bytes_down),0) AS bytes_down,"
            " COUNT(*) AS devices FROM traffic_daily WHERE day = ?", (day,))
        counts = store.query_one(
            "SELECT COUNT(*) AS total, SUM(last_seen >= ?) AS online, SUM(first_seen >= ? AND first_seen < ?) AS new"
            " FROM devices", (now - ONLINE_SECONDS, start, end))
        dns = store.query_one(
            "SELECT COALESCE(SUM(queries),0) AS queries, COUNT(DISTINCT domain) AS domains,"
            " COALESCE(SUM(blocked),0) AS blocked FROM domain_stats WHERE day = ?", (day,))
        alerts = store.query(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE acknowledged = 0 GROUP BY severity")
        top_domains = store.query(
            "SELECT base_domain AS domain, SUM(queries) AS queries, COUNT(DISTINCT device) AS devices"
            " FROM domain_stats WHERE day = ? GROUP BY base_domain ORDER BY queries DESC LIMIT 12", (day,))
        top_talkers = store.query(
            f"SELECT x.device, {LABEL_SQL} AS label, d.device_type, x.bytes_up, x.bytes_down"
            " FROM traffic_daily x LEFT JOIN devices d ON d.mac = x.device"
            " WHERE x.day = ? ORDER BY (x.bytes_up + x.bytes_down) DESC LIMIT 10", (day,))
        hourly = store.query(
            "SELECT hour_ts, SUM(bytes_up) AS bytes_up, SUM(bytes_down) AS bytes_down FROM traffic_hourly"
            " WHERE hour_ts >= ? AND hour_ts < ? GROUP BY hour_ts ORDER BY hour_ts", (start, end))
        hourly_dns = store.query(
            "SELECT (ts - ts % 3600) AS hour_ts, COUNT(*) AS queries FROM dns_queries"
            " WHERE ts >= ? AND ts < ? GROUP BY hour_ts ORDER BY hour_ts", (start, end))
        return {
            "day": day,
            "traffic": {
                "wan": wan,
                "devices": {"bytes_up": dev["bytes_up"], "bytes_down": dev["bytes_down"]},
                "source": "gateway" if wan else ("devices" if dev["devices"] else "none"),
            },
            "devices": {"total": counts["total"] or 0, "online": counts["online"] or 0, "new": counts["new"] or 0},
            "dns": dns,
            "alerts": {r["severity"]: r["n"] for r in alerts},
            "top_domains": top_domains,
            "top_talkers": top_talkers,
            "hourly": hourly,
            "hourly_dns": hourly_dns,
        }

    # ---------------------------------------------------------------- devices
    @app.get("/api/devices")
    def devices(day: str | None = Query(None, pattern=DAY_RE)) -> list[dict[str, Any]]:
        day = _day(day)
        now = time.time()
        rows = store.query(
            "SELECT d.*, COALESCE(t.bytes_up,0) AS bytes_up, COALESCE(t.bytes_down,0) AS bytes_down,"
            " COALESCE(q.queries,0) AS queries, COALESCE(q.domains,0) AS domains,"
            " COALESCE(a.open_alerts,0) AS open_alerts"
            " FROM devices d"
            " LEFT JOIN traffic_daily t ON t.device = d.mac AND t.day = ?"
            " LEFT JOIN (SELECT device, SUM(queries) AS queries, COUNT(*) AS domains FROM domain_stats"
            "            WHERE day = ? GROUP BY device) q ON q.device = d.mac"
            " LEFT JOIN (SELECT device, COUNT(*) AS open_alerts FROM alerts WHERE acknowledged = 0"
            "            GROUP BY device) a ON a.device = d.mac"
            " ORDER BY d.last_seen DESC", (day, day))
        for r in rows:
            r["online"] = r["last_seen"] >= now - ONLINE_SECONDS
        unknown = store.query(
            "SELECT t.device AS mac, t.bytes_up, t.bytes_down FROM traffic_daily t"
            " WHERE t.day = ? AND t.device LIKE 'ip:%'", (day,))
        for u in unknown:
            u.update({"hostname": None, "vendor": None, "device_type": "unknown", "online": False,
                      "ip": u["mac"][3:], "alias": None, "last_seen": None, "first_seen": None,
                      "queries": 0, "domains": 0, "open_alerts": 0, "trusted": 0, "unidentified": True})
            rows.append(u)
        return rows

    @app.get("/api/devices/{mac}")
    def device_detail(mac: str = PathParam(..., pattern=MAC_RE), days: int = Query(30, ge=1, le=365)):
        mac = mac.upper() if not mac.startswith("ip:") else mac
        info = store.get_device(mac) or ({"mac": mac, "ip": mac[3:]} if mac.startswith("ip:") else None)
        if info is None:
            raise HTTPException(404, "device not found")
        day_list = store.days_back(days)
        history = {r["day"]: r for r in store.query(
            "SELECT day, bytes_up, bytes_down FROM traffic_daily WHERE device = ? AND day >= ?",
            (mac, day_list[0]))}
        dns_history = {r["day"]: r["queries"] for r in store.query(
            "SELECT day, SUM(queries) AS queries FROM domain_stats WHERE device = ? AND day >= ? GROUP BY day",
            (mac, day_list[0]))}
        week_start = store.days_back(7)[0]
        top_domains = store.query(
            "SELECT domain, SUM(queries) AS queries, MAX(last_ts) AS last_ts, SUM(blocked) AS blocked"
            " FROM domain_stats WHERE device = ? AND day >= ? GROUP BY domain ORDER BY queries DESC LIMIT 100",
            (mac, week_start))
        top_hosts = store.query(
            "SELECT remote_ip, remote_host, remote_port, proto, SUM(bytes_up) AS bytes_up,"
            " SUM(bytes_down) AS bytes_down, MAX(last_ts) AS last_ts FROM host_traffic"
            " WHERE device = ? AND day >= ? GROUP BY remote_ip, remote_port, proto"
            " ORDER BY (SUM(bytes_up) + SUM(bytes_down)) DESC LIMIT 50", (mac, week_start))
        alerts = store.query("SELECT * FROM alerts WHERE device = ? ORDER BY ts DESC LIMIT 50", (mac,))
        return {
            "device": info,
            "history": [{"day": d, "bytes_up": history.get(d, {}).get("bytes_up", 0),
                         "bytes_down": history.get(d, {}).get("bytes_down", 0),
                         "queries": dns_history.get(d, 0)} for d in day_list],
            "top_domains": top_domains,
            "top_hosts": top_hosts,
            "alerts": alerts,
        }

    @app.patch("/api/devices/{mac}")
    def update_device(mac: str = PathParam(..., pattern=MAC_RE), body: dict[str, Any] = Body(...)):
        fields: dict[str, Any] = {}
        if "alias" in body:
            alias = body["alias"]
            if alias is not None and (not isinstance(alias, str) or len(alias) > 64):
                raise HTTPException(400, "alias must be a string of at most 64 characters")
            fields["alias"] = (alias.strip() or None) if isinstance(alias, str) else None
        if "device_type" in body:
            if body["device_type"] not in DEVICE_TYPES:
                raise HTTPException(400, "unknown device type")
            fields["device_type"] = body["device_type"]
        if "trusted" in body:
            fields["trusted"] = 1 if body["trusted"] else 0
        if not fields or not store.update_device_fields(mac.upper(), fields):
            raise HTTPException(404, "device not found or nothing to update")
        return store.get_device(mac.upper())

    # ---------------------------------------------------------------- traffic
    @app.get("/api/traffic/daily")
    def traffic_daily(days: int = Query(30, ge=1, le=730)) -> list[dict[str, Any]]:
        day_list = store.days_back(days)
        wan = {r["day"]: r for r in store.query("SELECT * FROM wan_daily WHERE day >= ?", (day_list[0],))}
        dev = {r["day"]: r for r in store.query(
            "SELECT day, SUM(bytes_up) AS bytes_up, SUM(bytes_down) AS bytes_down, COUNT(*) AS devices"
            " FROM traffic_daily WHERE day >= ? GROUP BY day", (day_list[0],))}
        out = []
        for d in day_list:
            w, v = wan.get(d), dev.get(d)
            out.append({
                "day": d,
                "wan_up": w["bytes_up"] if w else None,
                "wan_down": w["bytes_down"] if w else None,
                "devices_up": v["bytes_up"] if v else 0,
                "devices_down": v["bytes_down"] if v else 0,
                "active_devices": v["devices"] if v else 0,
            })
        return out

    @app.get("/api/traffic/by-device")
    def traffic_by_device(start: str = Query(..., pattern=DAY_RE), end: str = Query(..., pattern=DAY_RE)):
        return store.query(
            f"SELECT x.device, {LABEL_SQL} AS label, SUM(x.bytes_up) AS bytes_up, SUM(x.bytes_down) AS bytes_down"
            " FROM traffic_daily x LEFT JOIN devices d ON d.mac = x.device"
            " WHERE x.day BETWEEN ? AND ? GROUP BY x.device ORDER BY SUM(x.bytes_up + x.bytes_down) DESC",
            (start, end))

    # ---------------------------------------------------------------- domains
    @app.get("/api/domains")
    def domains(
        day: str | None = Query(None, pattern=DAY_RE),
        days: int = Query(1, ge=1, le=365),
        search: str | None = Query(None, max_length=100),
        device: str | None = Query(None, pattern=MAC_RE),
        group: bool = Query(False),
        limit: int = Query(200, ge=1, le=2000),
    ) -> list[dict[str, Any]]:
        end = _day(day)
        start = store.days_back(days, end)[0]
        column = "s.base_domain" if group else "s.domain"
        where = ["s.day BETWEEN ? AND ?"]
        params: list[Any] = [start, end]
        if search:
            where.append(f"{column} LIKE ? ESCAPE '\\'")
            params.append("%" + re.sub(r"([%_\\])", r"\\\1", search.lower()) + "%")
        if device:
            where.append("s.device = ?")
            params.append(device.upper() if not device.startswith("ip:") else device)
        params.append(limit)
        return store.query(
            f"SELECT {column} AS domain, SUM(s.queries) AS queries, SUM(s.blocked) AS blocked,"
            " COUNT(DISTINCT s.device) AS devices, MIN(s.first_ts) AS first_ts, MAX(s.last_ts) AS last_ts,"
            " MIN(g.first_seen) AS first_seen_ever,"
            f" GROUP_CONCAT(DISTINCT {label_sql('s.device')}) AS device_labels"
            " FROM domain_stats s LEFT JOIN devices d ON d.mac = s.device"
            " LEFT JOIN domains g ON g.domain = s.domain"
            f" WHERE {' AND '.join(where)} GROUP BY {column} ORDER BY queries DESC LIMIT ?",
            params)

    @app.get("/api/queries")
    def queries(
        device: str | None = Query(None, pattern=MAC_RE),
        search: str | None = Query(None, max_length=100),
        before: int | None = Query(None, ge=0),
        limit: int = Query(200, ge=1, le=2000),
    ) -> list[dict[str, Any]]:
        where = ["1 = 1"]
        params: list[Any] = []
        if device:
            where.append("q.device = ?")
            params.append(device.upper() if not device.startswith("ip:") else device)
        if search:
            where.append("q.domain LIKE ? ESCAPE '\\'")
            params.append("%" + re.sub(r"([%_\\])", r"\\\1", search.lower()) + "%")
        if before:
            where.append("q.ts < ?")
            params.append(before)
        params.append(limit)
        return store.query(
            "SELECT q.ts, q.client_ip, q.device, q.domain, q.qtype, q.rcode, q.source,"
            f" {label_sql('q.device')} AS label"
            " FROM dns_queries q LEFT JOIN devices d ON d.mac = q.device"
            f" WHERE {' AND '.join(where)} ORDER BY q.ts DESC LIMIT ?", params)

    # ----------------------------------------------------------------- alerts
    @app.get("/api/alerts")
    def alerts(status: str = Query("open", pattern="^(open|all)$"), limit: int = Query(200, ge=1, le=2000)):
        where = "WHERE a.acknowledged = 0" if status == "open" else ""
        return store.query(
            f"SELECT a.*, {label_sql('a.device')} AS label FROM alerts a"
            f" LEFT JOIN devices d ON d.mac = a.device {where} ORDER BY a.ts DESC LIMIT ?", (limit,))

    @app.post("/api/alerts/{alert_id}/ack")
    def ack(alert_id: int = PathParam(..., ge=1)) -> dict[str, int]:
        return {"acknowledged": store.ack_alerts(alert_id)}

    @app.post("/api/alerts/ack-all")
    def ack_all() -> dict[str, int]:
        return {"acknowledged": store.ack_alerts(None)}

    # ----------------------------------------------------------------- export
    @app.get("/api/export/{table}.csv")
    def export(table: str, start: str | None = Query(None, pattern=DAY_RE),
               end: str | None = Query(None, pattern=DAY_RE)) -> StreamingResponse:
        if table not in EXPORTABLE_TABLES:
            raise HTTPException(404, "unknown table")
        column = EXPORTABLE_TABLES[table]  # allowlisted identifiers only
        where, params = [], []
        if start:
            where.append(f"{column} >= ?")
            params.append(start if column == "day" else store.day_bounds(start)[0])
        if end:
            where.append(f"{column} < ?" if column != "day" else f"{column} <= ?")
            params.append(end if column == "day" else store.day_bounds(end)[1])
        sql = f"SELECT * FROM {table}" + (f" WHERE {' AND '.join(where)}" if where else "")
        rows = store.query(sql, params)

        def generate():
            buf = io.StringIO()
            writer = csv.writer(buf)
            if rows:
                writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow(row.values())
                if buf.tell() > 65536:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate()
            yield buf.getvalue()

        filename = f"netmon-{table}-{start or 'all'}-{end or store.today()}.csv"
        return StreamingResponse(generate(), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    return app
