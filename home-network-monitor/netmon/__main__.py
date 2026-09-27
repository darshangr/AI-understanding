"""Command-line entry point: ``python -m netmon <command>``."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import signal
import sys
import tempfile
from pathlib import Path

from .config import load_config, secret

log = logging.getLogger("netmon")

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _auth_for(host: str, allow_unauthenticated: bool) -> tuple[str, str] | None:
    password = secret("NETMON_DASHBOARD_PASSWORD")
    if password:
        return (secret("NETMON_DASHBOARD_USER") or "admin", password)
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if loopback or allow_unauthenticated:
        if not loopback:
            log.warning("dashboard on %s WITHOUT a password (web.allow_unauthenticated is true)", host)
        return None
    sys.exit(
        f"Refusing to serve the dashboard on {host} without a password.\n"
        "Set NETMON_DASHBOARD_PASSWORD (and optionally NETMON_DASHBOARD_USER), bind web.host to 127.0.0.1, "
        "or set web.allow_unauthenticated: true in the config if you accept the risk."
    )


def _serve(app, host: str, port: int) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info", access_log=False)


def cmd_run(args: argparse.Namespace) -> None:
    from .service import Monitor
    from .web.app import create_app

    cfg = load_config(args.config)
    host = args.host or cfg.get_path("web.host")
    port = args.port or int(cfg.get_path("web.port"))
    auth = _auth_for(host, bool(cfg.get_path("web.allow_unauthenticated")))
    monitor = Monitor(cfg)
    monitor.start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        _serve(create_app(monitor.store, lambda: monitor.status, auth), host, port)
    finally:
        monitor.stop()


def cmd_demo(args: argparse.Namespace) -> None:
    from .config import Config, DEFAULTS, _deep_merge
    from .demo import seed
    from .service import Monitor
    from .web.app import create_app

    data_dir = Path(args.data_dir) if args.data_dir else Path(tempfile.mkdtemp(prefix="netmon-demo-"))
    cfg = Config(_deep_merge(DEFAULTS, {"data_dir": str(data_dir), "feeds": {"sources": []}}))
    db_exists = cfg.db_path.exists()
    monitor = Monitor(cfg)
    if not db_exists:
        log.info("seeding %d days of demo data into %s ...", args.days, cfg.db_path)
        seed(monitor, days=args.days)
    auth = _auth_for(args.host, False)
    log.info("demo dashboard: http://%s:%d", args.host, args.port)
    try:
        _serve(create_app(monitor.store, lambda: {"demo": {"ok": True, "message": "synthetic data", "updated": 0}}, auth),
               args.host, args.port)
    finally:
        monitor.store.close()


def cmd_update_feeds(args: argparse.Namespace) -> None:
    from .feeds import ThreatFeeds

    cfg = load_config(args.config)
    feeds = ThreatFeeds(cfg.data_dir, cfg.get_path("feeds.sources", []), cfg.get_path("feeds.local_files", []))
    feeds.refresh(force=True)
    print(f"{len(feeds.domains)} malicious domains, {len(feeds.ips)} malicious IPs loaded")


def cmd_update_oui(args: argparse.Namespace) -> None:
    import httpx

    cfg = load_config(args.config)
    target = cfg.data_dir / "oui.csv"
    with httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": "netmon/0.1"}) as client:
        resp = client.get(OUI_URL)
        resp.raise_for_status()
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(resp.content)
    tmp.replace(target)
    print(f"saved {len(resp.content):,} bytes to {target}")


def cmd_prune(args: argparse.Namespace) -> None:
    from .db import Store

    cfg = load_config(args.config)
    store = Store(cfg.db_path, cfg.get("timezone"))
    print(store.prune(cfg["retention"]))
    store.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="netmon", description="Home network monitor")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run collectors and the dashboard")
    run.add_argument("-c", "--config", help="path to config.yaml (or set NETMON_CONFIG)")
    run.add_argument("--host")
    run.add_argument("--port", type=int)
    run.set_defaults(func=cmd_run)

    demo = sub.add_parser("demo", help="serve the dashboard with a month of synthetic data")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--port", type=int, default=8080)
    demo.add_argument("--days", type=int, default=30)
    demo.add_argument("--data-dir", help="reuse/keep the demo database here")
    demo.set_defaults(func=cmd_demo)

    for name, func, text in (("update-feeds", cmd_update_feeds, "download threat-intel feeds now"),
                             ("update-oui", cmd_update_oui, "download the IEEE MAC vendor registry"),
                             ("prune", cmd_prune, "apply data retention now")):
        p = sub.add_parser(name, help=text)
        p.add_argument("-c", "--config")
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()
