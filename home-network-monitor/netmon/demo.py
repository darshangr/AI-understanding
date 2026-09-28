"""Seed a database with a realistic month of synthetic home-network data.

Lets you explore the dashboard without touching your network:
``python -m netmon demo``.
"""

from __future__ import annotations

import random
import time

from .domains import base_domain
from .service import Monitor

MB = 1024 * 1024

# (mac, ip, hostname, profile)
DEVICES = [
    ("8C:85:90:1A:2B:01", "192.168.1.64", "Dads-MacBook-Pro", "laptop"),
    ("5A:3F:21:9C:44:02", "192.168.1.65", "Moms-iPhone", "phone"),
    ("F0:18:98:3C:11:03", "192.168.1.66", "iPad", "tablet"),
    ("F4:F5:D8:77:21:04", "192.168.1.67", "Pixel-8", "phone"),
    ("B0:A7:37:5D:90:05", "192.168.1.68", "Roku-Ultra", "tv"),
    ("44:65:0D:A1:B2:06", "192.168.1.69", "Fire-TV-Stick", "tv"),
    ("68:54:FD:0E:33:07", "192.168.1.70", "Echo-Dot-Kitchen", "speaker"),
    ("34:3E:A4:6F:12:08", "192.168.1.71", "Ring-Doorbell", "camera"),
    ("18:B4:30:2C:8D:09", "192.168.1.72", "Nest-Thermostat", "iot"),
    ("8C:79:F5:44:10:0A", "192.168.1.73", "Samsung-QLED-TV", "tv"),
    ("98:5F:D3:61:7A:0B", "192.168.1.74", "DESKTOP-7GH2K", "computer"),
    ("A0:8C:FD:19:C4:0C", "192.168.1.75", "HP-OfficeJet-Pro", "printer"),
    ("68:57:2D:8B:E0:0D", "192.168.1.76", "Smart-Plug-Garage", "plug"),
    ("00:D9:D1:73:5A:0E", "192.168.1.77", "PS5", "console"),
    ("FC:65:DE:3E:77:0F", "192.168.1.78", "Kids-Fire-HD", "tablet"),
    ("B8:27:EB:12:34:10", "192.168.1.79", "raspberrypi", "server"),
]

DOMAINS = {
    "laptop": ["www.google.com", "mail.google.com", "github.com", "api.github.com", "slack.com", "zoom.us",
               "outlook.office365.com", "www.youtube.com", "i.ytimg.com", "stackoverflow.com", "apple.com",
               "icloud.com", "gateway.icloud.com", "docs.google.com", "news.ycombinator.com", "www.linkedin.com",
               "cdn.jsdelivr.net", "fonts.googleapis.com", "www.amazon.com", "chase.com"],
    "computer": ["www.bing.com", "login.microsoftonline.com", "settings-win.data.microsoft.com", "www.msn.com",
                 "steamcommunity.com", "store.steampowered.com", "discord.com", "gateway.discord.gg",
                 "www.reddit.com", "www.twitch.tv", "windowsupdate.com", "ctldl.windowsupdate.com"],
    "phone": ["www.instagram.com", "graph.facebook.com", "scontent.cdninstagram.com", "api.whatsapp.net",
              "www.tiktok.com", "v16m.tiktokcdn.com", "gateway.icloud.com", "mesu.apple.com", "maps.apple.com",
              "spotify.com", "audio-ak-spotify-com.akamaized.net", "www.google.com", "gmail.com", "api.twitter.com",
              "weather.com", "app-measurement.com"],
    "tablet": ["www.youtube.com", "youtubei.googleapis.com", "r3---sn-ab5l6nrz.googlevideo.com", "www.roblox.com",
               "setup.roblox.com", "pbskids.org", "www.netflix.com", "kids.youtube.com", "api.amazon.com",
               "device-metrics-us.amazon.com", "minecraft.net"],
    "tv": ["www.netflix.com", "nflxvideo.net", "ipv4-c001-dfw001-ix.1.oca.nflxvideo.net", "api.hulu.com",
           "disneyplus.com", "bamgrid.com", "scribe.logs.roku.com", "cloudservices.roku.com", "www.youtube.com",
           "googlevideo.com", "api.amazonvideo.com", "atv-ps.amazon.com", "samsungcloudsolution.com",
           "log-config.samsungacr.com", "tvinfo.samsungcloudsolution.com"],
    "speaker": ["avs-alexa-4-na.amazon.com", "device-metrics-us.amazon.com", "api.amazonalexa.com",
                "pindorama.amazon.com", "spectrum.s3.amazonaws.com", "ntp-g7g.amazon.com"],
    "camera": ["fw.ring.com", "es.ring.com", "api.prod.signalling.ring.devices.a2z.com", "stickupcammini.s3.amazonaws.com",
               "time.nist.gov"],
    "iot": ["frontdoor.nest.com", "transport01.rts18.iad01.production.nest.com", "time.google.com"],
    "printer": ["hpeprint.com", "h10141.www1.hp.com", "time.nist.gov"],
    "plug": ["a1.tuyaus.com", "m1.tuyaus.com", "pool.ntp.org"],
    "console": ["playstation.net", "np.community.playstation.net", "gs2.ww.prod.dl.playstation.net",
                "psn-rsc.prod.dl.playstation.net", "www.fortnite.com", "epicgames.com"],
    "server": ["deb.debian.org", "archive.raspberrypi.org", "pypi.org", "files.pythonhosted.org", "urlhaus.abuse.ch"],
}

# profile: (daily download MB, daily upload MB, dns lookups/day, active hours)
PROFILES = {
    "laptop": (2500, 400, 3500, range(8, 23)),
    "computer": (6000, 350, 2500, range(15, 24)),
    "phone": (1500, 200, 4000, range(7, 24)),
    "tablet": (1800, 60, 1800, range(15, 21)),
    "tv": (9000, 90, 1500, range(18, 24)),
    "speaker": (120, 30, 900, range(0, 24)),
    "camera": (60, 350, 500, range(0, 24)),
    "iot": (15, 8, 300, range(0, 24)),
    "printer": (3, 1, 60, range(0, 24)),
    "plug": (2, 1, 150, range(0, 24)),
    "console": (7000, 150, 800, range(16, 24)),
    "server": (200, 40, 400, range(0, 24)),
}

REMOTE_IPS = {
    "laptop": [("140.82.114.4", 443), ("142.250.72.100", 443), ("17.253.144.10", 443)],
    "computer": [("13.107.4.50", 443), ("162.159.130.234", 443), ("23.62.210.12", 443)],
    "phone": [("157.240.22.35", 443), ("31.13.66.63", 443), ("17.57.144.20", 5223)],
    "tablet": [("142.250.72.110", 443), ("128.116.123.3", 443)],
    "tv": [("45.57.90.1", 443), ("198.38.120.1", 443), ("52.84.150.10", 443)],
    "speaker": [("52.94.233.129", 443)],
    "camera": [("3.33.186.135", 443), ("52.20.211.9", 443)],
    "iot": [("34.107.192.10", 443)],
    "printer": [("15.73.182.64", 443)],
    "plug": [("18.214.100.12", 8883)],
    "console": [("23.38.215.10", 443), ("35.186.224.25", 443)],
    "server": [("151.101.0.223", 443)],
}


def _hour_weights(active: range) -> list[float]:
    return [1.0 if h in active else 0.08 for h in range(24)]


def seed(monitor: Monitor, days: int = 30, seed_value: int = 7) -> None:
    rng = random.Random(seed_value)
    store = monitor.store
    now = time.time()
    today = store.today()
    start_of_today = store.day_bounds(today)[0]
    store.set_meta("installed_at", str(int(start_of_today - days * 86400)))

    for mac, ip, host, _p in DEVICES:
        monitor.on_device(mac, ip=ip, hostname=host, source="att_gateway",
                          ts=start_of_today - days * 86400 + rng.randint(0, 3600))
    store.execute("UPDATE devices SET first_seen = ?", (int(start_of_today - days * 86400),))
    store.execute("DELETE FROM alerts")
    store.execute("UPDATE devices SET alias = 'Garage smart plug' WHERE hostname = 'Smart-Plug-Garage'")
    store.execute("UPDATE devices SET services = 'conn:wifi-5ghz' WHERE mac LIKE '8C:85:90%'")

    domain_rows = []
    for day_offset in range(days, -1, -1):
        day_start = start_of_today - day_offset * 86400
        day = store.day_of(day_start + 3600)
        is_today = day_offset == 0
        hours_so_far = int((now - day_start) // 3600) + 1 if is_today else 24
        weekend = time.localtime(day_start + 3600).tm_wday >= 5
        wan_up = wan_down = 0
        for mac, ip, _host, profile in DEVICES:
            down_mb, up_mb, lookups, active = PROFILES[profile]
            scale = rng.uniform(0.6, 1.4) * (1.3 if weekend and profile in ("tv", "console", "tablet") else 1.0)
            weights = _hour_weights(active)
            total_w = sum(weights)
            remotes = REMOTE_IPS[profile]
            for hour in range(min(24, hours_so_far)):
                frac = weights[hour] / total_w * rng.uniform(0.5, 1.5)
                down = int(down_mb * MB * scale * frac)
                up = int(up_mb * MB * scale * frac)
                if profile == "camera" and is_today and hour >= max(0, hours_so_far - 4):
                    up += int(900 * MB * rng.uniform(0.9, 1.1))  # the upload spike the anomaly engine should catch
                ts = min(day_start + hour * 3600 + 1800, now - 60)
                rip, rport = rng.choice(remotes)
                store.add_traffic(ts, ip, rip, rport, "tcp", up, down, flows=rng.randint(5, 60))
                wan_up += up
                wan_down += down
            domain_list = DOMAINS[profile]
            day_lookups = int(lookups * scale * (hours_so_far / 24))
            weights_d = [1 / (i + 1) for i in range(len(domain_list))]
            counts: dict[str, int] = {}
            for dom in rng.choices(domain_list, weights=weights_d, k=min(day_lookups, 400)):
                counts[dom] = counts.get(dom, 0) + 1
            factor = max(1, day_lookups // 400)
            if not is_today:
                for dom, c in counts.items():
                    first = int(day_start + rng.randint(0, 40000))
                    domain_rows.append((day, mac, dom, c * factor, first, first + rng.randint(600, 40000)))
        store.flush()
        store.execute(
            "INSERT INTO wan_daily(day, bytes_up, bytes_down) VALUES (?,?,?) ON CONFLICT(day) DO UPDATE SET"
            " bytes_up = excluded.bytes_up, bytes_down = excluded.bytes_down",
            (day, int(wan_up * 1.04), int(wan_down * 1.03)))

    store.executemany(
        "INSERT INTO domain_stats(day, device, domain, base_domain, queries, blocked, first_ts, last_ts)"
        " VALUES (?,?,?,?,?,0,?,?) ON CONFLICT(day, device, domain) DO UPDATE SET queries = queries + excluded.queries",
        [(d, dev, dom, base_domain(dom), q, f, l) for d, dev, dom, q, f, l in domain_rows])
    store.executemany(
        "INSERT INTO domains(domain, base_domain, first_seen, last_seen, total_queries) VALUES (?,?,?,?,?)"
        " ON CONFLICT(domain) DO UPDATE SET total_queries = total_queries + excluded.total_queries,"
        " first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen)",
        [(dom, base_domain(dom), f, l, q) for _d, _dev, dom, q, f, l in domain_rows])

    # Today's raw DNS log, via the real pipeline so anomaly checks run.
    hours_today = int((now - start_of_today) // 3600) + 1
    events = []
    for mac, ip, _host, profile in DEVICES:
        _d, _u, lookups, active = PROFILES[profile]
        n = int(lookups * hours_today / 24 * 0.25)
        for _ in range(n):
            events.append((rng.uniform(max(start_of_today, now - 6 * 3600), now - 30), ip,
                           rng.choices(DOMAINS[profile], weights=[1 / (i + 1) for i in range(len(DOMAINS[profile]))])[0]))
    events.sort()
    for ts, ip, dom in events:
        monitor.on_dns(ip, dom, rng.choice(["A", "A", "AAAA", "HTTPS"]), "NOERROR", source="dns_proxy", ts=ts)

    # Suspicious activity for the anomaly engine to find.
    if monitor.feeds is not None:
        monitor.feeds.domains["secure-login-verify.xyz"] = "demo-feed"
        monitor.feeds.ips["185.220.101.47"] = "demo-feed"
    plug_ip, kid_ip, pc_ip, phone_ip = "192.168.1.76", "192.168.1.78", "192.168.1.74", "192.168.1.65"
    t = now - 2 * 3600
    for dom in ("xj4k9qzt2mplw8vr.com", "qpz7x2kfm9wltrbn.net", "zk3mf8q2xwpl7tny.info"):
        monitor.on_dns(plug_ip, dom, "A", "NXDOMAIN", source="dns_proxy", ts=t)
        t += 60
    monitor.on_flow(plug_ip, "185.220.101.47", 50211, 6667, "tcp", 5400, flows=1, ts=now - 5400)
    monitor.on_dns(kid_ip, "free-robux-generator.top", "A", "NOERROR", source="dns_proxy", ts=now - 3000)
    monitor.on_dns(phone_ip, "secure-login-verify.xyz", "A", "NOERROR", source="dns_proxy", ts=now - 1800)
    monitor.on_flow(pc_ip, "8.8.8.8", 51000, 853, "tcp", 12000, flows=1, ts=now - 4000)
    monitor.on_device("DA:A1:19:5E:22:C1", ip="192.168.1.90", source="att_gateway", ts=now - 1200)
    store.flush()
    monitor.anomaly.run_periodic(now)
    store.execute("UPDATE alerts SET acknowledged = 1 WHERE severity = 'info'")
