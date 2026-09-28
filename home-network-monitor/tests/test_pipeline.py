import base64
import socket
import threading
import time

from fastapi.testclient import TestClient

from netmon import dnsparse
from netmon.collectors.dns_proxy import DnsProxy
from netmon.web.app import create_app

MAC = "B0:A7:37:5D:90:05"
IP = "192.168.1.68"


def test_device_dns_and_traffic_are_attributed(monitor):
    monitor.on_device(MAC.lower(), ip=IP, hostname="Roku-Ultra", source="test")
    now = time.time()
    monitor.on_dns(IP, "www.Netflix.com", "A", "NOERROR", ["45.57.90.1"], ts=now)
    monitor.on_dns(IP, "www.netflix.com", "A", "NOERROR", ts=now)
    monitor.on_flow("45.57.90.1", IP, 443, 50000, "tcp", 10_000, ts=now)
    monitor.on_flow(IP, "45.57.90.1", 50000, 443, "tcp", 500, flows=1, ts=now)
    monitor.on_flow(IP, "192.168.1.20", 1, 2, "udp", 999, ts=now)  # LAN-to-LAN ignored
    monitor.store.flush()
    store = monitor.store
    day = store.day_of(now)
    dev = store.get_device(MAC)
    assert dev["device_type"] == "tv/streaming" and dev["vendor"] == "Roku"
    assert store.query_one("SELECT queries FROM domain_stats WHERE device = ? AND domain = 'www.netflix.com'",
                           (MAC,))["queries"] == 2
    t = store.query_one("SELECT * FROM traffic_daily WHERE day = ? AND device = ?", (day, MAC))
    assert (t["bytes_up"], t["bytes_down"]) == (500, 10_000)
    host = store.query_one("SELECT * FROM host_traffic WHERE device = ?", (MAC,))
    assert host["remote_host"] == "www.netflix.com" and host["remote_port"] == 443


def test_unknown_ip_gets_placeholder_device(monitor):
    monitor.on_dns("192.168.1.200", "example.com", ts=time.time())
    monitor.store.flush()
    assert monitor.store.query_one("SELECT device FROM dns_queries")["device"] == "ip:192.168.1.200"


def test_wan_counter_deltas_and_reset(monitor):
    s = monitor.store
    t0 = s.day_bounds(s.today())[0] + 60
    s.record_wan_counters(t0, 1000, 5000)
    assert s.record_wan_counters(t0 + 300, 1500, 9000) == (500, 4000)
    assert s.record_wan_counters(t0 + 600, 200, 300) == (200, 300)  # gateway rebooted
    row = s.query_one("SELECT * FROM wan_daily WHERE day = ?", (s.today(),))
    assert (row["bytes_up"], row["bytes_down"]) == (700, 4300)


def test_anomalies(monitor):
    monitor.feeds = None
    monitor.anomaly.feeds = None
    monitor.on_device(MAC, ip=IP, source="test")
    now = time.time()
    monitor.on_dns(IP, "xj4k9qzt2mplw8vr.com", "A", "NXDOMAIN", ts=now)
    monitor.on_dns(IP, "prize.top", "A", ts=now)
    monitor.on_dns(IP, "a" * 60 + ".tunnel.example.com", "TXT", ts=now)
    monitor.on_flow(IP, "45.33.32.156", 40000, 6667, "tcp", 100, ts=now)
    monitor.on_flow(IP, "8.8.8.8", 40000, 853, "tcp", 100, ts=now)
    cats = {r["category"] for r in monitor.store.query("SELECT category FROM alerts")}
    assert {"new_device", "dga_domain", "suspicious_tld", "dns_tunneling", "suspicious_port", "dns_bypass"} <= cats
    before = len(monitor.store.query("SELECT id FROM alerts"))
    monitor.on_dns(IP, "xj4k9qzt2mplw8vr.com", "A", "NXDOMAIN", ts=now)
    assert len(monitor.store.query("SELECT id FROM alerts")) == before  # de-duplicated


def test_traffic_spike(monitor):
    s = monitor.store
    monitor.on_device(MAC, ip=IP, source="test")
    today_start = s.day_bounds(s.today())[0]
    for d in range(1, 8):
        s.add_traffic(today_start - d * 86400 + 3600, IP, "1.1.1.1", 443, "tcp", 50 * 2**20, 10 * 2**20)
    s.add_traffic(time.time() - 60, IP, "1.1.1.1", 443, "tcp", 2 * 2**30, 10 * 2**20)
    s.flush()
    monitor.anomaly.run_periodic()
    alert = s.query_one("SELECT * FROM alerts WHERE category = 'traffic_spike'")
    assert alert and alert["severity"] == "high" and "upload" in alert["title"]


def test_feed_parsing(monitor, tmp_path):
    from netmon.feeds import ThreatFeeds
    domains, _ = ThreatFeeds.parse("# comment\n127.0.0.1 localhost\n127.0.0.1 evil.example.com\n", "hosts")
    assert domains == {"evil.example.com"}
    _, ips = ThreatFeeds.parse("1.2.3.4\nnot-an-ip\n", "ips")
    assert ips == {"1.2.3.4"}
    local = tmp_path / "blocklist.txt"
    local.write_text("bad.example.net\n")
    feeds = ThreatFeeds(tmp_path, [], [str(local)])
    feeds.load_cached()
    assert feeds.match_domain("cdn.bad.example.net") == "local:blocklist.txt"
    assert feeds.match_domain("example.net") is None


def _fake_upstream():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve():
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                return
            msg = dnsparse.parse(data)
            reply = bytearray(data)
            reply[2:4] = b"\x81\x80"
            reply[6:8] = b"\x00\x01"
            reply += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([93, 184, 216, 34])
            if msg.qname:
                sock.sendto(bytes(reply), addr)

    threading.Thread(target=serve, daemon=True).start()
    return sock


def test_dns_proxy_forwards_and_logs(monitor):
    upstream = _fake_upstream()
    proxy = DnsProxy(monitor, {"listen_host": "127.0.0.1", "listen_port": 0,
                               "upstream": ["127.0.0.1"], "timeout_seconds": 2})
    proxy.forwarder.upstreams = [upstream.getsockname()]
    proxy.start()
    port = proxy._servers[0].server_address[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    client.sendto(dnsparse.build_query("example.com", txid=0x4242), ("127.0.0.1", port))
    reply = dnsparse.parse(client.recv(4096))
    assert reply.txid == 0x4242 and reply.answers == ["93.184.216.34"]
    time.sleep(0.2)
    monitor.store.flush()
    row = monitor.store.query_one("SELECT * FROM dns_queries")
    assert row["domain"] == "example.com" and row["client_ip"] == "127.0.0.1"
    assert monitor.store.domain_for_ip("93.184.216.34") == "example.com"
    client.sendto(dnsparse.build_query("use-application-dns.net", txid=0x0101), ("127.0.0.1", port))
    assert dnsparse.parse(client.recv(4096)).rcode == "NXDOMAIN"
    proxy.stop()
    upstream.close()


def test_api_auth_and_endpoints(monitor):
    monitor.on_device(MAC, ip=IP, hostname="Roku-Ultra", source="test")
    monitor.on_dns(IP, "netflix.com", ts=time.time())
    monitor.store.flush()
    client = TestClient(create_app(monitor.store, auth=("admin", "s3cret")))
    assert client.get("/api/summary").status_code == 401
    assert client.get("/", headers={"Authorization": "Basic " + base64.b64encode(b"admin:nope").decode()}).status_code == 401
    good = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret").decode()}
    summary = client.get("/api/summary", headers=good).json()
    assert summary["devices"]["total"] == 1 and summary["dns"]["queries"] == 1
    assert client.get("/api/devices/not-a-mac", headers=good).status_code == 422
    resp = client.patch(f"/api/devices/{MAC}", json={"alias": "Living room Roku", "trusted": True}, headers=good)
    assert resp.status_code == 200 and resp.json()["alias"] == "Living room Roku"
    assert client.patch(f"/api/devices/{MAC}", json={"device_type": "rm -rf"}, headers=good).status_code == 400
    assert client.get("/api/export/sqlite_master.csv", headers=good).status_code == 404
    csv_text = client.get("/api/export/devices.csv", headers=good).text
    assert csv_text.startswith("mac,") and "Living room Roku" in csv_text
    domains = client.get("/api/domains", params={"search": "%"}, headers=good).json()
    assert domains == []  # LIKE wildcards are escaped
    assert client.get("/", headers=good).headers["content-security-policy"].startswith("default-src 'self'")
