from __future__ import annotations

import struct

import pytest

from netmon import dnsparse
from netmon.collectors.att_gateway import parse_devices, parse_wan_counters
from netmon.collectors.discovery import read_proc_arp
from netmon.collectors.netflow import parse_v5
from netmon.devices import OuiDatabase, guess_device_type, normalize_mac
from netmon.domains import base_domain, dga_score, normalize
from netmon.tls import extract_sni

from .conftest import FIXTURES


def _dns_response(qname: str, ips: list[str], rcode: int = 0, cname: str | None = None) -> bytes:
    query = dnsparse.build_query(qname)
    answers = b""
    count = 0
    if cname:
        target = b"".join(bytes([len(p)]) + p.encode() for p in cname.split(".")) + b"\x00"
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        count += 1
    for ip in ips:
        answers += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(o) for o in ip.split("."))
        count += 1
    header = struct.pack("!HHHHHH", 0x1234, 0x8180 | rcode, 1, count, 0, 0)
    return header + query[12:] + answers


def test_dns_parse_query_and_response():
    q = dnsparse.parse(dnsparse.build_query("www.Example.com", qtype=28))
    assert (q.qname, q.qtype, q.is_response) == ("www.example.com", "AAAA", False)
    r = dnsparse.parse(_dns_response("netflix.com", ["1.2.3.4", "5.6.7.8"], cname="edge.nflx.net"))
    assert r.is_response and r.rcode == "NOERROR"
    assert r.answers == ["1.2.3.4", "5.6.7.8"]
    assert r.cnames == ["edge.nflx.net"]
    assert dnsparse.parse(_dns_response("nope.invalid", [], rcode=3)).rcode == "NXDOMAIN"


@pytest.mark.parametrize("packet", [b"", b"\x00" * 11, b"\x12\x34\x01\x00\x00\x01" + b"\x00" * 6 + b"\xc0\x0c",
                                    b"\x12\x34\x01\x00\x00\x01" + b"\x00" * 6 + b"\x3fabc"])
def test_dns_parse_rejects_garbage(packet):
    with pytest.raises(dnsparse.DnsParseError):
        dnsparse.parse(packet)


def test_servfail_keeps_id_and_question():
    q = dnsparse.build_query("example.org", txid=0xBEEF)
    msg = dnsparse.parse(dnsparse.build_servfail(q))
    assert msg.txid == 0xBEEF and msg.rcode == "SERVFAIL" and msg.qname == "example.org"


def _client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_tls_sni():
    assert extract_sni(_client_hello("api.Example.com")) == "api.example.com"
    assert extract_sni(b"\x16\x03\x01\x00") is None
    assert extract_sni(b"GET / HTTP/1.1\r\n") is None


def test_netflow_v5():
    header = struct.pack("!HHIIIIBBH", 5, 1, 100000, 1_800_000_000, 0, 1, 0, 0, 0)
    record = struct.pack("!IIIHHIIIIHHBBBBHHBBH",
                         0xC0A80140, 0x08080808, 0, 1, 2, 10, 1500, 90000, 99000, 51000, 443,
                         0, 0x18, 6, 0, 0, 0, 24, 0, 0)
    ts, flows = parse_v5(header + record)
    assert ts == 1_800_000_000
    assert flows[0]["src"] == "192.168.1.64" and flows[0]["dst"] == "8.8.8.8"
    assert flows[0]["bytes"] == 1500 and flows[0]["proto"] == "tcp" and flows[0]["dport"] == 443
    with pytest.raises(ValueError):
        parse_v5(header)


def test_att_device_list():
    devices = parse_devices((FIXTURES / "att_devices.html").read_text())
    assert [d["mac"].lower() for d in devices] == ["8c:85:90:1a:2b:01", "b0:a7:37:5d:90:05", "da:a1:19:5e:22:c1"]
    assert devices[0]["hostname"] == "Dads-MacBook-Pro" and devices[0]["ip"] == "192.168.1.64"
    assert devices[1]["status"] == "off"
    assert "hostname" not in devices[2]
    assert "5 GHz" in devices[0]["connection"]


def test_att_wan_counters():
    assert parse_wan_counters((FIXTURES / "att_broadband.html").read_text()) == (52_331_998_120, 412_009_773_551)
    assert parse_wan_counters("<table><tr><th>Line State</th><td>Up</td></tr></table>") is None


def test_proc_arp(tmp_path):
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.254    0x1         0x2         e0:37:17:aa:bb:cc     *        eth0\n"
        "192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0\n")
    assert read_proc_arp(str(arp)) == [("192.168.1.254", "e0:37:17:aa:bb:cc")]


def test_dnsmasq_leases(tmp_path):
    from netmon.collectors.discovery import read_dnsmasq_leases
    leases = tmp_path / "leases"
    leases.write_text("1790600000 b0:a7:37:5d:90:05 192.168.1.68 Roku-Ultra 01:b0:a7:37:5d:90:05\n"
                      "1790600000 da:a1:19:5e:22:c1 192.168.1.90 * *\n")
    assert read_dnsmasq_leases(str(leases)) == [("192.168.1.68", "b0:a7:37:5d:90:05", "Roku-Ultra"),
                                                ("192.168.1.90", "da:a1:19:5e:22:c1", None)]


def test_domains():
    assert normalize("WWW.Example.COM.") == "www.example.com"
    assert normalize("bad domain.com") is None
    assert base_domain("a.b.bbc.co.uk") == "bbc.co.uk"
    assert base_domain("d1x2y3.cloudfront.net") == "d1x2y3.cloudfront.net"
    assert base_domain("r3---sn-ab5l6nrz.googlevideo.com") == "googlevideo.com"


@pytest.mark.parametrize("name,expected", [
    ("xj4k9qzt2mplw8vr.com", True), ("qpz7x2kfm9wltrbn.net", True),
    ("www.google.com", False), ("r3---sn-ab5l6nrz.googlevideo.com", False),
    ("scontent.cdninstagram.com", False), ("stackoverflow.com", False), ("d3kjh2l4k5j6.cloudfront.net", False),
    ("samsungcloudsolution.com", False), ("transport01.rts18.iad01.production.nest.com", False),
])
def test_dga(name, expected):
    assert dga_score(name)[0] is expected


def test_device_identification():
    oui = OuiDatabase()
    assert normalize_mac("b0-a7-37-5d-90-05") == "B0:A7:37:5D:90:05"
    assert oui.vendor("B0:A7:37:5D:90:05") == "Roku"
    assert oui.vendor("DA:A1:19:5E:22:C1") == "Randomized MAC"
    assert guess_device_type("Roku-Ultra", "Roku") == "tv/streaming"
    assert guess_device_type("Moms-iPhone", None) == "phone"
    assert guess_device_type(None, "Ring") == "camera/doorbell"
    assert guess_device_type("ESP_3A1F22", "Espressif (IoT)") == "iot"
    assert guess_device_type(None, None) == "unknown"
