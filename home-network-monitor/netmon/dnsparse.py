"""Minimal, defensive DNS wire-format parser (RFC 1035).

Only what the monitor needs: the question name/type, the response code and
A/AAAA/CNAME answers. Every read is bounds-checked; malformed packets raise
``DnsParseError`` instead of crashing a collector.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
          33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DnsParseError(ValueError):
    pass


@dataclass
class DnsMessage:
    txid: int
    is_response: bool
    rcode: str
    qname: str
    qtype: str
    answers: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end_offset = offset
    hops = 0
    while True:
        if offset >= len(data):
            raise DnsParseError("name runs past end of packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsParseError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            hops += 1
            if hops > 32 or pointer >= len(data):
                raise DnsParseError("bad compression pointer")
            offset = pointer
            continue
        if length & 0xC0:
            raise DnsParseError("unsupported label type")
        offset += 1
        if length == 0:
            break
        if offset + length > len(data):
            raise DnsParseError("label runs past end of packet")
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
        if sum(len(label) + 1 for label in labels) > 255:
            raise DnsParseError("name too long")
    return ".".join(labels), (end_offset if jumped else offset)


def parse(data: bytes) -> DnsMessage:
    if len(data) < 12:
        raise DnsParseError("packet shorter than DNS header")
    txid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    is_response = bool(flags & 0x8000)
    rcode = RCODES.get(flags & 0x000F, str(flags & 0x000F))
    if qdcount < 1:
        raise DnsParseError("no question section")
    offset = 12
    qname, offset = _read_name(data, offset)
    if offset + 4 > len(data):
        raise DnsParseError("truncated question")
    qtype_num, _qclass = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4
    for _ in range(qdcount - 1):
        _, offset = _read_name(data, offset)
        offset += 4

    msg = DnsMessage(txid, is_response, rcode, qname.lower(), QTYPES.get(qtype_num, str(qtype_num)))
    if not is_response:
        return msg

    for _ in range(min(ancount, 100)):
        _name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_end = offset + rdlength
        if rdata_end > len(data):
            break
        if rtype == 1 and rdlength == 4:
            msg.answers.append(str(ipaddress.IPv4Address(data[offset:rdata_end])))
        elif rtype == 28 and rdlength == 16:
            msg.answers.append(str(ipaddress.IPv6Address(data[offset:rdata_end])))
        elif rtype == 5:
            cname, _ = _read_name(data, offset)
            msg.cnames.append(cname.lower())
        offset = rdata_end
    return msg


def build_query(qname: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    """Build a simple recursive query (used by tests and health checks)."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    body = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.strip(".").split(".")) + b"\x00"
    return header + body + struct.pack("!HH", qtype, 1)


def _error_response(query: bytes, rcode: int) -> bytes | None:
    if len(query) < 12:
        return None
    txid, flags = struct.unpack("!HH", query[:4])
    new_flags = 0x8000 | (flags & 0x0100) | 0x0080 | rcode
    return struct.pack("!HH", txid, new_flags) + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]


def build_servfail(query: bytes) -> bytes | None:
    """Turn a query into a SERVFAIL response so clients fail fast."""
    return _error_response(query, 2)


def build_nxdomain(query: bytes) -> bytes | None:
    return _error_response(query, 3)
