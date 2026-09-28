"""Extract the Server Name Indication (SNI) hostname from a TLS ClientHello."""

from __future__ import annotations

import struct


def extract_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, client_version, random
        sid_len = payload[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0 and pos + 5 <= end:
                name_type = payload[pos + 2]
                name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                if name_type == 0 and pos + 5 + name_len <= end:
                    return payload[pos + 5:pos + 5 + name_len].decode("ascii", errors="replace").lower()
                return None
            pos += ext_len
    except (IndexError, struct.error):
        return None
    return None
