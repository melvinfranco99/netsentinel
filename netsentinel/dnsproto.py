"""Construcción y parseo mínimo de paquetes DNS / mDNS."""

import random
import struct

T_A, T_PTR, T_TXT, T_AAAA, T_SRV, T_ANY = 1, 12, 16, 28, 33, 255


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_query(name: str, qtype: int, qclass: int = 1, rd: bool = True,
                unicast_response: bool = False, tid: int | None = None) -> bytes:
    tid = random.randint(0, 0xFFFF) if tid is None else tid
    flags = 0x0100 if rd else 0
    hdr = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    if unicast_response:
        qclass |= 0x8000
    return hdr + encode_name(name) + struct.pack(">HH", qtype, qclass)


def _read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped = False
    end = off
    while True:
        if off >= len(data) or depth > 20:
            raise ValueError("nombre DNS inválido")
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        off += 1
        labels.append(data[off:off + ln].decode("utf-8", "replace"))
        off += ln
    return ".".join(labels), (end if jumped else off)


def parse(data: bytes) -> dict:
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    records = []
    for i in range(an + ns + ar):
        name, off = _read_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rec = {"name": name, "type": rtype, "section": "an" if i < an else ("ns" if i < an + ns else "ar")}
        try:
            if rtype == T_A and rdlen == 4:
                rec["value"] = ".".join(str(b) for b in rdata)
            elif rtype == T_PTR:
                rec["value"], _ = _read_name(data, off)
            elif rtype == T_SRV:
                prio, weight, port = struct.unpack(">HHH", rdata[:6])
                target, _ = _read_name(data, off + 6)
                rec["value"] = {"port": port, "target": target}
            elif rtype == T_TXT:
                items, p = [], 0
                while p < len(rdata):
                    ln = rdata[p]
                    items.append(rdata[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                    p += 1 + ln
                rec["value"] = items
            else:
                rec["value"] = rdata
        except (ValueError, struct.error):
            rec["value"] = None
        records.append(rec)
        off += rdlen
    return {"id": tid, "flags": flags, "rcode": flags & 0xF, "ra": bool(flags & 0x80),
            "ancount": an, "records": records}


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
