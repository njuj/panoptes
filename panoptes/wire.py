"""DNS messages on the wire (RFC 1035): enough to read queries and answers out of packets, and to
write the sinkhole's replies."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
         65: "HTTPS", 64: "SVCB", 255: "ANY"}
TYPE_IDS = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class WireError(ValueError):
    pass


@dataclass
class Message:
    id: int
    response: bool
    rcode: str
    questions: list[tuple[str, str]] = field(default_factory=list)     # (name, type)
    answers: list[tuple[str, str, int, str]] = field(default_factory=list)   # (name, type, ttl, data)


def _name(buf: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels, end = [], None
    while True:
        if pos >= len(buf):
            raise WireError("name runs past the message")
        n = buf[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if depth > 10 or pos + 1 >= len(buf):
                raise WireError("bad compression pointer")
            ptr = ((n & 0x3F) << 8) | buf[pos + 1]
            if end is None:
                end = pos + 2
            sub, _ = _name(buf, ptr, depth + 1)
            labels.append(sub)
            pos = end
            return ".".join(l for l in labels if l), pos
        labels.append(buf[pos + 1:pos + 1 + n].decode("latin-1"))
        pos += 1 + n
    return ".".join(labels), end if end is not None else pos


def parse(buf: bytes) -> Message:
    if len(buf) < 12:
        raise WireError("shorter than a DNS header")
    mid, flags, qd, an, _, _ = struct.unpack_from("!HHHHHH", buf, 0)
    m = Message(mid, bool(flags & 0x8000), RCODES.get(flags & 0xF, str(flags & 0xF)))
    pos = 12
    for _ in range(min(qd, 16)):
        name, pos = _name(buf, pos)
        qtype, _ = struct.unpack_from("!HH", buf, pos)
        pos += 4
        m.questions.append((name, TYPES.get(qtype, str(qtype))))
    for _ in range(min(an, 64)):
        name, pos = _name(buf, pos)
        rtype, _, ttl, rdlen = struct.unpack_from("!HHIH", buf, pos)
        pos += 10
        rdata = buf[pos:pos + rdlen]
        t = TYPES.get(rtype, str(rtype))
        if t == "A" and rdlen == 4:
            data = str(ipaddress.IPv4Address(rdata))
        elif t == "AAAA" and rdlen == 16:
            data = str(ipaddress.IPv6Address(rdata))
        elif t in ("CNAME", "PTR", "NS"):
            data, _ = _name(buf, pos)
        elif t == "TXT":
            parts, k = [], 0
            while k < len(rdata):
                parts.append(rdata[k + 1:k + 1 + rdata[k]].decode("latin-1"))
                k += 1 + rdata[k]
            data = "".join(parts)
        else:
            data = rdata.hex()
        m.answers.append((name, t, ttl, data))
        pos += rdlen
    return m


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("latin-1")
        if not 0 < len(raw) < 64:
            raise WireError(f"bad label {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def query(name: str, qtype: str = "A", mid: int = 0x1234) -> bytes:
    return struct.pack("!HHHHHH", mid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", TYPE_IDS.get(qtype, 1), 1)


def reply(request: bytes, *, ipv4: str | None = None, ipv6: str | None = None, rcode: int = 0, ttl: int = 60) -> bytes:
    """An answer to `request`: one A or AAAA record when given, or just the rcode (NXDOMAIN = 3)."""
    m = parse(request)
    qend = 12
    for _ in m.questions:
        _, qend = _name(request, qend)
        qend += 4
    question = request[12:qend]
    answers = b""
    if m.questions and rcode == 0:
        qtype = m.questions[0][1]
        if qtype in ("A", "ANY") and ipv4:
            answers = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + ipaddress.IPv4Address(ipv4).packed
        elif qtype == "AAAA" and ipv6:
            answers = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, ttl, 16) + ipaddress.IPv6Address(ipv6).packed
    flags = 0x8180 | (rcode & 0xF)                     # response, recursion desired + available
    return struct.pack("!HHHHHH", m.id, flags, len(m.questions), 1 if answers else 0, 0, 0) + question + answers
