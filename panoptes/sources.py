"""Offline sources: packet captures (pcap and pcapng, as Wireshark and tcpdump write them), Zeek's dns.log,
and plain lists of domain names. Each becomes the engine's Dns and Conn events."""

from __future__ import annotations

import ipaddress
import json
import struct
from pathlib import Path
from typing import Iterator

from . import wire
from .engine import Conn, Dns


class SourceError(ValueError):
    pass


# ── packets ──────────────────────────────────────────────────────────────────

def _l3(link: int, data: bytes) -> bytes | None:
    """The IP packet inside a frame of the given link type."""
    if link == 1:                                      # Ethernet, with optional VLAN tags
        if len(data) < 14:
            return None
        etype, off = struct.unpack_from("!H", data, 12)[0], 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype, off = struct.unpack_from("!H", data, off + 2)[0], off + 4
        return data[off:] if etype in (0x0800, 0x86DD) else None
    if link == 113:                                    # Linux cooked capture
        return data[16:] if len(data) > 16 and struct.unpack_from("!H", data, 14)[0] in (0x0800, 0x86DD) else None
    if link == 276:                                    # Linux cooked capture v2
        return data[20:] if len(data) > 20 else None
    if link in (101, 12, 228, 229):                    # raw IP
        return data
    if link == 0:                                      # BSD loopback
        return data[4:]
    return None


def _ip(pkt: bytes):
    """(src, dst, proto, payload) of an IPv4 or IPv6 packet."""
    if not pkt:
        return None
    v = pkt[0] >> 4
    if v == 4 and len(pkt) >= 20:
        ihl = (pkt[0] & 0xF) * 4
        if struct.unpack_from("!H", pkt, 6)[0] & 0x1FFF:          # a later fragment
            return None
        return str(ipaddress.IPv4Address(pkt[12:16])), str(ipaddress.IPv4Address(pkt[16:20])), pkt[9], pkt[ihl:]
    if v == 6 and len(pkt) >= 40:
        nxt, off = pkt[6], 40
        while nxt in (0, 43, 60) and len(pkt) >= off + 8:           # skip extension headers
            nxt, off = pkt[off], off + 8 + pkt[off + 1] * 8
        return str(ipaddress.IPv6Address(pkt[8:24])), str(ipaddress.IPv6Address(pkt[24:40])), nxt, pkt[off:]
    return None


def _frames(path: Path) -> Iterator[tuple[float, int, bytes]]:
    data = path.read_bytes()
    if len(data) < 24:
        raise SourceError(f"{path.name}: too short to be a capture")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        link = struct.unpack_from(e + "I", data, 20)[0] & 0x0FFFFFFF
        pos = 24
        while pos + 16 <= len(data):
            sec, frac, incl, _ = struct.unpack_from(e + "IIII", data, pos)
            pos += 16
            yield sec + frac / (1e9 if nano else 1e6), link, data[pos:pos + incl]
            pos += incl
        return
    if magic == b"\x0a\x0d\x0d\x0a":                  # pcapng
        pos, e, links, res = 0, "<", [], []
        while pos + 12 <= len(data):
            btype = struct.unpack_from(e + "I", data, pos)[0]
            if btype == 0x0A0D0D0A:
                e = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                links, res = [], []
            blen = struct.unpack_from(e + "I", data, pos + 4)[0]
            if blen < 12:
                break
            body = data[pos + 8:pos + blen - 4]
            if btype == 1:                                           # interface description
                links.append(struct.unpack_from(e + "H", body, 0)[0])
                res.append(1e6)
                k = 8
                while k + 4 <= len(body):                            # options: if_tsresol
                    code, ln = struct.unpack_from(e + "HH", body, k)
                    if code == 0:
                        break
                    if code == 9 and ln >= 1:
                        r = body[k + 4]
                        res[-1] = 2 ** (r & 0x7F) if r & 0x80 else 10 ** r
                    k += 4 + (ln + 3) // 4 * 4
            elif btype == 6 and len(body) >= 20:                      # enhanced packet
                iface, hi, lo, cap, _ = struct.unpack_from(e + "IIIII", body, 0)
                if iface < len(links):
                    yield ((hi << 32) | lo) / res[iface], links[iface], body[20:20 + cap]
            elif btype == 3 and links:                               # simple packet
                yield 0.0, links[0], body[4:]
            pos += blen
        return
    raise SourceError(f"{path.name}: not a pcap or pcapng capture")


def from_capture(path: Path) -> Iterator[Dns | Conn]:
    pending: dict[tuple, tuple[float, str, str]] = {}
    for ts, link, frame in _frames(path):
        pkt = _l3(link, frame)
        ip = _ip(pkt) if pkt else None
        if not ip:
            continue
        src, dst, proto, payload = ip
        if proto == 17 and len(payload) >= 8:
            sport, dport = struct.unpack_from("!HH", payload, 0)
            if 53 not in (sport, dport) and 5353 not in (sport, dport):
                continue
            try:
                m = wire.parse(payload[8:])
            except (wire.WireError, struct.error, ValueError):
                continue
            if not m.questions:
                continue
            name, qtype = m.questions[0]
            if not m.response:
                pending[(m.id, src, sport)] = (ts, name, qtype)
                continue
            asked = pending.pop((m.id, dst, dport), (ts, name, qtype))
            answers = [d for _, t, _, d in m.answers if t in ("A", "AAAA")]
            yield Dns(asked[0], name, qtype, answers, m.rcode)
        elif proto == 6 and len(payload) >= 20:
            sport, dport = struct.unpack_from("!HH", payload, 0)
            flags = payload[13]
            if flags & 0x02 and not flags & 0x10:                    # SYN without ACK: a new outbound connection
                yield Conn(ts, dst, dport, "tcp")
    for (_, _, _), (ts, name, qtype) in pending.items():           # queries that never got an answer
        yield Dns(ts, name, qtype, [], "NOANSWER")


# ── logs ─────────────────────────────────────────────────────────────────────

def from_zeek(path: Path) -> Iterator[Dns]:
    fields: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not fields:
            continue
        row = dict(zip(fields, line.split("\t")))
        answers = [a for a in row.get("answers", "-").split(",") if a not in ("-", "")]
        yield Dns(float(row.get("ts", 0) or 0), row.get("query", ""), row.get("qtype_name", "A"),
                  [a for a in answers if a.replace(".", "").replace(":", "").isalnum()], row.get("rcode_name", "NOERROR"))


def from_jsonl(path: Path) -> Iterator[Dns | Conn]:
    """panoptes' own --save format, one event per line."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        kind = d.pop("kind", "dns")
        yield Dns(**d) if kind == "dns" else Conn(**d)


def from_list(path: Path) -> Iterator[Dns]:
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        name = line.strip().split()[0] if line.strip() and not line.startswith("#") else ""
        if name:
            yield Dns(float(i), name)


def read(path: Path) -> Iterator[Dns | Conn]:
    head = path.read_bytes()[:4] if path.stat().st_size >= 4 else b""
    if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
        return from_capture(path)
    text = path.read_text(encoding="utf-8", errors="replace")[:4096]
    if text.startswith("#separator") or "#fields" in text:
        return from_zeek(path)
    if text.lstrip().startswith("{"):
        return from_jsonl(path)
    return from_list(path)
