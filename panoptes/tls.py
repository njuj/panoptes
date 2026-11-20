"""TLS handshakes in captured traffic. Two things cross the wire before encryption starts: the server
name the client asks for (SNI, in every TLS version until Encrypted Client Hello) and, up to TLS 1.2,
the certificate the server answers with. The first names a destination even when DNS went over HTTPS;
the second gives away servers still using the certificate their RAT builder made."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_STREAM = 128 * 1024           # a handshake that has not finished by then is not one we can read

# Certificates RAT builders and C2 frameworks generate out of the box. Operators rarely replace them.
KNOWN_CERTS = (("asyncrat server", "AsyncRAT"), ("dcrat", "DcRat"), ("venomrat", "VenomRAT"),
               ("quasar server ca", "Quasar RAT"), ("major cobalt strike", "Cobalt Strike"),
               ("cobaltstrike", "Cobalt Strike"), ("advancedpentesting", "Cobalt Strike"))
COBALT_STRIKE_SERIAL = 146473198  # the serial of Cobalt Strike's default keystore certificate

OIDS = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O", b"\x55\x04\x0b": "OU", b"\x55\x04\x06": "C"}


@dataclass
class Cert:
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    serial: int = 0

    @property
    def self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer


def dn(names: dict[str, str]) -> str:
    return ", ".join(f"{k}={v}" for k, v in names.items())


def family(subject: str | None, issuer: str | None, serial: int | None) -> str | None:
    """The RAT or C2 framework whose default certificate this is, if any."""
    if serial == COBALT_STRIKE_SERIAL:
        return "Cobalt Strike"
    text = f"{subject or ''} {issuer or ''}".lower()
    return next((fam for needle, fam in KNOWN_CERTS if needle in text), None)


# ── DER, just enough for an X.509 name ────────────────────────────────────────

def _tlv(b: bytes, i: int) -> tuple[int, bytes, int]:
    if i + 2 > len(b):
        raise ValueError("truncated DER")
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or i + k > len(b):
            raise ValueError("bad DER length")
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    if i + n > len(b):
        raise ValueError("DER runs past its container")
    return tag, b[i:i + n], i + n


def _children(b: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(b) and len(out) < 64:
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def _name(seq: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for _, rdn in _children(seq):
        for _, atv in _children(rdn):
            parts = _children(atv)
            if len(parts) == 2 and parts[0][0] == 0x06 and parts[0][1] in OIDS:
                raw = parts[1][1]
                text = raw.decode("utf-16-be", "replace") if parts[1][0] == 0x1E else raw.decode("utf-8", "replace")
                out.setdefault(OIDS[parts[0][1]], text)
    return out


def parse_cert(der: bytes) -> Cert:
    _, cert, _ = _tlv(der, 0)
    _, tbs, _ = _tlv(cert, 0)
    parts = _children(tbs)
    if parts and parts[0][0] == 0xA0:                 # explicit version
        parts = parts[1:]
    if len(parts) < 5 or parts[0][0] != 0x02:
        raise ValueError("not an X.509 certificate")
    return Cert(_name(parts[4][1]), _name(parts[2][1]), int.from_bytes(parts[0][1], "big", signed=True))


# ── handshake messages ───────────────────────────────────────────────────────

def sni(hello: bytes) -> str | None:
    """The server name in a ClientHello body."""
    i = 34                                            # version + random
    try:
        i += 1 + hello[i]                             # session id
        i += 2 + struct.unpack_from("!H", hello, i)[0]  # cipher suites
        i += 1 + hello[i]                             # compression
        end = i + 2 + struct.unpack_from("!H", hello, i)[0]
        i += 2
        while i + 4 <= min(end, len(hello)):
            etype, elen = struct.unpack_from("!HH", hello, i)
            if etype == 0 and elen >= 5 and hello[i + 6] == 0:     # server_name, host_name
                n = struct.unpack_from("!H", hello, i + 7)[0]
                name = hello[i + 9:i + 9 + n].decode("ascii", "replace").lower().rstrip(".")
                return name or None
            i += 4 + elen
    except (IndexError, struct.error):
        pass
    return None


def leaf_cert(body: bytes) -> Cert | None:
    """The first (server's own) certificate of a TLS 1.0-1.2 Certificate message."""
    if len(body) < 6:
        return None
    n = int.from_bytes(body[3:6], "big")
    try:
        return parse_cert(body[6:6 + n])
    except ValueError:
        return None


@dataclass
class Stream:
    """One direction of one TCP connection, read until its handshake is over."""
    data: bytearray = field(default_factory=bytearray)
    hs: bytearray = field(default_factory=bytearray)  # handshake bytes gathered from the records
    pos: int = 0                                      # next unread record
    done: bool = False

    def feed(self, chunk: bytes) -> list[tuple[int, bytes]]:
        """Add stream bytes; returns the complete handshake messages (type, body) they finished."""
        if self.done:
            return []
        self.data += chunk
        while self.pos + 5 <= len(self.data):
            ctype, _, length = struct.unpack_from("!BHH", self.data, self.pos)
            if ctype != 22:                           # ChangeCipherSpec, alert or data: the clear part is over
                self.done = True
                break
            if self.pos + 5 + length > len(self.data):
                break
            self.hs += self.data[self.pos + 5:self.pos + 5 + length]
            self.pos += 5 + length
        out = []
        while len(self.hs) >= 4:
            n = int.from_bytes(self.hs[1:4], "big")
            if len(self.hs) < 4 + n:
                break
            out.append((self.hs[0], bytes(self.hs[4:4 + n])))
            del self.hs[:4 + n]
        if len(self.data) > MAX_STREAM:
            self.done = True
        return out
