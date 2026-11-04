"""Traffic for the tests: the shapes real malware leaves in DNS and connection logs, and the normal traffic
that must stay quiet. Nothing here talks to the network; captures are written as pcap bytes."""

from __future__ import annotations

import hashlib
import random
import string
import struct

from panoptes.engine import Conn, Dns
from panoptes import wire

BENIGN = """google.com www.youtube.com facebook.com en.wikipedia.org amazon.com x.com www.instagram.com www.linkedin.com
netflix.com login.microsoftonline.com apple.com yahoo.com www.reddit.com bing.com web.whatsapp.com tiktok.com zoom.us
outlook.office.com chatgpt.com github.com stackoverflow.com www.cloudflare.com adobe.com dropbox.com open.spotify.com
twitch.tv discord.com pinterest.com ebay.com paypal.com walmart.com booking.com airbnb.com nytimes.com cnn.com bbc.co.uk
theguardian.com weather.com imdb.com quora.com medium.com wordpress.com tumblr.com shopify.com salesforce.com oracle.com
ibm.com intel.com nvidia.com samsung.com aliexpress.com baidu.com yandex.ru vk.com web.telegram.org signal.org mozilla.org
duckduckgo.com proton.me gitlab.com bitbucket.org atlassian.net notion.so figma.com canva.com slack.com trello.com
stripe.com coinbase.com binance.com etsy.com indeed.com espn.com steampowered.com epicgames.com roblox.com minecraft.net
store.playstation.com xbox.com hulu.com disneyplus.com vimeo.com soundcloud.com uber.com expedia.com tripadvisor.com
aljazeera.net alarabiya.net sabq.org okaz.com.sa alriyadh.com stcpay.com.sa mobily.com.sa absher.sa noon.com jarir.com
haraj.com.sa www.gov.sa my.gov.sa tawakkalna.sdaia.gov.sa pypi.org files.pythonhosted.org registry.npmjs.org
update.googleapis.com clients4.google.com fonts.gstatic.com i.ytimg.com rr3---sn-4g5edn7y.googlevideo.com
settings-win.data.microsoft.com v10.events.data.microsoft.com ctldl.windowsupdate.com edge.microsoft.com
ocsp.digicert.com r3.o.lencr.org api.anthropic.com claude.ai cdn.discordapp.com gateway.discord.gg
d1a2b3c4d5e6f7.cloudfront.net s3.us-east-1.amazonaws.com a1234.dscb.akamai.net static.xx.fbcdn.net""".split()


def dga_cryptolocker(seed: int, n: int) -> list[str]:
    """Random-letter names under a handful of TLDs, as CryptoLocker-era DGAs produced."""
    r = random.Random(seed)
    return ["".join(r.choice(string.ascii_lowercase) for _ in range(r.randint(12, 18))) + r.choice([".com", ".net", ".org", ".biz", ".ru"])
            for _ in range(n)]


def dga_md5(seed: int, n: int) -> list[str]:
    """Hex digests as names, as hash-based DGAs produce."""
    return [hashlib.md5(f"{seed}-{i}".encode()).hexdigest()[:16] + ".info" for i in range(n)]


def tunnel_dnscat(secret: bytes, domain: str = "c2.example-cdn.net") -> list[str]:
    """Hex-encoded chunks of data in the leftmost label, one query per chunk (dnscat2's shape)."""
    hexd = secret.hex()
    return [f"{hexd[i:i + 60]}.{domain}" for i in range(0, len(hexd), 60)]


def tunnel_iodine(secret: bytes, domain: str = "t.tunnel-host.org") -> list[str]:
    import base64
    b32 = base64.b32encode(secret).decode().lower().rstrip("=")
    return [f"{b32[i:i + 52]}.{domain}" for i in range(0, len(b32), 52)]


def beacon(start: float, every: float, n: int, jitter: float = 0.0, seed: int = 9) -> list[float]:
    r = random.Random(seed)
    return [start + i * every + r.uniform(-jitter, jitter) * every for i in range(n)]


# ── a capture file, written byte by byte ──────────────────────────────────────

def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    import ipaddress
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return hdr + payload


def _eth(pkt: bytes) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + pkt


def udp(src, sport, dst, dport, data):
    return _eth(_ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data))


def syn(src, sport, dst, dport):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x02, 65535, 0, 0)
    return _eth(_ipv4(src, dst, 6, tcp))


def pcap(frames: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, f in frames:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(f), len(f)) + f
    return out


def lookup_frames(ts: float, name: str, answer: str | None, mid: int, client="192.168.1.20", sport=50000, server="192.168.1.1"):
    q = wire.query(name, "A", mid)
    r = wire.reply(q, ipv4=answer) if answer else wire.reply(q, rcode=3)
    return [(ts, udp(client, sport, server, 53, q)), (ts + .02, udp(server, 53, client, sport, r))]
