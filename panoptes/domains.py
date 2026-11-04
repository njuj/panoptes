"""What a domain name looks like: its registrable part, how random it is, whether it carries encoded
data, and whether it belongs to a service malware is known to lean on."""

from __future__ import annotations

import math
import re
from collections import Counter

# Multi-label public suffixes common enough to matter; anything else is treated as a single-label TLD.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp",
    "co.kr", "or.kr", "com.br", "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg", "com.my", "co.in",
    "co.id", "co.za", "com.mx", "com.ar", "com.tr", "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa", "med.sa",
    "com.eg", "com.kw", "com.qa", "com.bh", "co.ae", "gov.ae", "com.pk", "com.ng", "com.ua", "co.il", "com.vn",
    "com.ph", "co.th", "in.th", "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net", "cloudapp.net",
    "blob.core.windows.net", "web.core.windows.net", "appspot.com", "firebaseapp.com", "web.app", "pages.dev",
    "workers.dev", "netlify.app", "vercel.app", "onrender.com", "fly.dev", "amazonaws.com", "cloudfront.net",
    "s3.amazonaws.com", "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
    "serveo.net", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "lhr.life",
}


def registrable(name: str) -> str:
    """example.co.uk for a.b.example.co.uk: the part someone actually registered."""
    labels = name.lower().rstrip(".").split(".")
    for take in (4, 3, 2):
        if len(labels) > take and ".".join(labels[-take:]) in MULTI_SUFFIXES:
            return ".".join(labels[-take - 1:])
    return ".".join(labels[-2:])


def subdomain(name: str) -> str:
    base = registrable(name)
    name = name.lower().rstrip(".")
    return name[:-len(base)].rstrip(".") if name != base else ""


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


# How common each letter pair is in English prose, 0 (never) to 9, row by first letter a..z. Learned from the
# comments and docstrings of the Python standard library (4.9 million letter pairs); random strings score low.
PAIRS = (
    "47875674736888273889776674746574326637437516657332628464843871774485476874406276568453843645743675744362"
    "86887765645878677998576864745476418026348317567133516343846772265654067564313382339333802544821657512152"
    "77877773536879874788471626511162214030025311505011205433734363252544346343513185579644824844851577755173"
    "86458523703664771465622143847886857466568644887642636778666364678977487887764583568445714734773767643271"
    "42122120101312110332711010856796748266778527777651717374855782667677548874536284659639824664762878746474"
    "66657562613878570888422412723183327012335213324122217234623780152674166321530164646423621352361337222641"
    "4454544351255667166743613351126223520332521222102134"
)
_A = "abcdefghijklmnopqrstuvwxyz"


def wordlike(label: str) -> float:
    """How much a label reads like language: about 6-8 for words and brand names, 2-5 for random strings."""
    s = re.sub(r"[^a-z]", "", label.lower())
    if len(s) < 2:
        return 9.0
    v = [int(PAIRS[_A.index(s[i]) * 26 + _A.index(s[i + 1])]) for i in range(len(s) - 1)]
    rare = sum(x <= 1 for x in v) / len(v)
    digits = sum(c.isdigit() for c in label) / len(label)
    return sum(v) / len(v) - 3.6 * rare - 3 * digits


def generated(label: str) -> bool:
    """A label long enough to judge that reads like noise (0 of 510 real site names, 83-87% of DGA output)."""
    return len(label) >= 8 and wordlike(label) < 5.2


BASE32 = re.compile(r"^[a-z2-7]+$")
HEX = re.compile(r"^[0-9a-f]+$")
B64ISH = re.compile(r"^[A-Za-z0-9_-]+$")


def encoded_payload(name: str) -> tuple[float, str] | None:
    """(strength 0..1, why) when the subdomain looks like data rather than a hostname."""
    sub = subdomain(name)
    if not sub:
        return None
    labels = [l for l in sub.split(".") if l]
    longest = max(labels, key=len)
    total = sum(len(l) for l in labels)
    ent = entropy("".join(labels))
    why = []
    s = 0.0
    if len(longest) >= 40:
        s += .45
        why.append(f"a {len(longest)}-character label")
    elif len(longest) >= 25:
        s += .25
        why.append(f"a {len(longest)}-character label")
    if total >= 60:
        s += .25
        why.append(f"{total} characters of subdomain")
    if HEX.match(longest) and len(longest) >= 16:
        s += .3
        why.append("hex-encoded")
    elif BASE32.match(longest) and len(longest) >= 20 and any(c.isdigit() for c in longest):
        s += .25
        why.append("base32-encoded")
    elif B64ISH.match(longest) and len(longest) >= 20 and any(c.isupper() for c in longest) and any(c.islower() for c in longest):
        s += .25
        why.append("base64-encoded")
    if ent >= 4.0 and total >= 20:
        s += .2
        why.append(f"entropy {ent:.1f} bits/char")
    return (min(1.0, s), ", ".join(why)) if s >= .45 else None


# Services malware leans on. Each entry: suffix -> (category, why)
SERVICES: dict[str, tuple[str, str]] = {}
for _suffixes, _cat, _why in [
    ("duckdns.org no-ip.org no-ip.com ddns.net hopto.org zapto.org sytes.net servebeer.com serveftp.com myftp.org "
     "dynu.net freedns.afraid.org mooo.com dyndns.org changeip.com 3utilities.com bounceme.net",
     "dynamic-dns", "dynamic DNS: a free name that follows a home IP, the classic address of a RAT's controller"),
    ("ngrok.io ngrok-free.app ngrok.app trycloudflare.com loca.lt serveo.net localhost.run lhr.life pinggy.link "
     "portmap.io playit.gg bore.pub", "tunnel",
     "a public tunnel into someone's machine: used to hide a controller behind a legitimate service"),
    ("api.telegram.org", "chat-api", "the Telegram bot API: stealers and RATs post stolen data and take commands here"),
    ("discord.com/api/webhooks discordapp.com/api/webhooks", "chat-api", "Discord webhooks: a favourite drop box for stolen data"),
    ("pastebin.com paste.ee hastebin.com rentry.co controlc.com ghostbin.co dpaste.org", "paste",
     "a paste site: malware fetches its next stage or its config here"),
    ("transfer.sh file.io anonfiles.com gofile.io temp.sh catbox.moe 0x0.st bashupload.com oshi.at", "file-drop",
     "an anonymous file drop: used to stage payloads and exfiltrate archives"),
    ("ip-api.com ipinfo.io api.ipify.org ipify.org icanhazip.com ifconfig.me checkip.amazonaws.com myexternalip.com "
     "ipwho.is wtfismyip.com ident.me geoplugin.net freegeoip.app api.myip.com", "ip-lookup",
     "a what-is-my-IP service: the first thing many stealers and RATs ask after infecting a machine"),
    ("tor2web.org onion.ws onion.pet onion.ly", "tor-gateway", "a gateway into Tor hidden services"),
    ("minexmr.com supportxmr.com nanopool.org 2miners.com hashvault.pro moneroocean.stream xmrpool.eu f2pool.com "
     "c3pool.com herominers.com unmineable.com", "mining-pool", "a cryptocurrency mining pool: the sign of a cryptominer"),
]:
    for _s in _suffixes.split():
        SERVICES[_s] = (_cat, _why)


def service(name: str) -> tuple[str, str] | None:
    name = name.lower().rstrip(".")
    for suffix, info in SERVICES.items():
        if "/" in suffix:
            continue
        if name == suffix or name.endswith("." + suffix):
            return info
    return None


# Big, well-known operators: periodic traffic to them is normal (telemetry, sync, keep-alives).
TRUSTED_BASES = set("""
microsoft.com windows.com windowsupdate.com live.com office.com office.net office365.com msftconnecttest.com msn.com
bing.com azure.com azureedge.net azurefd.net microsoftonline.com msedge.net skype.com xboxlive.com xbox.com sharepoint.com
onedrive.com outlook.com msauth.net msftauth.net gfx.ms visualstudio.com vsassets.io github.com githubusercontent.com
githubassets.com github.io google.com googleapis.com gstatic.com googleusercontent.com googlevideo.com youtube.com
ytimg.com ggpht.com gvt1.com gvt2.com doubleclick.net google-analytics.com googletagmanager.com chrome.com
android.com apple.com icloud.com mzstatic.com cdn-apple.com amazon.com amazonaws.com cloudfront.net akamai.net
akamaiedge.net akamaihd.net akamaized.net edgekey.net edgesuite.net cloudflare.com cloudflare-dns.com fastly.net
fastly.com discord.com discordapp.com discord.gg discordapp.net discord.media spotify.com scdn.co spotifycdn.com
steampowered.com steamcommunity.com steamstatic.com valvesoftware.com nvidia.com geforce.com anthropic.com claude.ai
claude.com openai.com chatgpt.com slack.com slack-edge.com zoom.us whatsapp.net whatsapp.com facebook.com fbcdn.net
instagram.com twitter.com x.com twimg.com reddit.com redd.it redditstatic.com mozilla.org mozilla.net firefox.com
digicert.com letsencrypt.org sectigo.com globalsign.com usertrust.com verisign.com pki.goog lencr.org
npmjs.org npmjs.com pypi.org pythonhosted.org python.org jsdelivr.net unpkg.com wikipedia.org wikimedia.org
adobe.com adobe.io epicgames.com riotgames.com ea.com ubisoft.com blizzard.com battle.net asus.com dell.com
hp.com lenovo.com intel.com amd.com logitech.com razer.com corsair.com elgato.com windhawk.net rivatuner.net
""".split())


def trusted(name: str) -> bool:
    """Run by one of the big operators: the name or any parent of it is on the list (CDN hostnames included)."""
    labels = name.lower().rstrip(".").split(".")
    return any(".".join(labels[i:]) in TRUSTED_BASES for i in range(len(labels) - 1))
