"""The watcher's judgement: DNS queries and outbound connections go in, alerts come out.

Every source (a live Windows machine, the sinkhole, a pcap, a log) is turned into the same two events,
so the same rules run on all of them. Some rules look at one event (a dynamic-DNS name, a mining
pool); others need memory (a beacon, a burst of failed lookups, a domain receiving encoded data).
"""

from __future__ import annotations

import ipaddress
import ntpath
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field

from . import domains as D

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Dns:
    ts: float
    name: str
    qtype: str = "A"
    answers: list[str] = field(default_factory=list)
    rcode: str = "NOERROR"              # NOERROR, NXDOMAIN, SERVFAIL...
    pid: int | None = None
    process: str | None = None          # full path when known


@dataclass
class Conn:
    ts: float
    ip: str
    port: int
    proto: str = "tcp"
    pid: int | None = None
    process: str | None = None


@dataclass
class Alert:
    severity: str
    rule: str
    title: str
    detail: str
    process: str | None
    pid: int | None
    target: str
    first: float
    last: float
    count: int = 1
    technique: str | None = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


# default ports of well-known RATs and post-exploitation frameworks
RAT_PORTS = {1604: "DarkComet", 5552: "njRAT", 1177: "njRAT", 4782: "Quasar RAT", 2404: "Remcos", 6606: "AsyncRAT",
             7707: "AsyncRAT", 8808: "AsyncRAT", 3460: "Poison Ivy", 4444: "Metasploit / Meterpreter", 5650: "Warzone RAT",
             50050: "Cobalt Strike team server", 1337: "commonly used backdoor port", 31337: "Back Orifice",
             6667: "IRC (botnet command channel)", 6697: "IRC over TLS (botnet command channel)", 9001: "Tor relay",
             9050: "Tor SOCKS", 9150: "Tor Browser SOCKS"}
# Windows' own programs that attackers use to download and run code ("living off the land")
LOLBINS = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
           "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe",
           "msiexec.exe", "hh.exe", "forfiles.exe", "wmic.exe", "curl.exe", "finger.exe"}
CHAT_CLIENTS = {"telegram.exe", "ayugram.exe", "kotatogram.exe", "discord.exe", "discordptb.exe", "discordcanary.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "arc.exe", "iexplore.exe"}


def proc_name(path: str | None) -> str:
    return ntpath.basename(path).lower() if path else ""


def odd_location(path: str | None) -> str | None:
    """Why a program's location is unusual for software that talks to the internet."""
    if not path:
        return None
    p = path.lower().replace("/", "\\")
    if "\\appdata\\local\\temp\\" in p or "\\windows\\temp\\" in p:
        return "runs from a temp folder"
    if "\\downloads\\" in p:
        return "runs from Downloads"
    if "\\users\\public\\" in p or "\\programdata\\" in p and p.count("\\") <= 3:
        return "runs from a shared folder"
    if "\\appdata\\roaming\\" in p and p.count("\\") <= 5:
        return "runs from the top of AppData\\Roaming"
    if "$recycle.bin" in p or "\\perflogs\\" in p:
        return "runs from a folder programs never live in"
    return None


def bump(sev: str, steps: int = 1) -> str:
    return SEVERITIES[max(0, RANK[sev] - steps)]


def public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


class Engine:
    def __init__(self, *, dns_visible: bool = True, local_suffixes: tuple[str, ...] = ()):
        self.dns_visible = dns_visible            # can we see lookups? (if not, "no lookup first" means nothing)
        self.local = (".local", ".lan", ".arpa", ".home", ".internal", ".localdomain") + tuple("." + s for s in local_suffixes)
        self.alerts: dict[tuple, Alert] = {}
        self.ip_names: dict[str, str] = {}
        self.encoded: dict[str, set[str]] = defaultdict(set)        # base domain -> distinct encoded subdomains
        self.subs: dict[str, set[str]] = defaultdict(set)           # base domain -> distinct subdomains
        self.txt: dict[str, int] = defaultdict(int)
        self.nx: dict[str, deque] = defaultdict(deque)              # process -> recent NXDOMAIN (ts, name)
        self.gib: dict[str, set[str]] = defaultdict(set)            # process -> gibberish names
        self.contacts: dict[tuple, list[float]] = defaultdict(list)  # (process, target) -> timestamps
        self.events = 0
        self.new: list[Alert] = []

    # ── bookkeeping ──────────────────────────────────────────────────────────
    def _raise(self, sev, rule, title, detail, ev, target, technique=None, key=None):
        proc = ev.process or (f"pid {ev.pid}" if ev.pid else None)
        why = odd_location(ev.process)
        if why and RANK[sev] > RANK["critical"]:
            sev = bump(sev)
            detail += f"; the program {why}"
        k = key or (rule, proc_name(ev.process) or ev.pid, target)
        a = self.alerts.get(k)
        if a:
            a.count += 1
            a.last = ev.ts
            a.title, a.detail = title, detail                # the latest picture (counts grow)
            if RANK[sev] < RANK[a.severity]:
                a.severity = sev
                self.new.append(a)
            return a
        a = Alert(sev, rule, title, detail, proc, ev.pid, target, ev.ts, ev.ts, technique=technique)
        self.alerts[k] = a
        self.new.append(a)
        return a

    def feed(self, ev) -> list[Alert]:
        self.new = []
        self.events += 1
        if isinstance(ev, Dns):
            self._dns(ev)
        else:
            self._conn(ev)
        return self.new

    # ── DNS ──────────────────────────────────────────────────────────────────
    def _dns(self, ev: Dns):
        name = ev.name.lower().rstrip(".")
        if not name or "." not in name or name.endswith(self.local):
            return
        for ip in ev.answers:
            self.ip_names[ip] = name
        base = D.registrable(name)
        sub = D.subdomain(name)
        pname = proc_name(ev.process)
        trusted = D.trusted(name)

        svc = D.service(name)
        if svc:
            cat, why = svc
            sev = {"dynamic-dns": "high", "tunnel": "high", "tor-gateway": "high", "mining-pool": "critical",
                   "chat-api": "medium", "paste": "medium", "file-drop": "medium", "ip-lookup": "medium"}[cat]
            if cat == "chat-api" and pname in CHAT_CLIENTS:
                sev = "info"
            if cat in ("ip-lookup", "paste", "file-drop", "chat-api") and pname and pname not in BROWSERS and pname not in CHAT_CLIENTS:
                sev = bump(sev)                     # a background program, not a person in a browser
            tech = {"dynamic-dns": "T1568", "tunnel": "T1572", "mining-pool": "T1496", "ip-lookup": "T1016",
                    "chat-api": "T1102", "paste": "T1102", "file-drop": "T1567", "tor-gateway": "T1090.003"}[cat]
            self._raise(sev, cat, f"{name}: {cat.replace('-', ' ')}", why, ev, name, tech)

        if not trusted:
            enc = D.encoded_payload(name)
            if enc:
                strength, why = enc
                self.encoded[base].add(sub)
                n = len(self.encoded[base])
                sev = "critical" if n >= 5 else "high" if strength >= .7 or n >= 2 else "medium"
                self._raise(sev, "dns-exfil", f"Data hidden in DNS names sent to {base}",
                            f"{n} distinct encoded subdomain{'s' if n > 1 else ''} ({why}): DNS tunneling or exfiltration "
                            f"(dnscat2, iodine and most stealers' DNS channels look like this)", ev, base, "T1048.003",
                            key=("dns-exfil", base))
            if sub:
                self.subs[base].add(sub)
                if len(self.subs[base]) == 200:
                    self._raise("high", "dns-exfil", f"Hundreds of unique names under {base}",
                                f"{len(self.subs[base])} distinct subdomains: a channel that encodes data in each name",
                                ev, base, "T1048.003", key=("dns-volume", base))
            if ev.qtype in ("TXT", "NULL", "ANY") and not trusted:
                self.txt[base] += 1
                if self.txt[base] == 10:
                    self._raise("high", "dns-c2", f"Repeated {ev.qtype} lookups for {base}",
                                f"{self.txt[base]} {ev.qtype} queries: commands and payloads ride in TXT records", ev, base, "T1071.004",
                                key=("txt", base))
            label = base.split(".")[0]
            if D.generated(label):
                g = D.wordlike(label)
                who = pname or "?"
                self.gib[who].add(base)
                k = len(self.gib[who])
                sev = "high" if k >= 3 or ev.rcode == "NXDOMAIN" else "medium" if k >= 2 else "low"
                if pname in BROWSERS:
                    sev = "low"                          # people visit odd names; DGAs run in background programs
                self._raise(sev, "dga", f"Machine-generated domain names{' from ' + pname if pname else ''}",
                            f"{k} random-looking domain{'s' if k > 1 else ''}, latest {name} (reads like language {g:.1f}/9): domain generation "
                            f"algorithms let malware find its controller", ev, who, "T1568.002", key=("dga", who))

        if ev.rcode == "NXDOMAIN" and not trusted:
            who = pname or "?"
            q = self.nx[who]
            q.append((ev.ts, base))
            while q and ev.ts - q[0][0] > 120:
                q.popleft()
            distinct = {b for _, b in q}
            if len(distinct) >= 10:
                self._raise("high", "nx-storm", f"Burst of failed lookups{' from ' + pname if pname else ''}",
                            f"{len(distinct)} different domains that do not exist in two minutes: a DGA looking for its live "
                            f"controller", ev, who, "T1568.002", key=("nx", who))

        if not trusted and not svc:
            self._contact(ev, f"dns:{base}", base, "lookups of")

    # ── connections ──────────────────────────────────────────────────────────
    def _conn(self, ev: Conn):
        if not public_ip(ev.ip):
            return
        name = self.ip_names.get(ev.ip)
        pname = proc_name(ev.process)
        target = f"{name or ev.ip}:{ev.port}"
        trusted = bool(name) and D.trusted(name)
        if ev.port in RAT_PORTS and not trusted:
            self._raise("high", "rat-port", f"Connection on the {RAT_PORTS[ev.port]} default port",
                        f"to {target}: port {ev.port} is the out-of-the-box port of {RAT_PORTS[ev.port]}", ev, target, "T1571")
        if pname in LOLBINS and not trusted:
            self._raise("high", "lolbin", f"{pname} is talking to the internet",
                        f"to {target}: attackers use this built-in Windows program to download and run code", ev, target, "T1218")
        if self.dns_visible and not name and ev.port not in (53, 853, 123, 3478, 19302) and pname not in BROWSERS:
            self._raise("medium" if odd_location(ev.process) or pname in LOLBINS else "low", "direct-ip",
                        f"Connection to an address no lookup produced",
                        f"to {ev.ip}:{ev.port}: hard-coded addresses are how a lot of malware reaches its controller", ev,
                        ev.ip, "T1071", key=("direct-ip", pname, ev.ip))
        if not trusted:
            self._contact(ev, f"conn:{name or ev.ip}:{ev.port}", target, "connections to")

    def _contact(self, ev, key, target, verb):
        who = proc_name(ev.process) or (str(ev.pid) if ev.pid else "?")
        ts = self.contacts[(who, key)]
        if ts and ev.ts - ts[-1] < 1.0:                    # one burst is one contact
            return
        ts.append(ev.ts)
        if len(ts) > 50:
            del ts[0]
        if len(ts) < 6:
            return
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.fmean(gaps)
        if not 5 <= mean <= 7200:
            return
        cv = statistics.pstdev(gaps) / mean
        if cv <= .2:
            self._raise("high", "beacon", f"Regular check-ins with {target}",
                        f"{len(ts)} {verb} {target} every {mean:.0f}s (jitter {cv:.0%}): a beacon calling home on a timer, the "
                        f"rhythm of a RAT or C2 implant", ev, target, "T1071", key=("beacon", who, key))

    def summary(self) -> dict:
        out = {s: 0 for s in SEVERITIES}
        for a in self.alerts.values():
            out[a.severity] += 1
        return out
