"""The trap: a DNS server that sees every question asked of it. Like ApateDNS it can answer every name
with an address you choose (so a sample under analysis connects to your listener instead of its real
controller) or say no name exists. Unlike it, it can also forward everything normally and only
sinkhole the names the engine flags, and it judges every query as it arrives."""

from __future__ import annotations

import socket
import sys
import threading
import time
from dataclasses import dataclass

from . import wire
from .engine import RANK, Dns, Engine

LOCAL = (".home", ".lan", ".local", ".localdomain", ".internal", ".arpa")


def search_suffixes() -> list[str]:
    """The DNS suffixes this machine appends to names (Windows' search list and its adapters' domains)."""
    if sys.platform != "win32":
        return []
    import winreg
    out = []
    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    def values(key):
        for v in ("SearchList", "Domain", "DhcpDomain"):
            try:
                out.extend(x.strip().lower().strip(".") for x in str(winreg.QueryValueEx(key, v)[0]).split(",") if x.strip())
            except OSError:
                pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            values(k)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + r"\Interfaces") as ifs:
            for i in range(winreg.QueryInfoKey(ifs)[0]):
                with winreg.OpenKey(ifs, winreg.EnumKey(ifs, i)) as k:
                    values(k)
    except OSError:
        pass
    return sorted(set(out))


@dataclass
class Policy:
    mode: str = "forward"            # forward | sinkhole | nxdomain | guard
    upstream: str = "1.1.1.1"
    answer: str = "127.0.0.1"        # where sinkholed names point
    guard_level: str = "high"        # guard: sinkhole names whose alert is at least this severe


class Trap:
    def __init__(self, engine: Engine, policy: Policy, on_event=None, host: str = "127.0.0.1", port: int = 53):
        self.engine, self.policy, self.on_event = engine, policy, on_event or (lambda ev, alerts, action: None)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.suffixes = LOCAL + tuple("." + s for s in search_suffixes())
        self.address = self.sock.getsockname()
        self.lock = threading.Lock()
        self.blocked: set[str] = set()
        self._stop = False

    def _forward(self, data: bytes) -> bytes | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(data, (self.policy.upstream, 53))
            return s.recvfrom(4096)[0]
        except OSError:
            return None
        finally:
            s.close()

    def _owner(self, client) -> tuple[int | None, str | None]:
        if sys.platform != "win32" or client[0] != "127.0.0.1":
            return None, None
        from . import windows
        pid = windows.udp_owner(client[1])
        return pid, windows.process_path(pid)

    def handle(self, data: bytes, client) -> None:
        try:
            q = wire.parse(data)
        except (wire.WireError, ValueError):
            return
        if q.response or not q.questions:
            return
        name, qtype = q.questions[0]
        pid, proc = self._owner(client)
        p = self.policy
        local = name.lower().rstrip(".").endswith(self.suffixes)
        if p.mode == "sinkhole" and local:
            # names with the network's search suffix (x.duckdns.org.home) and reverse lookups: say they do not
            # exist, so the program goes on to ask for the real name instead of stopping at a fake answer
            resp, action = wire.reply(data, rcode=3), "answered NXDOMAIN"
        elif p.mode == "sinkhole":
            resp, action = wire.reply(data, ipv4=p.answer, ipv6="::1" if p.answer.startswith("127.") else None), f"sinkholed to {p.answer}"
        elif p.mode == "nxdomain":
            resp, action = wire.reply(data, rcode=3), "answered NXDOMAIN"
        else:
            resp, action = None, "forwarded"
            if p.mode == "guard" and name.lower() in self.blocked:
                resp, action = wire.reply(data, ipv4=p.answer), f"blocked (sinkholed to {p.answer})"
            if resp is None:
                resp = self._forward(data)
                if resp is None:
                    resp, action = wire.reply(data, rcode=2), "upstream did not answer"
        try:
            r = wire.parse(resp)
            answers = [d for _, t, _, d in r.answers if t in ("A", "AAAA")]
            rcode = r.rcode
        except (wire.WireError, ValueError):
            answers, rcode = [], "SERVFAIL"
        ev = Dns(time.time(), name, qtype, answers, rcode, pid, proc)
        with self.lock:
            alerts = self.engine.feed(ev)
            if p.mode == "guard" and any(RANK[a.severity] <= RANK[p.guard_level] for a in alerts):
                self.blocked.add(name.lower())
                if action == "forwarded":
                    resp, action = wire.reply(data, ipv4=p.answer), f"blocked (sinkholed to {p.answer})"
            self.on_event(ev, alerts, action)
        try:
            self.sock.sendto(resp, client)
        except OSError:
            pass

    def serve(self, until: float | None = None) -> None:
        self.sock.settimeout(.5)
        while not self._stop and (until is None or time.time() < until):
            try:
                data, client = self.sock.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                # Windows reports "connection reset" on a UDP socket when a client left before our reply reached
                # it (an ICMP port-unreachable); for a server that is not an error
                continue
            except OSError:
                break
            threading.Thread(target=self.handle, args=(data, client), daemon=True).start()

    def stop(self) -> None:
        self._stop = True
        self.sock.close()
