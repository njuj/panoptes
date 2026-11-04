"""A live Windows machine, read-only: the connection tables with the process that owns each socket
(GetExtendedTcpTable, no administrator needed), and every DNS lookup with the process that made it, from
Windows' own DNS Client log once it is switched on (one administrator command)."""

from __future__ import annotations

import ctypes
import ipaddress
import re
import socket
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from ctypes import wintypes as W

from .engine import Conn, Dns
from .wire import TYPES

if sys.platform != "win32":                     # pragma: no cover
    raise ImportError("live monitoring needs Windows")

iphlpapi = ctypes.WinDLL("iphlpapi")
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = W.HANDLE
k32.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD)]
k32.CloseHandle.argtypes = [W.HANDLE]

DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"
TCP_STATES = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2",
              8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}


def _table(fn, family: int, klass: int) -> bytes:
    size = W.DWORD(0)
    fn(None, ctypes.byref(size), False, family, klass, 0)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = W.DWORD(len(buf))
        if fn(buf, ctypes.byref(size), False, family, klass, 0) == 0:
            return buf.raw[:size.value]
    return b""


def tcp_connections() -> list[tuple[str, int, str, int, int, str]]:
    """[(local ip, local port, remote ip, remote port, pid, state)] for IPv4 and IPv6."""
    out = []
    raw = _table(iphlpapi.GetExtendedTcpTable, socket.AF_INET, 5)             # TCP_TABLE_OWNER_PID_ALL
    if len(raw) >= 4:
        n = struct.unpack_from("<I", raw, 0)[0]
        for i in range(n):
            st, la, lp, ra, rp, pid = struct.unpack_from("<IIIIII", raw, 4 + 24 * i)
            out.append((socket.inet_ntoa(struct.pack("<I", la)), socket.ntohs(lp & 0xFFFF),
                        socket.inet_ntoa(struct.pack("<I", ra)), socket.ntohs(rp & 0xFFFF), pid, TCP_STATES.get(st, str(st))))
    raw = _table(iphlpapi.GetExtendedTcpTable, socket.AF_INET6, 5)
    if len(raw) >= 4:
        n = struct.unpack_from("<I", raw, 0)[0]
        for i in range(n):
            o = 4 + 56 * i
            la, lp = raw[o:o + 16], struct.unpack_from("<I", raw, o + 20)[0]
            ra, rp = raw[o + 24:o + 40], struct.unpack_from("<I", raw, o + 44)[0]
            st, pid = struct.unpack_from("<II", raw, o + 48)
            out.append((str(ipaddress.IPv6Address(la)), socket.ntohs(lp & 0xFFFF), str(ipaddress.IPv6Address(ra)),
                        socket.ntohs(rp & 0xFFFF), pid, TCP_STATES.get(st, str(st))))
    return out


def udp_owner(port: int) -> int | None:
    """The process that owns a local UDP port (who sent a query the sinkhole received)."""
    raw = _table(iphlpapi.GetExtendedUdpTable, socket.AF_INET, 1)               # UDP_TABLE_OWNER_PID
    if len(raw) >= 4:
        for i in range(struct.unpack_from("<I", raw, 0)[0]):
            _, lp, pid = struct.unpack_from("<III", raw, 4 + 12 * i)
            if socket.ntohs(lp & 0xFFFF) == port:
                return pid
    return None


_paths: dict[int, str | None] = {}


def process_path(pid: int | None) -> str | None:
    if not pid:
        return None
    if pid in _paths:
        return _paths[pid]
    path = None
    h = k32.OpenProcess(0x1000, False, pid)                                     # PROCESS_QUERY_LIMITED_INFORMATION
    if h:
        buf = ctypes.create_unicode_buffer(1024)
        n = W.DWORD(1024)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
            path = buf.value
        k32.CloseHandle(h)
    if path is None and pid == 4:
        path = "System"
    _paths[pid] = path
    return path


def dns_log_enabled() -> bool:
    try:
        out = subprocess.run(["wevtutil", "gl", DNS_LOG], capture_output=True, text=True, timeout=10).stdout
    except OSError:
        return False
    return bool(re.search(r"enabled:\s*true", out))


def enable_dns_log() -> tuple[bool, str]:
    r = subprocess.run(["wevtutil", "sl", DNS_LOG, "/e:true"], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def dns_events(after_record: int) -> tuple[list[Dns], int]:
    """Completed lookups (event 3008) logged after a record id: (events, last record id)."""
    q = f"*[System[(EventID=3008) and (EventRecordID>{after_record})]]"
    try:
        r = subprocess.run(["wevtutil", "qe", DNS_LOG, f"/q:{q}", "/f:xml", "/e:Events"], capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return [], after_record
    if not r.stdout.strip():
        return [], after_record
    try:
        root = ET.fromstring(r.stdout)
    except ET.ParseError:
        return [], after_record
    out, last = [], after_record
    for ev in root.findall(f"{NS}Event"):
        sysn = ev.find(f"{NS}System")
        rec = int(sysn.findtext(f"{NS}EventRecordID", "0"))
        last = max(last, rec)
        pid = int(sysn.find(f"{NS}Execution").get("ProcessID", "0"))
        tc = sysn.find(f"{NS}TimeCreated").get("SystemTime", "")
        data = {d.get("Name"): (d.text or "") for d in ev.find(f"{NS}EventData")}
        name = data.get("QueryName", "")
        qtype = TYPES.get(int(data.get("QueryType", "1") or 1), data.get("QueryType", "A"))
        status = int(data.get("QueryStatus", "0") or 0)
        rcode = "NOERROR" if status == 0 else "NXDOMAIN" if status == 9003 else "NODATA" if status == 9501 else f"error {status}"
        answers = []
        for part in (data.get("QueryResults") or "").split(";"):
            part = part.strip().removeprefix("::ffff:")
            try:
                ipaddress.ip_address(part)
                answers.append(part)
            except ValueError:
                continue
        out.append(Dns(_ts(tc), name, qtype, answers, rcode, pid, process_path(pid)))
    return out, last


def _ts(s: str) -> float:
    """2026-11-04T01:02:03.1234567Z (seven decimals, which fromisoformat refuses) to epoch seconds."""
    from datetime import datetime, timezone
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?", s)
    if not m:
        return time.time()
    base = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return base + (float("0." + m.group(2)) if m.group(2) else 0.0)


def last_dns_record() -> int:
    """The newest record id in the DNS log, so watching starts from now."""
    try:
        r = subprocess.run(["wevtutil", "qe", DNS_LOG, "/c:1", "/rd:true", "/f:xml"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=10)
        m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", r.stdout)
        return int(m.group(1)) if m else 0
    except (OSError, subprocess.TimeoutExpired):
        return 0


class Live:
    """Poll the machine: new outbound connections and new DNS lookups since the last poll."""

    def __init__(self, *, include_existing: bool = False):
        self.seen: set[tuple] = set()
        self.dns = dns_log_enabled()
        self.record = last_dns_record() if self.dns else 0
        if not include_existing:
            for c in tcp_connections():
                self.seen.add((c[4], c[0], c[1], c[2], c[3]))

    def poll(self) -> list[Dns | Conn]:
        out: list[Dns | Conn] = []
        if self.dns:
            evs, self.record = dns_events(self.record)
            out += evs
        now = time.time()
        for la, lp, ra, rp, pid, state in tcp_connections():
            if state not in ("ESTABLISHED", "SYN_SENT") or ra in ("0.0.0.0", "::"):
                continue
            key = (pid, la, lp, ra, rp)
            if key in self.seen:
                continue
            self.seen.add(key)
            out.append(Conn(now, ra, rp, "tcp", pid, process_path(pid)))
        return out
