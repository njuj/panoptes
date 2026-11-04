"""panoptes: the all-seeing watcher of DNS and outbound connections.
Exit codes: 0 nothing at or above --fail-on · 1 alerts · 2 could not run."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .engine import RANK, SEVERITIES, Alert, Conn, Dns, Engine, public_ip

LOCAL_SUFFIXES = (".home", ".lan", ".local", ".localdomain", ".internal", ".arpa")

ICON = {"critical": "✖", "high": "✖", "medium": "⚠", "low": "•", "info": "·"}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def _paint(enabled: bool):
    if enabled and os.name == "nt":
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x4)
    return (lambda s, c: f"\x1b[{c}m{s}\x1b[0m") if enabled else (lambda s, c: s)


class Out:
    def __init__(self, args):
        self.args = args
        color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self.p = _paint(color)
        self.save = open(args.save, "a", encoding="utf-8") if getattr(args, "save", None) else None

    def clock(self, ts: float) -> str:
        return time.strftime("%H:%M:%S", time.localtime(ts)) if ts > 1e9 else f"{ts:>8.1f}"

    def event(self, ev, action: str = ""):
        if self.save:
            d = asdict(ev)
            d["kind"] = "dns" if isinstance(ev, Dns) else "conn"
            self.save.write(json.dumps(d) + "\n")
            self.save.flush()
        if not getattr(self.args, "verbose", False) or self.args.json:
            return
        p = self.p
        who = (os.path.basename(ev.process) if ev.process else f"pid {ev.pid}" if ev.pid else "-")[:22]
        if isinstance(ev, Dns) and (ev.name.lower().endswith(LOCAL_SUFFIXES) or "." not in ev.name.strip(".")):
            return                                       # search-suffix and reverse lookups: noise, not traffic
        if isinstance(ev, Conn) and not public_ip(ev.ip):
            return
        if isinstance(ev, Dns):
            ans = ", ".join(ev.answers[:3]) + (" …" if len(ev.answers) > 3 else "") if ev.answers else ev.rcode
            line = f"{p(self.clock(ev.ts), '2')}  {p('DNS ', '36')} {who:<22} {ev.name} {p(ev.qtype, '2')} → {ans}"
        else:
            addr = f"[{ev.ip}]:{ev.port}" if ":" in ev.ip else f"{ev.ip}:{ev.port}"
            line = f"{p(self.clock(ev.ts), '2')}  {p('CONN', '35')} {who:<22} {addr}"
        print(line + (p(f"  [{action}]", "33") if action and action != "forwarded" else ""), flush=True)

    def alert(self, a: Alert):
        if RANK[a.severity] > RANK[self.args.min_severity]:
            return
        if self.args.json:
            print(json.dumps(a.to_dict()), flush=True)
            return
        p = self.p
        who = f"  {os.path.basename(a.process)}" + (f" (pid {a.pid})" if a.pid else "") if a.process else ""
        tech = f"  {a.technique}" if a.technique else ""
        print(f"{p(self.clock(a.last), '2')}  {p(f'{ICON[a.severity]} {a.severity.upper():<8}', COLOR[a.severity])} "
              f"{p(a.title, '1')}{p(who, '36')}{p(tech, '35')}", flush=True)
        print(p(f"            └ {a.detail}", "2"), flush=True)

    def summary(self, engine: Engine, elapsed: float, header: str):
        if self.args.json:
            return
        p = self.p
        alerts = sorted(engine.alerts.values(), key=lambda a: (RANK[a.severity], -a.count))
        shown = [a for a in alerts if RANK[a.severity] <= RANK[self.args.min_severity]]
        print()
        print(p(f" panoptes v{__version__}", "1;36") + p(f"  ·  {header}  ·  {engine.events:,} events  ·  {elapsed:.0f}s", "2"))
        if not shown:
            print(p(" ✔ nothing suspicious seen", "1;32"))
            return
        for a in shown[:40]:
            who = os.path.basename(a.process) if a.process else "-"
            times = f"×{a.count}" if a.count > 1 else ""
            print(f"   {p(f'{ICON[a.severity]} {a.severity.upper():<8}', COLOR[a.severity])} {a.title}  "
                  f"{p(who, '36')} {p(times, '2')}")
        counts = engine.summary()
        print(p(" " + "  ·  ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s]), "1"))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="panoptes", description="See every DNS lookup and outbound connection, and which ones "
                                 "look like malware: C2 beacons, DGAs, DNS tunneling and exfiltration, RAT ports, dynamic DNS.")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--json", action="store_true", help="one JSON alert per line")
        p.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide alerts below this (default: low)")
        p.add_argument("--fail-on", choices=SEVERITIES, default="high", help="exit 1 at or above this (default: high)")
        p.add_argument("--no-color", action="store_true")
        p.add_argument("-v", "--verbose", action="store_true", help="also print every lookup and connection")

    w = sub.add_parser("watch", help="watch this Windows machine live")
    w.add_argument("--seconds", type=float, help="stop after this long (default: until Ctrl+C)")
    w.add_argument("--interval", type=float, default=1.0, help="polling interval (default: 1s)")
    w.add_argument("--existing", action="store_true", help="also judge the connections already open when it starts")
    w.add_argument("--save", metavar="FILE", help="also record every event, to analyze or replay later")
    common(w)

    t = sub.add_parser("trap", help="run a DNS server that logs, judges, and can sinkhole every lookup")
    t.add_argument("--listen", default="127.0.0.1:53", help="address:port to listen on (default: 127.0.0.1:53)")
    mode = t.add_mutually_exclusive_group()
    mode.add_argument("--sinkhole", metavar="IP", help="answer every name with this address (malware analysis, like ApateDNS)")
    mode.add_argument("--nxdomain", action="store_true", help="answer that no name exists")
    mode.add_argument("--guard", action="store_true", help="forward normally, but sinkhole names flagged high or worse")
    t.add_argument("--upstream", default="1.1.1.1", help="resolver to forward to (default: 1.1.1.1)")
    t.add_argument("--seconds", type=float, help="stop after this long")
    t.add_argument("--save", metavar="FILE")
    common(t)

    a = sub.add_parser("analyze", help="analyze captures (pcap, pcapng), Zeek dns.log, saved events or domain lists")
    a.add_argument("files", nargs="+", type=Path)
    common(a)

    sub.add_parser("enable-dns-log", help="switch on Windows' DNS Client log (administrator) so watch sees every lookup")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    started = time.time()

    if args.cmd == "enable-dns-log":
        if sys.platform != "win32":
            print("panoptes: this is a Windows setting", file=sys.stderr)
            return 2
        from . import windows
        ok, msg = windows.enable_dns_log()
        print("DNS Client log enabled: panoptes watch now sees every lookup and the process behind it" if ok else
              f"Could not enable it ({msg or 'access denied'}). Run this once from an administrator terminal:\n"
              f"  wevtutil sl {windows.DNS_LOG} /e:true")
        return 0 if ok else 2

    out = Out(args)

    if args.cmd == "analyze":
        from . import sources
        engine = Engine()
        for path in args.files:
            try:
                for ev in sources.read(path):
                    out.event(ev)
                    for a in engine.feed(ev):
                        out.alert(a)
            except (OSError, sources.SourceError) as e:
                print(f"panoptes: {e}", file=sys.stderr)
                return 2
        out.summary(engine, time.time() - started, f"{len(args.files)} file(s)")
        return _exit(engine, args)

    if args.cmd == "watch":
        if sys.platform != "win32":
            print("panoptes watch: live monitoring needs Windows (use analyze or trap elsewhere)", file=sys.stderr)
            return 2
        from . import windows
        live = windows.Live(include_existing=args.existing)
        from .trap import search_suffixes
        engine = Engine(dns_visible=live.dns, local_suffixes=tuple(search_suffixes()))
        p = out.p
        if not args.json:
            print(p(f" panoptes v{__version__}", "1;36") + p("  ·  watching this machine  ·  Ctrl+C to stop", "2"))
            if not live.dns:
                print(p(" ⚠ DNS lookups are not visible yet: connections only. Run `panoptes enable-dns-log` once as "
                        "administrator to see every lookup and the program behind it.", "33"))
            print()
        try:
            while args.seconds is None or time.time() - started < args.seconds:
                for ev in live.poll():
                    out.event(ev)
                    for a in engine.feed(ev):
                        out.alert(a)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass
        out.summary(engine, time.time() - started, "live")
        return _exit(engine, args)

    # trap
    from .trap import Policy, Trap
    host, _, port = args.listen.rpartition(":")
    policy = Policy("sinkhole" if args.sinkhole else "nxdomain" if args.nxdomain else "guard" if args.guard else "forward",
                    args.upstream, args.sinkhole or "127.0.0.1")
    from .trap import search_suffixes
    engine = Engine(local_suffixes=tuple(search_suffixes()))

    def on_event(ev, alerts, action):
        out.event(ev, action)
        for a in alerts:
            out.alert(a)

    try:
        trap = Trap(engine, policy, on_event, host or "127.0.0.1", int(port))
    except OSError as e:
        print(f"panoptes trap: cannot listen on {args.listen}: {e.strerror or e}", file=sys.stderr)
        return 2
    if not args.json:
        p = out.p
        what = {"sinkhole": f"answering every name with {policy.answer}", "nxdomain": "answering that no name exists",
                "guard": f"forwarding to {policy.upstream}, sinkholing names flagged high or worse",
                "forward": f"forwarding to {policy.upstream}"}[policy.mode]
        print(p(f" panoptes v{__version__}", "1;36") + p(f"  ·  DNS trap on {trap.address[0]}:{trap.address[1]}  ·  {what}", "2"))
        print(p(f" point a machine's DNS server at {trap.address[0]} to see its lookups here; Ctrl+C to stop\n", "2"))
    try:
        trap.serve(until=started + args.seconds if args.seconds else None)
    except KeyboardInterrupt:
        pass
    trap.stop()
    out.summary(engine, time.time() - started, f"trap ({policy.mode})")
    return _exit(engine, args)


def _exit(engine: Engine, args) -> int:
    worst = min((RANK[a.severity] for a in engine.alerts.values()), default=99)
    return 1 if worst <= RANK[args.fail_on] else 0
