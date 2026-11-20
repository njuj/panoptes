"""TLS handshakes in captures: the server name, the server's certificate, RAT and C2 default certificates,
TCP segments out of order, and DNS over HTTPS from programs that are not browsers."""

import json
import ssl
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import simulate as S  # noqa: E402
from make_tls_capture import tcp  # noqa: E402
from panoptes import sources, tls  # noqa: E402
from panoptes.engine import Conn, Engine, Tls  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "tls.pcap"
MAL = r"C:\Users\victim\AppData\Roaming\winupd.exe"


def client_hello(name: str) -> bytes:
    """The first flight of a real OpenSSL client asking for `name`."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    out = ssl.MemoryBIO()
    c = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=name)
    with self_assert_raises(ssl.SSLWantReadError):
        c.do_handshake()
    return out.read()


class self_assert_raises:
    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        assert t is self.exc, f"expected {self.exc.__name__}"
        return True


def analyze(path):
    e = Engine()
    events = list(sources.read(path))
    for ev in events:
        e.feed(ev)
    return e, events


class Handshakes(unittest.TestCase):
    def test_real_handshakes_rat_and_c2_certificates(self):
        e, events = analyze(FIXTURE)
        seen = [(ev.ip, ev.sni, ev.subject) for ev in events if isinstance(ev, Tls)]
        self.assertIn(("203.0.113.66", None, "CN=AsyncRAT Server"), seen)                      # TLS 1.2, no SNI
        self.assertIn(("198.51.100.10", "wiki.example.com", "CN=wiki.example.com, O=Example Intranet"), seen)
        self.assertIn(("198.51.100.77", "victim-pc.duckdns.org", None), seen)                  # TLS 1.3: name only
        found = {(a.rule, a.target): a for a in e.alerts.values()}
        a = found[("rat-cert", "203.0.113.66:6606")]
        self.assertEqual((a.severity, a.technique), ("critical", "T1573.002"))
        self.assertIn("AsyncRAT", a.title)
        cs = found[("rat-cert", "cdn.update-check.net:443")]
        self.assertIn("Cobalt Strike", cs.title)
        self.assertIn("serial 146473198", cs.detail)
        self.assertEqual(found[("dynamic-dns", "victim-pc.duckdns.org")].severity, "high")   # no DNS in the capture
        self.assertEqual({r for r, _ in found}, {"rat-cert", "dynamic-dns"})                  # the intranet stays quiet

    def test_server_name_from_a_real_client_hello(self):
        hello = client_hello("files.example.org")
        stream = tls.Stream()
        msgs = []
        for i in range(len(hello)):                                    # one byte at a time
            msgs += stream.feed(hello[i:i + 1])
        self.assertEqual([(t, tls.sni(b)) for t, b in msgs], [(1, "files.example.org")])

    def test_segments_out_of_order_and_retransmitted(self):
        hello = client_hello("c2.duckdns.org")
        parts = [hello[i:i + 100] for i in range(0, len(hello), 100)]
        self.assertGreater(len(parts), 2)
        segs = [tcp("10.0.0.5", 50500, "198.51.100.9", 443, 1 + 100 * i, p) for i, p in enumerate(parts)]
        order = [segs[0]] + segs[1:][::-1] + [segs[1]]                 # all but the first reversed, one sent again
        frames = [(1.0, S.syn("10.0.0.5", 50500, "198.51.100.9", 443))] + [(1.0 + i / 100, f) for i, f in enumerate(order)]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "ooo.pcap")
            p.write_bytes(S.pcap(frames))
            e, events = analyze(p)
        self.assertEqual([ev.sni for ev in events if isinstance(ev, Tls)], ["c2.duckdns.org"])
        self.assertIn("dynamic-dns", {a.rule for a in e.alerts.values()})

    def test_the_hello_names_the_connection_before_it_is_judged(self):
        frames = [(1.0, S.syn("10.0.0.5", 50600, "198.51.100.20", 443)),
                  (1.01, tcp("10.0.0.5", 50600, "198.51.100.20", 443, 1, client_hello("docs.example.com")))]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "named.pcap")
            p.write_bytes(S.pcap(frames))
            e, events = analyze(p)
        self.assertEqual([type(ev).__name__ for ev in events], ["Tls", "Conn"])
        self.assertEqual(e.alerts, {})                                  # not "an address no lookup produced"

    def test_certificate_parser_never_raises_on_junk(self):
        for junk in (b"", b"\x0b\x00\x00\x03\x00\x00\x00", b"\x30\x82\xff\xff" + b"\x00" * 10, bytes(range(256))):
            self.assertIsNone(tls.leaf_cert(junk))
            tls.sni(junk)

    def test_saved_events_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "events.jsonl")
            ev = Tls(5.0, "203.0.113.66", 6606, subject="CN=AsyncRAT Server", issuer="CN=AsyncRAT Server", serial=7)
            p.write_text(json.dumps({**ev.__dict__, "kind": "tls"}) + "\n", encoding="utf-8")
            self.assertEqual(list(sources.read(p)), [ev])


class DnsOverHttps(unittest.TestCase):
    def test_only_programs_that_are_not_browsers(self):
        e = Engine()
        e.feed(Conn(0, "1.1.1.1", 443, process=MAL))
        e.feed(Conn(1, "8.8.8.8", 443, process=r"C:\Program Files\Mozilla Firefox\firefox.exe"))
        e.feed(Conn(2, "9.9.9.9", 443, process=r"C:\Windows\System32\svchost.exe"))
        e.feed(Conn(3, "1.1.1.1", 53, process=MAL))                     # plain DNS is visible: not this rule
        e.feed(Tls(4, "104.16.249.249", 443, sni="cloudflare-dns.com", process=r"C:\Tools\agent.exe"))
        doh = sorted((a.process, a.severity) for a in e.alerts.values() if a.rule == "doh")
        self.assertEqual(doh, [(r"C:\Tools\agent.exe", "medium"), (MAL, "high")])   # Roaming top level: one more


if __name__ == "__main__":
    unittest.main()
