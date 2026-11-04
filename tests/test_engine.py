"""The rules, on simulated malware traffic and on normal traffic that must stay quiet."""

import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import simulate as S  # noqa: E402
from panoptes import domains as D, sources, wire  # noqa: E402
from panoptes.engine import RANK, Conn, Dns, Engine  # noqa: E402
from panoptes.trap import Policy, Trap  # noqa: E402

MAL = r"C:\Users\victim\AppData\Local\Temp\svch0st.exe"
APP = r"C:\Program Files\App\app.exe"


def run(events, **kw):
    e = Engine(**kw)
    for ev in events:
        e.feed(ev)
    return e


def rules(e, worst="low"):
    return sorted({(a.rule, a.severity) for a in e.alerts.values() if RANK[a.severity] <= RANK[worst]})


class Quiet(unittest.TestCase):
    def test_normal_browsing_and_windows_traffic_raise_nothing(self):
        evs = [Dns(i, n, answers=["93.184.216.34"], process=r"C:\Program Files\Google\Chrome\Application\chrome.exe") for i, n in enumerate(S.BENIGN)]
        self.assertEqual(rules(run(evs)), [])

    def test_periodic_telemetry_to_big_operators_is_not_a_beacon(self):
        evs = [Dns(t, "v10.events.data.microsoft.com", answers=["20.42.65.92"], process=r"C:\Windows\System32\svchost.exe")
               for t in S.beacon(0, 60, 20)]
        evs += [Conn(t + .1, "20.42.65.92", 443, process=r"C:\Windows\System32\svchost.exe") for t in S.beacon(0, 60, 20)]
        self.assertEqual(rules(run(evs)), [])

    def test_telegram_desktop_using_its_own_api(self):
        e = run([Dns(0, "api.telegram.org", process=r"C:\Users\u\AppData\Roaming\Telegram Desktop\Telegram.exe")])
        self.assertEqual(rules(e, "low"), [])


class Malware(unittest.TestCase):
    def test_dns_exfiltration_dnscat_style(self):
        secret = b"user=alice;pass=Winter2026!;cookies=" + bytes(range(64))
        evs = [Dns(i, n, "TXT", process=MAL) for i, n in enumerate(S.tunnel_dnscat(secret))]
        e = run(evs)
        a = e.alerts[("dns-exfil", "example-cdn.net")]
        self.assertEqual(a.severity, "critical")
        self.assertIn("hex-encoded", a.detail)
        self.assertEqual(a.technique, "T1048.003")

    def test_dns_tunnel_iodine_style(self):
        evs = [Dns(i, n, process=MAL) for i, n in enumerate(S.tunnel_iodine(b"x" * 300))]
        self.assertIn(("dns-exfil", "critical"), rules(run(evs)))

    def test_dga_random_letters_and_failed_lookups(self):
        evs = [Dns(i * 2, n, rcode="NXDOMAIN", process=MAL) for i, n in enumerate(S.dga_cryptolocker(4, 30))]
        found = rules(run(evs), "high")
        self.assertIn(("dga", "critical"), found)                     # high, raised: the program runs from Temp
        self.assertIn(("nx-storm", "critical"), found)

    def test_dga_hash_names(self):
        evs = [Dns(i, n, rcode="NXDOMAIN", process=MAL) for i, n in enumerate(S.dga_md5(1, 12))]
        self.assertIn(("nx-storm", "critical"), rules(run(evs)))

    def test_rat_beacon_every_30_seconds_with_jitter(self):
        evs = [Conn(t, "45.137.21.9", 443, process=MAL) for t in S.beacon(1000, 30, 10, jitter=.08)]
        e = run(evs)
        a = next(a for a in e.alerts.values() if a.rule == "beacon")
        self.assertEqual(a.severity, "critical")                       # high, raised: it runs from Temp
        self.assertIn("every 30s", a.detail)

    def test_irregular_traffic_is_not_a_beacon(self):
        import random
        r = random.Random(3)
        t, evs = 0.0, []
        for _ in range(15):
            t += r.uniform(5, 400)
            evs.append(Conn(t, "45.137.21.9", 443, process=APP))
        self.assertNotIn("beacon", {a.rule for a in run(evs).alerts.values()})

    def test_rat_default_ports_dynamic_dns_and_lolbins(self):
        e = run([Dns(0, "victim-pc.duckdns.org", answers=["91.92.240.10"], process=MAL),
                 Conn(1, "91.92.240.10", 4782, process=MAL),
                 Conn(2, "185.7.33.10", 80, process=r"C:\Windows\System32\mshta.exe")])
        found = rules(e)
        self.assertIn(("dynamic-dns", "critical"), found)
        self.assertIn(("rat-port", "critical"), found)
        self.assertIn(("lolbin", "high"), found)
        self.assertIn("Quasar", e.alerts[next(k for k in e.alerts if k[0] == "rat-port")].title)

    def test_stealer_habits(self):
        e = run([Dns(0, "api.ipify.org", process=MAL), Dns(1, "api.telegram.org", process=MAL),
                 Dns(2, "pool.supportxmr.com", process=r"C:\ProgramData\x\xmrig.exe")])
        found = dict(rules(e))
        self.assertEqual(found["ip-lookup"], "critical")               # background program in Temp
        self.assertEqual(found["chat-api"], "critical")
        self.assertEqual(found["mining-pool"], "critical")

    def test_direct_ip_only_counts_when_lookups_are_visible(self):
        ev = [Conn(0, "193.42.33.7", 8443, process=MAL)]
        self.assertIn("direct-ip", {a.rule for a in run(ev).alerts.values()})
        self.assertNotIn("direct-ip", {a.rule for a in run(ev, dns_visible=False).alerts.values()})


class Domains(unittest.TestCase):
    def test_registrable_parts(self):
        self.assertEqual(D.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(D.registrable("www.absher.sa"), "absher.sa")
        self.assertEqual(D.registrable("my.gov.sa"), "my.gov.sa")
        self.assertEqual(D.registrable("victim.duckdns.org"), "victim.duckdns.org")

    def test_dga_score_separates_words_from_noise(self):
        noise = S.dga_cryptolocker(7, 300) + S.dga_md5(7, 300)
        caught = sum(D.generated(n.split(".")[0]) for n in noise) / len(noise)
        real = [D.registrable(n).split(".")[0] for n in S.BENIGN if not D.trusted(n)]
        self.assertGreater(caught, .8)
        self.assertEqual([l for l in real if D.generated(l)], [])
        for word in ("cryptography", "tawakkalna", "stackoverflow", "skyscanner", "alriyadh"):
            self.assertFalse(D.generated(word), word)


class Captures(unittest.TestCase):
    def test_pcap_lookups_failures_and_connections(self):
        frames = []
        frames += S.lookup_frames(1.0, "google.com", "142.250.80.46", 1)
        frames += S.lookup_frames(2.0, "qxzvbnmkwprtyl.com", None, 2)
        frames.append((3.0, S.syn("192.168.1.20", 50001, "142.250.80.46", 443)))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "cap.pcap")
            p.write_bytes(S.pcap(frames))
            evs = list(sources.read(p))
        self.assertEqual([type(e).__name__ for e in evs], ["Dns", "Dns", "Conn"])
        self.assertEqual(evs[0].answers, ["142.250.80.46"])
        self.assertEqual(evs[1].rcode, "NXDOMAIN")
        self.assertEqual((evs[2].ip, evs[2].port), ("142.250.80.46", 443))

    def test_beacon_found_in_a_capture(self):
        frames = []
        for i, t in enumerate(S.beacon(10, 45, 8)):
            frames += S.lookup_frames(t, "update.check-cdn-sync.net", "91.215.85.17", 100 + i)
            frames.append((t + .1, S.syn("192.168.1.20", 51000 + i, "91.215.85.17", 443)))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "beacon.pcap")
            p.write_bytes(S.pcap(frames))
            e = run(sources.read(p))
        self.assertIn("beacon", {a.rule for a in e.alerts.values()})

    def test_zeek_and_plain_lists(self):
        with tempfile.TemporaryDirectory() as d:
            z = Path(d, "dns.log")
            z.write_text("#separator \\x09\n#fields\tts\tquery\tqtype_name\trcode_name\tanswers\n"
                         "1.0\tvictim.no-ip.org\tA\tNOERROR\t1.2.3.4\n", encoding="utf-8")
            self.assertEqual(rules(run(sources.read(z))), [("dynamic-dns", "high")])
            l = Path(d, "list.txt")
            l.write_text("# domains\npool.minexmr.com\ngoogle.com\n", encoding="utf-8")
            self.assertEqual(rules(run(sources.read(l))), [("mining-pool", "critical")])


class TrapServer(unittest.TestCase):
    def start(self, policy):
        engine = Engine()
        seen = []
        t = Trap(engine, policy, lambda ev, alerts, action: seen.append((ev.name, action)), "127.0.0.1", 0)
        th = threading.Thread(target=t.serve, daemon=True)
        th.start()
        self.addCleanup(t.stop)
        return t, engine, seen

    def ask(self, trap, name, qtype="A"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(wire.query(name, qtype, 7), trap.address)
        data = s.recvfrom(4096)[0]
        s.close()
        return wire.parse(data)

    def test_sinkhole_answers_everything_and_logs_it(self):
        trap, engine, seen = self.start(Policy("sinkhole", answer="10.66.66.66"))
        r = self.ask(trap, "evil-c2.duckdns.org")
        self.assertEqual(r.answers[0][3], "10.66.66.66")
        time.sleep(.1)
        self.assertEqual(seen, [("evil-c2.duckdns.org", "sinkholed to 10.66.66.66")])
        self.assertIn("dynamic-dns", {a.rule for a in engine.alerts.values()})

    def test_nxdomain_mode(self):
        trap, _, _ = self.start(Policy("nxdomain"))
        self.assertEqual(self.ask(trap, "anything.example").rcode, "NXDOMAIN")


if __name__ == "__main__":
    unittest.main()
