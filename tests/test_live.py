"""On a real Windows machine: the DNS trap on port 53 answering real lookups and naming the program that
made them, and (as administrator, in CI) watch reading every lookup from the DNS Client log."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


@unittest.skipUnless(sys.platform == "win32", "needs Windows")
class Live(unittest.TestCase):
    def test_trap_names_the_program_behind_each_lookup(self):
        if not port_free(53):
            self.skipTest("port 53 is taken on this machine")
        with tempfile.TemporaryDirectory() as d:
            saved = Path(d, "events.jsonl")
            trap = subprocess.Popen([sys.executable, "-m", "panoptes", "trap", "--sinkhole", "10.9.9.9", "--seconds", "12",
                                     "--save", str(saved), "--json"], cwd=ROOT, env=ENV, stdout=subprocess.PIPE, text=True,
                                    encoding="utf-8")
            time.sleep(2)
            r = subprocess.run(["nslookup", "beacon-test.duckdns.org", "127.0.0.1"], capture_output=True, text=True)
            out, _ = trap.communicate(timeout=30)
            self.assertIn("10.9.9.9", r.stdout)                       # the sinkholed answer reached nslookup
            alerts = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
            self.assertIn("dynamic-dns", {a["rule"] for a in alerts})
            events = [json.loads(l) for l in saved.read_text(encoding="utf-8").splitlines()]
            asked = [e for e in events if e["name"] == "beacon-test.duckdns.org"]
            self.assertTrue(asked)
            self.assertTrue(asked[0]["process"].lower().endswith("nslookup.exe"), asked[0])

    @unittest.skipUnless(os.environ.get("PANOPTES_ADMIN_TESTS") == "1", "set PANOPTES_ADMIN_TESTS=1 as administrator")
    def test_watch_sees_lookups_from_the_dns_client_log(self):
        subprocess.run([sys.executable, "-m", "panoptes", "enable-dns-log"], cwd=ROOT, env=ENV, check=True)
        with tempfile.TemporaryDirectory() as d:
            saved = Path(d, "events.jsonl")
            watch = subprocess.Popen([sys.executable, "-m", "panoptes", "watch", "--seconds", "25", "--save", str(saved),
                                      "--json"], cwd=ROOT, env=ENV, stdout=subprocess.PIPE, text=True, encoding="utf-8")
            time.sleep(6)
            for name in ("github.com", "pool.supportxmr.com", "test-panoptes.duckdns.org"):
                subprocess.run(["powershell", "-NoProfile", "-Command", f"Resolve-DnsName {name} -ErrorAction SilentlyContinue"],
                               capture_output=True)
            out, _ = watch.communicate(timeout=60)
            names = {json.loads(l).get("name") for l in saved.read_text(encoding="utf-8").splitlines()}
            self.assertIn("github.com", names)
            rules = {json.loads(l)["rule"] for l in out.splitlines() if l.startswith("{")}
            self.assertIn("mining-pool", rules)
            self.assertIn("dynamic-dns", rules)


if __name__ == "__main__":
    unittest.main()
