"""Writes tests/fixtures/tls.pcap: real TLS handshakes made by OpenSSL (through Python's ssl module, in memory,
nothing on the network), cut into TCP segments with one pair swapped and one retransmitted, as captures show them.

    python tests/make_tls_capture.py        (needs the openssl command, only to make the throwaway certificates)

  1. 192.168.1.20 -> 203.0.113.66:6606   TLS 1.2, no SNI, certificate CN=AsyncRAT Server (the builder's default)
  2. 192.168.1.20 -> 203.0.113.80:443    TLS 1.2, SNI cdn.update-check.net, Cobalt Strike's default certificate
  3. 192.168.1.20 -> 198.51.100.10:443   TLS 1.2, SNI wiki.example.com, an ordinary self-signed certificate
  4. 192.168.1.20 -> 198.51.100.77:443   TLS 1.3, SNI victim-pc.duckdns.org: no DNS lookup in the capture at all
"""

import ssl
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import simulate as S  # noqa: E402

CLIENT = "192.168.1.20"
FLOWS = [
    ("/CN=AsyncRAT Server", None, "203.0.113.66", 6606, ssl.TLSVersion.TLSv1_2, None),
    ("/ST=Cyberspace/L=Somewhere/O=cobaltstrike/OU=AdvancedPenTesting/CN=Major Cobalt Strike", "146473198",
     "203.0.113.80", 443, ssl.TLSVersion.TLSv1_2, "cdn.update-check.net"),
    ("/CN=wiki.example.com/O=Example Intranet", None, "198.51.100.10", 443, ssl.TLSVersion.TLSv1_2, "wiki.example.com"),
    ("/CN=victim-pc.duckdns.org", None, "198.51.100.77", 443, ssl.TLSVersion.TLSv1_3, "victim-pc.duckdns.org"),
]


def tcp(src, sport, dst, dport, seq, data, flags=0x18):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, flags, 65535, 0, 0)
    return S._eth(S._ipv4(src, dst, 6, hdr + data))


def handshake(cert, key, version, server_name):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.maximum_version = version
    server.load_cert_chain(cert, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname, client.verify_mode = False, ssl.CERT_NONE
    cin, cout, sin, sout = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(cin, cout, server_hostname=server_name)
    s = server.wrap_bio(sin, sout, server_side=True)
    turns, done = [], [False, False]
    for _ in range(12):
        for i, side in enumerate((c, s)):
            try:
                side.do_handshake()
                done[i] = True
            except ssl.SSLWantReadError:
                pass
        up, down = cout.read(), sout.read()
        sin.write(up)
        cin.write(down)
        turns += [("up", up)] if up else []
        turns += [("down", down)] if down else []
        if all(done) and not up and not down:
            return turns
    raise RuntimeError("handshake did not finish")


def main():
    frames, t = [], 1795174927.0                 # 2026-11-20 11:42:07 UTC
    with tempfile.TemporaryDirectory() as d:
        for n, (subj, serial, ip, port, version, name) in enumerate(FLOWS):
            cert, key = Path(d, f"{n}.pem"), Path(d, f"{n}.key")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", subj,
                            "-keyout", str(key), "-out", str(cert)] + (["-set_serial", serial] if serial else []),
                           check=True, capture_output=True)
            sport, seq = 50100 + n, {"up": 1000, "down": 9000}
            frames.append((t, S.syn(CLIENT, sport, ip, port)))
            for direction, data in handshake(cert, key, version, name):
                segs = []
                for k in range(0, len(data), 536):
                    chunk = data[k:k + 536]
                    src, sp, dst, dp = (CLIENT, sport, ip, port) if direction == "up" else (ip, port, CLIENT, sport)
                    segs.append(tcp(src, sp, dst, dp, seq[direction], chunk))
                    seq[direction] += len(chunk)
                if len(segs) >= 3:                       # as captures show it: one pair out of order, one sent twice
                    segs[1], segs[2] = segs[2], segs[1]
                    segs.insert(3, segs[2])
                for f in segs:
                    t += .01
                    frames.append((t, f))
            t += 5
    out = HERE / "fixtures" / "tls.pcap"
    out.parent.mkdir(exist_ok=True)
    out.write_bytes(S.pcap(frames))
    print(f"{out}: {len(frames)} frames")


if __name__ == "__main__":
    main()
