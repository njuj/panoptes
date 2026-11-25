# panoptes

[![Part of Cryptid Security](https://img.shields.io/badge/part_of-Cryptid%20Security-c6922f?style=flat-square&labelColor=0c1411)](https://github.com/cryptid-security)

**See every DNS lookup and outbound connection, the program behind each one, and which of them look like malware.** It reads TLS handshakes too, so a C2 server still using its RAT's default certificate is named, and so is a destination whose lookup went over DNS over HTTPS. That covers C2 beacons, domain-generation algorithms, DNS tunneling and exfiltration, RAT default ports, dynamic DNS, mining pools, and stealers phoning home. Its DNS trap works like ApateDNS: it can sinkhole every name for malware analysis, or forward normally and block only the names it flags. It needs nothing but Python's standard library.

[![ci](https://github.com/njuj/panoptes/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/panoptes/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-c77dff?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-c77dff?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-c77dff?labelColor=0b0f17)

<p align="center"><img src="docs/banner.svg" width="100%" alt="panoptes: how it works"/></p>

<p align="center"><img src="docs/demo.svg" width="100%" alt="panoptes running in a terminal"/></p>

*Argus Panoptes, the hundred-eyed watchman of Greek myth, never slept with every eye at once.*

```text
$ panoptes analyze tests/fixtures/tls.pcap -v
14:42:07  TLS  -                      203.0.113.66:6606 certificate CN=AsyncRAT Server
14:42:07  ✖ CRITICAL AsyncRAT server certificate on 203.0.113.66:6606  T1573.002
            └ the server presented 'CN=AsyncRAT Server': the certificate AsyncRAT generates out of the box, so this is almost certainly its controller
14:42:12  TLS  -                      203.0.113.80:443 hello cdn.update-check.net
14:42:12  TLS  -                      203.0.113.80:443 certificate O=cobaltstrike, OU=AdvancedPenTesting, CN=Major Cobalt Strike
14:42:12  ✖ CRITICAL Cobalt Strike server certificate on cdn.update-check.net:443  T1573.002
            └ the server presented 'O=cobaltstrike, OU=AdvancedPenTesting, CN=Major Cobalt Strike', serial 146473198: the certificate Cobalt Strike generates out of the box, so this is almost certainly its controller
14:42:17  TLS  -                      198.51.100.10:443 hello wiki.example.com
14:42:17  TLS  -                      198.51.100.10:443 certificate CN=wiki.example.com, O=Example Intranet
14:42:22  TLS  -                      198.51.100.77:443 hello victim-pc.duckdns.org
14:42:22  ✖ HIGH     victim-pc.duckdns.org: dynamic dns  T1568
            └ dynamic DNS: a free name that follows a home IP, the classic address of a RAT's controller

 panoptes v0.2.0  ·  1 file(s)  ·  10 events  ·  0s
   ✖ CRITICAL AsyncRAT server certificate on 203.0.113.66:6606
   ✖ CRITICAL Cobalt Strike server certificate on cdn.update-check.net:443
   ✖ HIGH     victim-pc.duckdns.org: dynamic dns
 2 critical  ·  1 high
```

Four real TLS handshakes made by OpenSSL ([`tests/make_tls_capture.py`](tests/make_tls_capture.py)), with TCP segments out of order and sent twice, as captures show them. Two servers still use the certificate their framework generates (AsyncRAT's `CN=AsyncRAT Server`, Cobalt Strike's `Major Cobalt Strike` with serial 146473198). The third is an ordinary self-signed intranet certificate and stays quiet. The fourth is TLS 1.3: its certificate is encrypted and no DNS lookup was captured, but the name in the ClientHello is enough to flag a duckdns controller.

The DNS trap, in a real run on Windows:

```text
$ panoptes trap --guard -v
 panoptes v0.1.0  ·  DNS trap on 127.0.0.1:53  ·  forwarding to 1.1.1.1, sinkholing names flagged high or worse

14:55:01  DNS  nslookup.exe     github.com A → 20.233.83.145
14:55:01  DNS  nslookup.exe     victim-pc.duckdns.org A → NXDOMAIN  [blocked (sinkholed to 127.0.0.1)]
14:55:01  ✖ HIGH     victim-pc.duckdns.org: dynamic dns  nslookup.exe (pid 9624)  T1568
            └ dynamic DNS: a free name that follows a home IP, the classic address of a RAT's controller
14:55:01  ✖ CRITICAL pool.supportxmr.com: mining pool  nslookup.exe (pid 13720)  T1496
14:55:02  ✖ HIGH     Data hidden in DNS names sent to exfil-test.net  nslookup.exe (pid 9644)  T1048.003
            └ 1 distinct encoded subdomain (a 50-character label, hex-encoded): DNS tunneling or exfiltration
14:55:02  ✖ HIGH     Machine-generated domain names from nslookup.exe  nslookup.exe (pid 10548)  T1568.002
            └ 1 random-looking domain, latest qxzvbnmkwprtyl.com (reads like language 2.9/9)
```

That was a real run on Windows: real lookups, real answers, and the program behind each one identified from the socket that asked.

## Three ways to use it

```bash
pip install git+https://github.com/njuj/panoptes

panoptes watch                     # this Windows machine, live: every connection and lookup, with its program
panoptes trap --sinkhole 10.0.0.5  # a DNS server for malware analysis: every name answers with your listener
panoptes analyze capture.pcapng    # Wireshark/tcpdump captures, Zeek dns.log, saved events or a list of domains
```

| mode | what it sees | needs |
|---|---|---|
| `watch` | every new TCP connection (IPv4 and IPv6) and the program that opened it. With the DNS Client log on, also every lookup, its answer, and the program that asked | Windows; `panoptes enable-dns-log` once as administrator for lookups |
| `trap` | every question sent to it. `--sinkhole IP` answers all of them with your address (ApateDNS-style), `--nxdomain` says no name exists, `--guard` forwards normally but sinkholes flagged names, and with no option it forwards and watches | point a machine's or VM's DNS at it; port 53 |
| `analyze` | pcap and pcapng (Ethernet, Linux SLL, raw IP, VLANs; IPv4 and IPv6): DNS, connections and TLS handshakes (the server name, and the certificate up to TLS 1.2), with TCP segments put back in order. Also Zeek `dns.log`, panoptes' own `--save` files, plain domain lists | nothing |

`--json` prints one alert per line for a SIEM. `-v` prints every lookup and connection as it happens. `--save events.jsonl` records them all so you can analyze them again later. Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` alerts, `2` it could not run.

## What it catches

| rule | what it looks for | ATT&CK |
|---|---|---|
| `dns-exfil` | data encoded into names: long hex, base32 or base64 labels, high entropy, many distinct encoded subdomains under one domain (dnscat2, iodine and stealers' DNS channels) | T1048.003 |
| `dns-c2` | repeated TXT / NULL / ANY lookups to one domain: commands and payloads riding in records | T1071.004 |
| `dga` | names that do not read like language, judged by a letter-pair model learned from 4.9 million letter pairs of English | T1568.002 |
| `nx-storm` | one program failing to resolve 10+ different domains in two minutes: a DGA hunting for its live controller | T1568.002 |
| `beacon` | regular check-ins: 6+ contacts at a steady interval (5 s to 2 h, jitter ≤ 20%) to a destination outside the big operators | T1071 |
| `rat-port` | connections on the default ports of njRAT, DarkComet, Quasar, Remcos, AsyncRAT, Poison Ivy, Meterpreter, Cobalt Strike, IRC botnets, Tor | T1571 |
| `lolbin` | `powershell`, `mshta`, `rundll32`, `certutil`, `bitsadmin`… talking to the internet | T1218 |
| `dynamic-dns` · `tunnel` | duckdns, no-ip and friends; ngrok, trycloudflare, serveo… | T1568 · T1572 |
| `chat-api` · `paste` · `file-drop` | the Telegram bot API from anything but Telegram, paste sites, anonymous file drops | T1102 · T1567 |
| `ip-lookup` · `mining-pool` · `tor-gateway` | what-is-my-IP services (a stealer's first question), mining pools, Tor gateways | T1016 · T1496 · T1090.003 |
| `direct-ip` | connections to addresses no lookup produced (only when lookups are visible; in a capture, a TLS server name counts as a lookup) | T1071 |
| `rat-cert` | a server presenting the certificate a RAT or C2 framework generates out of the box: AsyncRAT, DcRat, VenomRAT, Quasar, Cobalt Strike (by name, and by its default keystore's serial) | T1573.002 |
| `doh` | DNS over HTTPS from a program that is not a browser (Cloudflare, Google, Quad9, OpenDNS, AdGuard, NextDNS…): lookups hidden from the DNS log, the trap and DNS filtering | T1071.004 |

**Every name rule also runs on TLS server names.** In a capture, the name in a ClientHello goes through the same checks as a lookup (dynamic DNS, tunnels, paste sites, random names, beacons), so a malware that resolves over DoH, or a capture that started after the lookup, still gives its destination away.

**Context changes severity.** A program running from `Temp`, `Downloads` or the top of `AppData\Roaming` gets one level more. So does a background program calling an IP-lookup or paste service; the same call from a browser is a person, not a stealer. Telegram using its own API is fine. Traffic to big operators (Microsoft, Google, Amazon, Cloudflare, Discord…) never counts as a beacon, because telemetry is periodic by design.

## How well it works

- **Random-name detection:** across 510 real site names (from a test list and from the links in the VS Code, npm and Python files on my machine), **0** were flagged, including words like *cryptography*, *tawakkalna* and *alriyadh*. It catches **83%** of CryptoLocker-style random names and **87%** of hash-based names. Dictionary-word DGAs (like Suppobox) are not caught.
- **TLS on real servers:** handshakes recorded from real connections to github.com and pypi.org (TLS 1.2 and 1.3) and cloudflare-dns.com read back with the right server names and certificates, and raised **0** alerts.
- **The trap, on Windows:** real `nslookup` queries were answered, sinkholed and blocked, each attributed to `nslookup.exe` by the PID owning the source port.
- **watch, on my everyday PC without administrator rights:** it judged 38 open connections from Claude, Chrome, Discord, ASUS and Windows services and raised **0** alerts.
- **Tests:** 28 tests cover simulated dnscat2 and iodine exfiltration, CryptoLocker and hash DGAs, a jittered 30-second RAT beacon, Quasar's port over duckdns, mshta, stealer habits, pcap and Zeek parsing, real OpenSSL handshakes with AsyncRAT and Cobalt Strike certificates, TCP segments out of order, DoH from a background program, and the trap answering over a real socket. They also cover the quiet side: normal browsing and periodic Microsoft telemetry. On GitHub's Windows runner (administrator), CI switches on the DNS Client log and checks that `watch` sees real lookups and flags them.

## Limits

- **DNS over HTTPS bypasses system DNS.** Browsers using DoH (Chrome's and Firefox's secure DNS) send their lookups inside HTTPS, so neither the DNS log nor the trap sees them. Their connections are still seen.
- **Without administrator rights, `watch` sees connections only:** IPs and programs, no names. `panoptes enable-dns-log` fixes that once.
- **Dictionary-word DGAs read like language and pass.** A beacon with very high jitter (over 20%) also passes. These are heuristics; they show you where to look.
- **TLS 1.3 encrypts the certificate,** so `rat-cert` needs TLS 1.2 or older (AsyncRAT and its forks use .NET's SslStream, which still negotiates 1.2 on many systems). Encrypted Client Hello hides the server name too; it is still rare outside Cloudflare.
- **Live mode watches TCP only;** UDP flows other than DNS are not followed.

## Layout

```
panoptes/engine.py    the rules: events in, alerts out
panoptes/domains.py   registrable names, the letter-pair model, encoded-data checks, service lists
panoptes/wire.py      DNS messages on the wire (parse and answer)
panoptes/trap.py      the DNS server: forward, sinkhole, nxdomain, guard
panoptes/windows.py   live Windows: connection tables with owners, the DNS Client log (ctypes, read-only)
panoptes/sources.py   pcap, pcapng, Zeek dns.log, saved events, domain lists; TCP reassembly for TLS
panoptes/tls.py       ClientHello server names, X.509 certificates (a small DER reader), default RAT/C2 certificates
tests/simulate.py     malware-shaped traffic and pcap bytes, generated offline
tests/make_tls_capture.py   real OpenSSL handshakes, in memory, written as tests/fixtures/tls.pcap
```

## License

MIT © kira
