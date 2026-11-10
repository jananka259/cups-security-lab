# CUPS Security Lab

This repository is an isolated investigation of CUPS printer discovery. It
implements a Scapy advertisement tool, a Scapy detector, a vulnerable Vulhub
victim, and an `ippserver` virtual printer. The authoritative specification is
[assignment.md](./assignment.md).

## Architecture

```text
Kali/host tooling
        |
        | Docker Desktop internal network: 172.28.77.0/24
        |
+-------+-----------+------------------+
| attacker .10     | victim .20       | printer .30
| Ubuntu + Scapy   | cups-browsed 2.0.1| ippserver
| tcpdump          | internal only     | TCP/631
+------------------+------------------+
```

The attacker container has only `NET_RAW`, no published ports, and mounts the
attack/detection scripts plus evidence directories. The victim and printer
also have no published ports. The printer exposes `ippserver` internally on
TCP/631. Docker Desktop on Apple Silicon uses `linux/amd64` emulation for the
Vulhub victim; Kali can run separately in VMware Fusion and does not need
Docker.

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
docker compose build
docker compose up -d
docker compose ps
```

The attacker image installs Python, Scapy, `tcpdump`, and `iproute2`. The
printer image installs `ippserver`, `tcpdump`, and `netcat-openbsd` for
controlled baseline advertisements.

## Tools

[`cups_attack.py`](./cups_attack.py) constructs the historical five-field
UDP/631 browse datagram, writes a PCAP and log, and can transmit only after
`--authorize-lab` is supplied. The fixed live destination is
`172.28.77.20`; all live source and advertised endpoints must be inside
`172.28.77.0/24`. Use `--dry-run` for offline evidence; without it, live transmission requires
the explicit `--authorize-lab` flag.

[`cups_detector.py`](./cups_detector.py) validates five browse fields and IPP
URIs, keeps advertiser and printer allowlists separate, correlates later TCP
connections with advertised endpoints, detects repetition inside a configurable
time window, and exports JSON or CSV alerts with rule IDs.

## Experiments

Generate fixtures without transmitting:

```bash
python cups_attack.py --dry-run --advertiser-ip 172.28.77.30 \
  --printer-ip 172.28.77.30 --queue printers/lab \
  --pcap pcap_files/attacks/fixture-normal.pcap
python cups_attack.py --dry-run --queue printers/lab --repeat 3 \
  --pcap pcap_files/attacks/fixture-repeated.pcap
python cups_attack.py --dry-run --variation invalid-port --queue printers/lab \
  --pcap pcap_files/attacks/fixture-invalid-port.pcap
python cups_attack.py --dry-run --variation malformed-fields --queue printers/lab \
  --pcap pcap_files/attacks/fixture-malformed.pcap
```

Run a controlled live attack from the attacker container:

```bash
docker exec cups-attacker python3 /opt/lab/cups_attack.py \
  --authorize-lab --queue printers/lab \
  --pcap /tmp/attack.pcap --log /opt/lab/evidence/logs/live-attack.log
```

The legacy browse parser in this specific `cups-browsed` build accepts
`/printers/<queue>` for discovery. The `ippserver`'s actual standards-oriented
endpoint is `/ipp/print`; advertising it was captured and measured to produce
`Don't understand URI`, so the report records that incompatibility rather than
claiming a successful queue. The `/printers/lab` experiment demonstrates the
vulnerable discovery and subsequent IPP request attempt.

**Attacker-endpoint observation:** the unauthorized advertisement names
`172.28.77.40:631`, but none of the seven existing real captures contains a
recorded packet from the victim (`172.28.77.20`) to that endpoint. The capture
therefore proves that the advertisement was sent, **not** that the victim
connected to the attacker-controlled endpoint. This does not exclude traffic
outside the observed capture scope. The legitimate `.30` handshake is separate
evidence and must not be used as proof of a `.40` connection.

Analyze offline or real captures:

```bash
python cups_detector.py --pcap pcap_files/real/legitimate-clean.pcap \
  --allow-advertiser 172.28.77.30 --allow-printer 172.28.77.30 \
  --output evidence/detection_results/real-legitimate.json
python cups_detector.py --live --allow-printer 172.28.77.30 \
  --output evidence/detection_results/live.json
```

## Capture method

Host `tcpdump` failed with `Operation not permitted` on Docker Desktop. The
reproducible workaround captures inside the relevant Linux container namespace:

```bash
docker exec cups-printer tcpdump -i any -U -c 30 \
  -w /lab/pcap_files/real/legitimate-clean.pcap \
  'udp port 631 or tcp port 631'
docker exec cups-attacker tcpdump -i any -U -c 1 \
  -w /opt/lab/pcap_files/real/unauthorized.pcap 'udp port 631'
```

The resulting `pcap_files/real/` files are independent captures of packets
observed on container interfaces, not merely `wrpcap` output from the attack
tool. `tcpdump -r <file> -nn` verifies readability.

## Mitigation

The reversible mitigation allowlists the authorized printer endpoint:

```bash
docker compose -f docker-compose.yml -f docker-compose.mitigated.yml up -d victim
docker compose -f docker-compose.yml -f docker-compose.mitigated.yml down
```

[`mitigation/cups-browsed.conf`](./mitigation/cups-browsed.conf) uses
`BrowseAllow 172.28.77.30`, which was verified on cups-browsed 2.0.1 to allow
the `.30` advertisement and reject the attacker `.10` advertisement. The
pre/post packet captures remain detectable by the detector; the mitigation
effect is verified by victim logs showing `browse packet from 172.28.77.10
disallowed`. The available captures do not establish a complete end-to-end
absence of unauthorized IPP attempts, so prevention evidence is based on the
explicit browse rejection log.

## Tests

```bash
python3 -m pytest -q
python3 -m py_compile cups_attack.py cups_detector.py
docker compose config
```

The test suite covers packet formatting, UTF-8 fields, unsafe input,
allowlists, malformed/truncated packets, empty PCAPs, time-window repetition,
correlated IPP connections, JSON/CSV export, and CLI validation.

## Troubleshooting and safety

- If Docker cannot build `attacker`, verify Docker Desktop has network access
  for the Ubuntu base image and Scapy installation.
- If live capture is empty, start `tcpdump` first and wait for its
  `listening` message before sending traffic.
- Do not publish the victim or printer ports and do not run live transmission
  without `--authorize-lab`.
- Use only the private `172.28.77.0/24` network and authorized lab systems.
- Stop the lab with `docker compose down` after evidence collection.

## Evidence inventory

- Real packet captures: [pcap_files/real/](./pcap_files/real/)
- Generated fixtures: [pcap_files/](./pcap_files/)
- Logs: [evidence/logs/](./evidence/logs/)
- Detector results: [evidence/detection_results/](./evidence/detection_results/)
- Selected Wireshark, detector, and mitigation screenshots:
  [evidence/screenshots/](./evidence/screenshots/)
- Final report: [LaTeX source](./report/report.tex),
  [PDF](./report/report.pdf), and [figure files](./report/figures/).
- The older [Markdown research notes](./report/report.md) are retained for
  traceability; the LaTeX/PDF pair is the final submission report.

## Requirements traceability

| Assignment requirement | Responsible source | Status | Verification | Evidence | Remaining work |
|---|---|---|---|---|---|
| Isolated victim, printer, attacker | Compose and Dockerfiles | Verified | `docker compose ps`, network inspection, attacker `.10` | `evidence/logs/network-inspect.txt` | None |
| Normal discovery traffic | Attack tool and printer sender | Verified with limitation | Real UDP/TCP capture; CUPS logs | `pcap_files/real/legitimate-clean.pcap` | None |
| Scapy construction and advertisement | `cups_attack.py` | Verified | 11 tests and live attacker capture | `pcap_files/real/unauthorized.pcap` | None |
| Address, port, field manipulation | `cups_attack.py` | Verified | Four variations and detector results | `pcap_files/real/` | None |
| CLI, logging, PCAP export | `cups_attack.py` | Verified | Dry-run and authorized live commands | `evidence/logs/` | None |
| Unauthorized/suspicious/repeated/malformed detection | `cups_detector.py` | Verified | 11 tests and real captures | `evidence/detection_results/real-*.json` | None |
| Live/offline and JSON/CSV | `cups_detector.py` | Verified | CLI execution and export tests | `evidence/detection_results/` | None |
| Experiments and evaluation | Report, captures, tests | Verified with stated limitations | Real capture counts, logs, screenshots; `.40` connection not observed | [report/report.pdf](./report/report.pdf) | None beyond stated capture limitation |
| Mitigation and comparison | Mitigated Compose override | Verified | Authorized `.30` accepted; attacker `.10` disallowed | `evidence/logs/live-mitigated-victim.log` | None |
| README, requirements, PCAP, evidence, PDF | Repository | Verified | File checks and PDF generation | Root, evidence, report | None |
