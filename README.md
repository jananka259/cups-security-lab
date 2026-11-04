# CUPS Security Lab

This repository is an isolated, reproducible investigation of insecure CUPS
printer discovery. It uses Scapy to craft legacy UDP/631 browse advertisements
and to detect unauthorized advertisements, suspicious IPP connections,
repetition, and malformed fields. The authoritative specification is
[assignment.md](./assignment.md).

## Architecture

`docker-compose.yml` creates an internal-only `172.28.77.0/24` network:

- `victim` is `vulhub/cups-browsed:2.0.1` at `172.28.77.20`.
- `printer` is an `ippserver` software printer at `172.28.77.30`.
- the host-side attacker tool can target the lab only when explicitly attached
  to the lab network or can generate offline PCAP fixtures with `--dry-run`.

[`cups_attack.py`](./cups_attack.py) constructs an IP/UDP/Raw packet, writes
PCAP and log evidence, and optionally transmits it. [`cups_detector.py`](./cups_detector.py)
shares the same packet model, supports offline PCAP or live Scapy capture, and
exports JSON or CSV alerts.

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
docker compose build printer
docker compose pull victim
```

Run only in the isolated lab:

```bash
docker compose up -d
docker compose ps
```

## Execution and experiment workflow

Generate the four repeatable discovery cases without sending traffic:

```bash
python cups_attack.py --dry-run --variation baseline --pcap pcap_files/normal/normal.pcap
python cups_attack.py --dry-run --variation baseline --repeat 3 --pcap pcap_files/attacks/repeated.pcap
python cups_attack.py --dry-run --variation invalid-port --pcap pcap_files/attacks/invalid-port.pcap
python cups_attack.py --dry-run --variation malformed-fields --pcap pcap_files/attacks/malformed.pcap
```

Analyze a capture and export evidence:

```bash
python cups_detector.py --pcap pcap_files/attacks/repeated.pcap \
  --allow-advertiser 172.28.77.30 --allow-printer 172.28.77.30 \
  --output evidence/detection_results/repeated.json
python cups_detector.py --live --allow-printer 172.28.77.30 \
  --output evidence/detection_results/live.json
```

Capture real lab traffic with `tcpdump` on the Docker bridge, then repeat the
detector command. Apply the mitigation by restricting host access to UDP/631
and by configuring the victim to allowlist `172.28.77.30`; the repository
provides the runnable `docker-compose.mitigated.yml` override and
`mitigation/cups-browsed.conf`. Compare alert output before and after. Keep
only isolated, authorized test traffic.

## Tests and evidence

```bash
pytest -q
```

The experiment matrix, measured results, limitations, and ethics discussion
are in [report/report.md](./report/report.md). Raw PCAPs are under
[pcap_files/](./pcap_files/), logs under [evidence/logs/](./evidence/logs/),
and detector exports under [evidence/detection_results/](./evidence/detection_results/).

## Requirements traceability

| Assignment requirement | Responsible source file | Implementation status | Verification method | Evidence location | Remaining work |
|---|---|---|---|---|---|
| Isolated vulnerable CUPS, virtual printer, attacker | `docker-compose.yml`, `Dockerfile.printer` | Implemented | `docker compose ps`, isolated network inspection | `report/report.md` environment section | Run Docker capture on target host |
| Normal printer-discovery traffic | `cups_attack.py` | Implemented | Baseline PCAP generation and detector run | `pcap_files/normal/`, `evidence/detection_results/` | Capture real CUPS exchange |
| Scapy packet construction and printer advertisement | `cups_attack.py` | Implemented | `pytest`, `--dry-run` PCAP inspection | `pcap_files/attacks/` | Live transmission requires lab privileges |
| Address, port, and field manipulation | `cups_attack.py` | Implemented | Three variation fixtures and tests | `report/report.md` experiments | None for offline proof |
| CLI, logging, and PCAP export | `cups_attack.py` | Implemented | CLI commands and output files | `evidence/logs/` | None |
| Unauthorized, suspicious, repeated, malformed detection | `cups_detector.py` | Implemented | Focused pytest cases and detector JSON | `evidence/detection_results/` | Evaluate against real capture |
| Live and offline detection, JSON/CSV | `cups_detector.py` | Implemented | CLI help, offline fixture, live command | `evidence/detection_results/` | Live capture requires lab privileges |
| Four experiments and analysis | `report/report.md`, `tests/test_tools.py` | Partially verified | Automated fixtures and alert counts | `report/report.md`, `evidence/` | Run real Docker experiments and screenshots |
| Mitigation and before/after comparison | `docker-compose.mitigated.yml`, `mitigation/cups-browsed.conf` | Implemented and verified | Restarted victim and replayed unauthorized advertisement; log showed `disallowed` | `evidence/logs/docker-victim.log`, `evidence/logs/docker-mitigated-victim.log` | Capture packet-level before/after PCAP |
| README, requirements, PCAP, evidence, PDF report | repository root | Implemented | File checks, pytest, generated PDF | `README.md`, `requirements.txt`, `report/report.pdf` | Add screenshots from final host run |
# cups-security-lab
