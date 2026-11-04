#!/usr/bin/env python3
"""Detect suspicious CUPS discovery and IPP activity in PCAPs or live traffic."""

from __future__ import annotations

import argparse
import csv
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Iterable

from scapy.all import IP, Raw, TCP, UDP, Packet, rdpcap, sniff

URI_RE = re.compile(r"^ipp://(?P<host>[^:/\s]+):(?P<port>\d{1,5})/(?P<queue>\S+)$")


def alert(kind: str, severity: str, packet: Packet, detail: str) -> dict[str, object]:
    return {
        "timestamp": float(getattr(packet, "time", time.time())),
        "type": kind,
        "severity": severity,
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "detail": detail,
    }


def inspect_packets(
    packets: Iterable[Packet],
    allowed_advertisers: set[str],
    allowed_printers: set[str],
    repeat_threshold: int = 3,
) -> list[dict[str, object]]:
    """Return deterministic alerts for discovery, IPP, repetition, and malformed fields."""
    packets = list(packets)
    alerts: list[dict[str, object]] = []
    signatures: Counter[str] = Counter()
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        if packet.haslayer(UDP) and packet[UDP].dport == 631 and packet.haslayer(Raw):
            text = bytes(packet[Raw].load).decode("ascii", errors="replace").strip()
            fields = text.split()
            if len(fields) < 3:
                alerts.append(alert("malformed_discovery", "high", packet, "fewer than three fields"))
                continue
            match = URI_RE.match(fields[2])
            if not match:
                alerts.append(alert("malformed_discovery", "high", packet, "invalid IPP URI"))
                continue
            host = match.group("host")
            port = int(match.group("port"))
            signature = f"{packet[IP].src}|{text}"
            signatures[signature] += 1
            if packet[IP].src not in allowed_advertisers:
                alerts.append(alert("unauthorized_advertisement", "high", packet, f"advertiser {packet[IP].src} is not allowlisted"))
            if host not in allowed_printers or port != 631:
                alerts.append(alert("suspicious_printer_endpoint", "medium", packet, f"advertised endpoint {host}:{port}"))
        elif packet.haslayer(TCP) and (packet[TCP].dport == 631 or packet[TCP].sport == 631):
            if packet[IP].src not in allowed_printers and packet[IP].dst not in allowed_printers:
                alerts.append(alert("suspicious_ipp_connection", "medium", packet, "TCP/631 endpoint is outside the printer allowlist"))
    for signature, count in signatures.items():
        if count >= repeat_threshold:
            source, _ = signature.split("|", 1)
            matching = next(p for p in packets if p.haslayer(IP) and p[IP].src == source)
            alerts.append(alert("repeated_discovery", "medium", matching, f"same advertisement observed {count} times"))
    return alerts


def write_results(alerts: list[dict[str, object]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
        return
    if path.suffix.lower() != ".csv":
        raise ValueError("output must end in .json or .csv")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("timestamp", "type", "severity", "src", "dst", "detail"))
        writer.writeheader()
        writer.writerows(alerts)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path)
    source.add_argument("--live", action="store_true")
    parser.add_argument("--allow-advertiser", action="append", default=[])
    parser.add_argument("--allow-printer", action="append", default=[])
    parser.add_argument("--repeat-threshold", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("evidence/detection_results/alerts.json"))
    parser.add_argument("--count", type=int, default=0, help="live packets; zero means until interrupted")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    packets = sniff(count=args.count, store=True) if args.live else rdpcap(str(args.pcap))
    alerts = inspect_packets(packets, set(args.allow_advertiser), set(args.allow_printer), args.repeat_threshold)
    write_results(alerts, args.output)
    print(json.dumps({"packets": len(packets), "alerts": len(alerts), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
