#!/usr/bin/env python3
"""Detect suspicious CUPS discovery and correlated IPP activity."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import shlex
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from scapy.all import IP, Raw, TCP, UDP, Packet, rdpcap, sniff

RULES = {
    "unauthorized_advertisement": ("high", "DISCOVERY-001"),
    "suspicious_printer_endpoint": ("medium", "DISCOVERY-002"),
    "malformed_discovery": ("high", "DISCOVERY-003"),
    "repeated_discovery": ("medium", "DISCOVERY-004"),
    "suspicious_ipp_connection": ("medium", "IPP-001"),
}


def alert(rule: str, packet: Packet, detail: str) -> dict[str, object]:
    severity, rule_id = RULES[rule]
    return {
        "timestamp": float(getattr(packet, "time", time.time())),
        "rule_id": rule_id,
        "type": rule,
        "severity": severity,
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "detail": detail,
    }


def parse_advertisement(packet: Packet) -> tuple[str, str, int, str] | tuple[None, str, None, str]:
    """Validate a browse payload and return advertised host, port, and URI."""
    if not packet.haslayer(Raw):
        return None, "missing discovery payload", None, ""
    try:
        fields = shlex.split(bytes(packet[Raw].load).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "payload is not valid UTF-8 or quoted text", None, ""
    if len(fields) != 5:
        return None, f"expected 5 fields, received {len(fields)}", None, ""
    if not fields[0].lstrip("-").isdigit() or not fields[1].lstrip("-").isdigit():
        return None, "message type and state must be integers", None, ""
    try:
        parsed = urlsplit(fields[2])
    except ValueError:
        return None, "invalid IPP URI syntax", None, fields[2]
    if parsed.scheme != "ipp" or not parsed.hostname or not parsed.path.strip("/"):
        return None, "invalid IPP URI syntax", None, fields[2]
    try:
        port = parsed.port
    except ValueError:
        return None, "IPP URI contains an invalid port", None, fields[2]
    if port is None or not 1 <= port <= 65535:
        return None, "IPP URI port must be between 1 and 65535", None, fields[2]
    return parsed.hostname, "", port, fields[2]


def inspect_packets(
    packets: Iterable[Packet],
    allowed_advertisers: set[str],
    allowed_printers: set[str],
    repeat_threshold: int = 3,
    repeat_window: float = 60.0,
) -> list[dict[str, object]]:
    """Inspect packets using allowlists, validation, repetition, and correlation."""
    if repeat_threshold < 1:
        raise ValueError("repeat_threshold must be at least 1")
    if repeat_window < 0:
        raise ValueError("repeat_window must not be negative")
    packet_list = list(packets)
    alerts: list[dict[str, object]] = []
    signatures: defaultdict[str, list[Packet]] = defaultdict(list)
    advertised_endpoints: set[tuple[str, int]] = set()

    for packet in packet_list:
        if not packet.haslayer(IP):
            continue
        if packet.haslayer(UDP) and packet[UDP].dport == 631:
            host, error, port, uri = parse_advertisement(packet)
            if error:
                alerts.append(alert("malformed_discovery", packet, error))
                continue
            assert host is not None and port is not None
            signatures[f"{packet[IP].src}|{bytes(packet[Raw].load)}"].append(packet)
            advertised_endpoints.add((host, port))
            if packet[IP].src not in allowed_advertisers:
                alerts.append(
                    alert(
                        "unauthorized_advertisement",
                        packet,
                        f"advertiser {packet[IP].src} is not allowlisted; advertised endpoint is {host}:{port}",
                    )
                )
            if host not in allowed_printers or port != 631:
                alerts.append(
                    alert(
                        "suspicious_printer_endpoint",
                        packet,
                        f"advertised endpoint {host}:{port} is not an allowed printer endpoint",
                    )
                )
        elif packet.haslayer(TCP) and (packet[TCP].dport or 0) > 0:
            endpoint = (packet[IP].dst, packet[TCP].dport)
            reverse_endpoint = (packet[IP].src, packet[TCP].sport)
            if endpoint in advertised_endpoints and (
                endpoint[0] not in allowed_printers or endpoint[1] != 631
            ):
                alerts.append(
                    alert(
                        "suspicious_ipp_connection",
                        packet,
                        f"connection correlates with advertised unauthorized endpoint {endpoint[0]}:{endpoint[1]}",
                    )
                )
            elif reverse_endpoint in advertised_endpoints and (
                reverse_endpoint[0] not in allowed_printers or reverse_endpoint[1] != 631
            ):
                alerts.append(
                    alert(
                        "suspicious_ipp_connection",
                        packet,
                        f"response correlates with advertised unauthorized endpoint {reverse_endpoint[0]}:{reverse_endpoint[1]}",
                    )
                )

    for packets_for_signature in signatures.values():
        timestamps = [float(getattr(item, "time", 0)) for item in packets_for_signature]
        if len(timestamps) >= repeat_threshold and max(timestamps) - min(timestamps) <= repeat_window:
            alerts.append(
                alert(
                    "repeated_discovery",
                    packets_for_signature[0],
                    f"same advertisement observed {len(timestamps)} times within {repeat_window:g}s",
                )
            )
    return alerts


def write_results(alerts: list[dict[str, object]], path: Path) -> None:
    """Write alerts to JSON or CSV, rejecting unsupported output formats."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ("timestamp", "rule_id", "type", "severity", "src", "dst", "detail")
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
        return
    if path.suffix.lower() != ".csv":
        raise ValueError("output must end in .json or .csv")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
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
    parser.add_argument("--repeat-window", type=float, default=60.0)
    parser.add_argument("--output", type=Path, default=Path("evidence/detection_results/alerts.json"))
    parser.add_argument("--count", type=int, default=0, help="live packets; zero means until interrupted")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeat_threshold < 1:
        raise SystemExit("--repeat-threshold must be at least 1")
    if args.repeat_window < 0:
        raise SystemExit("--repeat-window must not be negative")
    if args.count < 0:
        raise SystemExit("--count must not be negative")
    try:
        packets = sniff(count=args.count, store=True) if args.live else rdpcap(str(args.pcap))
        alerts = inspect_packets(
            packets,
            set(args.allow_advertiser),
            set(args.allow_printer),
            args.repeat_threshold,
            args.repeat_window,
        )
        write_results(alerts, args.output)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"detection failed: {exc}") from exc
    print(json.dumps({"packets": len(packets), "alerts": len(alerts), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
