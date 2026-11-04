from scapy.all import IP, TCP, Raw, UDP

from cups_attack import build_advertisement, build_variation
from cups_detector import inspect_packets


def test_attack_packet_contains_custom_endpoint():
    packet = build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40", 9999)
    assert packet[UDP].dport == 631
    assert b"ipp://10.0.0.40:9999/" in bytes(packet[Raw].load)


def test_detector_flags_unauthorized_and_malformed():
    packets = [
        build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40"),
        build_variation(
            "malformed-fields",
            source_ip="10.0.0.40",
            destination_ip="10.0.0.20",
            printer_ip="10.0.0.40",
        ),
    ]
    kinds = {item["type"] for item in inspect_packets(packets, {"10.0.0.30"}, {"10.0.0.30"})}
    assert {"unauthorized_advertisement", "malformed_discovery"} <= kinds


def test_detector_flags_repetition_and_suspicious_tcp():
    packet = build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40")
    tcp = IP(src="10.0.0.40", dst="10.0.0.20") / TCP(sport=40000, dport=631)
    kinds = {item["type"] for item in inspect_packets([packet] * 3 + [tcp], set(), {"10.0.0.30"})}
    assert {"repeated_discovery", "suspicious_ipp_connection"} <= kinds
