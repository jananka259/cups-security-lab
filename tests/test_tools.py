import csv
import json
import subprocess
import sys

import pytest
from scapy.all import IP, Raw, TCP, UDP, rdpcap

from cups_attack import build_advertisement, build_variation
from cups_detector import inspect_packets, write_results


def test_attack_packet_contains_custom_endpoint_and_termination():
    packet = build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40", 9999)
    assert packet[UDP].sport == packet[UDP].dport == 631
    assert bytes(packet[Raw].load).endswith(b'"')
    assert b"ipp://10.0.0.40:9999/ipp/print" in bytes(packet[Raw].load)


def test_attack_supports_utf8_and_rejects_unsafe_fields():
    packet = build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40", printer_name="Lab \u03c0")
    assert "\u03c0".encode() in bytes(packet[Raw].load)
    with pytest.raises(ValueError):
        build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40", printer_name='bad"field')


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


def test_detector_accepts_authorized_advertisement_without_false_positive():
    packet = build_advertisement("10.0.0.30", "10.0.0.20", "10.0.0.30")
    assert inspect_packets([packet], {"10.0.0.30"}, {"10.0.0.30"}) == []


def test_detector_flags_repetition_only_inside_time_window():
    packets = [build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40") for _ in range(3)]
    for index, packet in enumerate(packets):
        packet.time = index * 10
    assert any(item["type"] == "repeated_discovery" for item in inspect_packets(
        packets, set(), set(), repeat_threshold=3, repeat_window=20
    ))
    assert not any(item["type"] == "repeated_discovery" for item in inspect_packets(
        packets, set(), set(), repeat_threshold=3, repeat_window=5
    ))


def test_detector_correlates_suspicious_ipp_connection():
    advertisement = build_advertisement("10.0.0.40", "10.0.0.20", "10.0.0.40", 9999)
    connection = IP(src="10.0.0.20", dst="10.0.0.40") / TCP(sport=40000, dport=9999)
    kinds = {item["type"] for item in inspect_packets([advertisement, connection], set(), {"10.0.0.30"})}
    assert "suspicious_ipp_connection" in kinds


def test_detector_ignores_unrelated_tcp_and_empty_capture():
    unrelated = IP(src="10.0.0.20", dst="10.0.0.30") / TCP(sport=40000, dport=631)
    assert inspect_packets([], set(), set()) == []
    assert inspect_packets([unrelated], set(), {"10.0.0.30"}) == []


def test_detector_handles_invalid_port_and_truncated_payload():
    invalid = build_variation(
        "invalid-port",
        source_ip="10.0.0.40",
        destination_ip="10.0.0.20",
        printer_ip="10.0.0.40",
    )
    truncated = IP(src="10.0.0.40", dst="10.0.0.20") / UDP(dport=631) / Raw(load=b"0 3")
    kinds = {item["type"] for item in inspect_packets([invalid, truncated], set(), set())}
    assert "malformed_discovery" in kinds


def test_json_and_csv_exports(tmp_path):
    alerts = [{"timestamp": 1.0, "rule_id": "TEST", "type": "test", "severity": "low",
               "src": "1.1.1.1", "dst": "2.2.2.2", "detail": "detail"}]
    json_path = tmp_path / "alerts.json"
    csv_path = tmp_path / "alerts.csv"
    write_results(alerts, json_path)
    write_results(alerts, csv_path)
    assert json.loads(json_path.read_text())[0]["rule_id"] == "TEST"
    with csv_path.open(newline="") as handle:
        assert next(csv.DictReader(handle))["type"] == "test"


def test_empty_pcap_is_readable(tmp_path):
    pcap = tmp_path / "empty.pcap"
    from scapy.all import wrpcap
    wrpcap(str(pcap), [])
    assert inspect_packets(rdpcap(str(pcap)), set(), set()) == []


def test_cli_rejects_unsafe_live_transmission():
    result = subprocess.run(
        [sys.executable, "cups_attack.py", "--printer-port", "0"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "between 1 and 65535" in result.stderr
