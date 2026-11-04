
# CUPS Printer Discovery Exploitation and Attack Detection Using Scapy

**Deadline:** November 16, 2026, 23:59  
**Submission:** GitHub repository and PDF report  
**Assignment type:** Individual

## Scenario

The Common Unix Printing System (CUPS) is widely used to manage printers in Linux environments.

In 2024, several vulnerabilities were discovered in CUPS, including CVE-2024-47176, CVE-2024-47076, and CVE-2024-47175, allowing attackers to manipulate printer-discovery mechanisms and potentially compromise vulnerable systems.

In this assignment, you will investigate these vulnerabilities by developing Scapy-based attack and detection tools against an existing vulnerable CUPS environment.

Vulnerable environment:

https://github.com/vulhub/vulhub/tree/master/cups-browsed/CVE-2024-47177

Note: The Vulhub directory retains the rejected CVE-2024-47177 identifier.

## Task 1 — Virtual Environment Setup

Set up an isolated laboratory containing:

- **Attacker:** Kali Linux or Ubuntu with Python, Scapy, and Wireshark/tcpdump.
- **Victim:** Vulnerable CUPS Docker container provided by Vulhub.
- **Virtual Printer:** A software-based IPP server, such as OpenPrinting's `ippserver`.

No physical printer is required.

Students may use existing software to simulate a network printer.

Document the network configuration and capture normal printer-discovery traffic.

## Task 2 — CUPS Attack Tool Using Scapy

Develop `cups_attack.py` to investigate insecure printer discovery.

The tool must:

- Construct and send custom CUPS printer-discovery packets using Scapy.
- Advertise an attacker-controlled virtual printer to the vulnerable CUPS service.
- Manipulate printer addresses, ports, and discovery message fields.
- Demonstrate whether the victim initiates communication with the advertised printer.
- Support command-line arguments, logging, and PCAP export.

Full remote code execution is not required.

Focus on demonstrating the insecure printer-discovery mechanism.

## Task 3 — CUPS Attack Detection Tool

Develop `cups_detector.py` using Scapy to identify suspicious CUPS network activity.

Implement detection for:

- Unauthorized printer advertisements.
- Suspicious IPP connections.
- Repeated or abnormal printer-discovery messages.
- Malformed or unexpected protocol fields.

The tool must:

- Support live monitoring or offline PCAP analysis.
- Generate security alerts.
- Export results to CSV or JSON.

## Task 4 — Attack Simulation and Analysis

Perform the following experiments:

### Experiment 1 — Normal Traffic

Capture legitimate communication between CUPS and the virtual printer.

### Experiment 2 — Unauthorized Discovery

Use the attack tool to advertise an attacker-controlled printer.

### Experiment 3 — Packet Manipulation

Test at least three variations of crafted discovery messages.

### Experiment 4 — Detection

Analyze normal and attack traffic using the detection tool.

Provide:

- PCAP files.
- Screenshots.
- Logs.
- Explanation of observed behavior.

Evaluate:

- Successful detections.
- False positives.
- Missed attacks.

## Task 5 — Defence and Mitigation

Investigate security measures such as:

- Restricting UDP port 631.
- Disabling unnecessary `cups-browsed` functionality.
- Allowlisting authorized printer addresses.
- Applying security patches.
- Network segmentation.

Implement at least one mitigation.

Compare the results before and after applying it.

## Submission Requirements

This is an individual assignment.

Submit a GitHub repository containing:

- `cups_attack.py` — Scapy-based attack tool.
- `cups_detector.py` — Scapy-based detection tool.
- `README.md`
- `requirements.txt`
- `pcap_files/` — captured network traffic.
- `evidence/` — screenshots and logs.

Submit a PDF report describing:

- Environment.
- Tool implementations.
- Experiments.
- Results.
- Mitigations.
- Ethical considerations.

## Important Rules

- Use only isolated Docker containers or virtual machines.
- No physical printer is required.
- Students must develop their own Scapy-based attack and detection logic.
- Existing vulnerable environments and software-based printer simulators may be used.

## Implementation Checklist

### Environment
- [ ] Vulnerable CUPS container running
- [ ] Virtual IPP printer running
- [ ] Ubuntu/Kali attacker configured
- [ ] Network isolation verified
- [ ] Normal printer traffic captured

### Attack Tool
- [ ] Scapy packet construction
- [ ] Printer advertisement
- [ ] Custom address and port
- [ ] Discovery field manipulation
- [ ] CLI arguments
- [ ] Logging
- [ ] PCAP export

### Detection Tool
- [ ] Unauthorized advertisement detection
- [ ] Suspicious IPP connection detection
- [ ] Repeated-message detection
- [ ] Malformed-packet detection
- [ ] Live capture
- [ ] Offline PCAP analysis
- [ ] JSON/CSV export

### Experiments
- [ ] Normal traffic
- [ ] Unauthorized discovery
- [ ] Three packet variations
- [ ] Detection evaluation
- [ ] False-positive analysis
- [ ] Missed-attack analysis

### Mitigation
- [ ] Mitigation implemented
- [ ] Before/after comparison
- [ ] Evidence captured

### Submission
- [ ] README complete
- [ ] Requirements documented
- [ ] PCAP files included
- [ ] Screenshots and logs included
- [ ] PDF report generated
- [ ] GitHub repository prepared

