Screenshots were not fabricated. On a host with GUI capture capability, take:

1. `docker compose ps` and `docker network inspect cups-security-lab_cups-lab`.
2. The printer's `ippserver` startup log.
3. `live-baseline-victim.log` showing discovery and IPP requests.
4. `real-unauthorized.json` and the matching victim log.
5. Wireshark or `tcpdump -r` showing `172.28.77.10:631 -> 172.28.77.20:631`.
6. `live-mitigated-victim.log` showing `browse packet ... disallowed`.

The text logs and real PCAPs in this repository are the non-fabricated evidence
for environments where macOS GUI screenshot automation is unavailable.
