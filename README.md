# Purple Team Lab

Work in progress. A free, reproducible lab where I attack a vulnerable web app
(DVWA), write detection rules for Suricata, and test them against recorded
traffic.

## Safety and legal

Intentionally vulnerable target, bound to localhost only. Never expose it to a
network. Only attack systems you own.

## Detection results so far

Each rule is run against recorded traffic (`scripts/matrix.cmd`). Expected
results are marked; counts are alerts per recording.

| Recording | Port scan (1000001) | SQLi rules (1000002-1000005) |
|---|---|---|
| nmap connect scan | 1 | 0 |
| sqlmap | 0 | 8 / 7 / 119 / 15 |
| normal browsing | 0 | 0 |

Rules map to MITRE ATT&CK T1046 (network scanning) and T1190 (exploiting a
public-facing app).

## Status

- [x] Lab and traffic capture
- [x] Suricata rules, tested with positive and negative controls
- [ ] Sigma rules, CI, write-up

## Quick start

    docker compose up -d
    # open http://localhost:4280  (admin / password), set security level to Low