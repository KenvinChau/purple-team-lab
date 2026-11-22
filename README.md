# Purple Team Lab
![tests](https://github.com/KenvinChau/purple-team-lab/actions/workflows/detection-tests.yml/badge.svg)

Write-up: [what testing my own rules found](docs/WRITEUP.md)

A free, reproducible lab where I attack a deliberately vulnerable web app
(DVWA) with standard tools (nmap, sqlmap), write Suricata detection rules,
and test them against recorded traffic, including harmless traffic that
looks suspicious.

## Safety and legal

Intentionally vulnerable target, bound to localhost only. Never expose it to a
network. Only attack systems you own.

## Detection results

Alerts per recording (`scripts/matrix.cmd`, Suricata run offline on pcaps).

| Recording | 1000001 scan | 1000002 UNION | 1000003 SLEEP | 1000004 boolean | 1000005 quote |
|---|:---:|:---:|:---:|:---:|:---:|
| nmap connect scan | 1 | 0 | 0 | 0 | 0 |
| sqlmap (all techniques) | 0 | 8 | 7 | 57 | 15 |
| normal browsing | 0 | 0 | 0 | 0 | 0 |
| hand-written SQLi | 0 | 1 | 0 | 0 | 1 |
| hand-written `1 OR 1=1` | 0 | 0 | 0 | 1 | 0 |
| harmless look-alikes | 0 | 0 | 0 | 0 | 0 |
| sqlmap with `space2comment` | 0 | 10 | 11 | 57 | 15 |

Rules map to MITRE ATT&CK T1046 (network service discovery) and T1190
(exploit public-facing application).

## What testing my own rules found

- Rule 1 (port scan) first counted SYN packets and also flagged sqlmap
  (3 false alerts). v2 counts refused connections instead: 0 false alerts.
- A hand-written `' OR '1'='1` slipped past the rules I had built from
  sqlmap's output. I added a quote-based rule (1000005).
- `1 OR 1=1` slipped past too, because browsers encode spaces as `+`. Rule
  1000004 v2 accepts it.
- That loosening made the harmless sentence "formula 2 and 2=4" fire, and
  so did "union station select" on rule 1000002. Rules 2 and 4 were tightened
  (v2 and v3); the false positives went to 0 without losing any recorded attack.

## Known limitations

- Rule 1000002 requires `UNION` directly followed by `SELECT`, so
  `UNION/**/SELECT` evades it.
- Rule 1000004 still matches `2 and 2=2` in harmless text.
- No rule covers error-based SQL injection yet.
- Rule 1000001 has not been tested against bursty legitimate traffic.
- The test set is small. "No false positives found" means in these recordings.

## Status

- [x] Lab and traffic capture
- [x] Five Suricata rules with positive and negative controls
- [ ] Automated tests in CI
- [ ] Sigma rules
- [ ] Write-up

## Run the tests

Requires Docker and Python 3.

    pip install pytest
    python -m pytest -v

Each test replays one recording from `attacks/` through Suricata and compares
the alert counts per rule with the table in `docs/WRITEUP.md`.

## More

- Write-up of findings and limitations: `docs/WRITEUP.md`
- Rules: `rules/suricata/local.rules`
- Sanitizing recordings before committing them: `scripts/sanitize_pcap.py`

## Quick start

    docker compose up -d
    # open http://localhost:4280  (admin / password), set security level to Low