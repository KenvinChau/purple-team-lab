# Detecting nmap and sqlmap with Suricata: a purple team lab

Kenvin Chau, Computer Engineering (Civilingenjör Datateknik), Lund University (LTH)
[LinkedIn](https://www.linkedin.com/in/kenvin-chau/) · Looking for a cybersecurity internship for summer 2027

Self-study project, built in November 2026 alongside my studies.

## 1. Goal

I wanted to learn detection engineering by working on both sides: attack a deliberately vulnerable web app with standard tools, write Suricata rules that catch those attacks, and then try to break my own rules with harmless and hand-written traffic. Everything is free and runs on one laptop.

## 2. Setup

```
attacker container (nmap 7.93, sqlmap 1.7.2)
        │  attacks
        ▼
DVWA + MariaDB (Docker, private network, published on 127.0.0.1 only)
        │  tcpdump container shares DVWA's network and records traffic
        ▼
.pcap recordings ──► Suricata 8.0.8 (offline mode, only my rules) ──► alerts
                                                                       │
                                                  pytest + GitHub Actions compare
                                                  alert counts with expected counts
```

- **Why offline replay:** the same recording always gives the same result, so detections can be tested in CI. Live sniffing on Docker Desktop for Windows would have been fragile.
- **Fixtures:** six recordings in `attacks/`: an nmap connect scan, a full sqlmap run, normal browsing, two hand-written injections, and a set of harmless look-alike inputs. A script (`scripts/sanitize_pcap.py`) blanks cookies and CSRF tokens with same-length filler before they are committed.

## 3. Detections

| Rule (sid) | Detects | MITRE ATT&CK |
|---|---|---|
| 1000001 | Port scan, counted as many refused connections (RST) to one client | T1046 Network Service Discovery |
| 1000002 | `UNION [ALL] SELECT` in the URL | T1190 Exploit Public-Facing Application |
| 1000003 | `SLEEP(` in the URL (time-based injection) | T1190 |
| 1000004 | `AND`/`OR` followed by a true condition like `7204=7204` | T1190 |
| 1000005 | Quote-based tautology such as `' OR '1'='1` | T1190 |

Rules are in `rules/suricata/local.rules`.

## 4. Results

Alerts per recording. Every cell is asserted by an automated test.

| Recording | 1000001 | 1000002 | 1000003 | 1000004 | 1000005 |
|---|:---:|:---:|:---:|:---:|:---:|
| nmap connect scan | 1 | 0 | 0 | 0 | 0 |
| sqlmap (161 HTTP requests, 4 techniques) | 0 | 8 | 7 | 57 | 15 |
| normal browsing | 0 | 0 | 0 | 0 | 0 |
| hand-written `' UNION SELECT …` and `' OR '1'='1` | 0 | 1 | 0 | 0 | 1 |
| hand-written `1 OR 1=1` | 0 | 0 | 0 | 1 | 0 |
| five harmless look-alike inputs | 0 | 0 | 0 | 0 | 0 |

## 5. What testing my own rules found

**1. My port-scan rule flagged a web attack.** The first version counted SYN packets from one source. I expected it to fire on nmap only. It also fired three times on the sqlmap recording, because sqlmap opens a new connection for every request. A scan is defined by many *different ports*, and Suricata can't count distinct ports in a rule. A scan of closed ports does make the *server* send many refusals (RST), and a web attack against an open port doesn't. Version 2 counts those refusals: 1 alert on nmap, 0 on sqlmap. The cost: a scan that touches only open ports produces no refusals and would not trigger it.

**2. Rules built from sqlmap's output missed hand-written attacks.** I wrote rules 2-4 by reading sqlmap's payloads and tested them on the same recording, so of course they matched. When I typed `' OR '1'='1` into the form by hand, nothing fired. Rule 4 needed digits on both sides of `=`, and this payload has quotes, so I added rule 5. Then `1 OR 1=1` slipped past too. A browser sends spaces as `+`, while sqlmap sends `%20`, and my regex only accepted real whitespace. Rule 4 now accepts `+`.

**3. Fixing the misses created false positives.** I recorded five harmless inputs (`salt and pepper`, `2 or 3`, `formula 2 and 2=4`, `O'Brien`, `union station select`). Two of them fired alerts, confirmed in Suricata's `eve.json`: `formula 2 and 2=4` triggered rule 1000004 (the `+` change made that possible) and `union station select` triggered rule 1000002, which matched the two words anywhere in the URL. I tightened both:

- Rule 2 now requires `union` directly followed by `select` (optionally with `all` between).
- Rule 4 now requires the *same* number on both sides of `=`, using a regex backreference: `\b(and|or)[\s+]+(not[\s+]+)?(\d+)[\s+]*=[\s+]*\3\b`

After tuning, all five harmless inputs give 0 alerts, and every attack cell that had to stay did stay (rule 2 on sqlmap is still 8, `1 OR 1=1` is still detected). The cost: rule 4 fell from 119 to 57 alerts on sqlmap, because sqlmap's *false* probes (`5619=7995`) no longer match, and rule 2 no longer sees `UNION/**/SELECT`.

**4. Some of my tests couldn't fail.** Two of my recordings turned out not to contain the traffic I thought they did: the first "harmless inputs" file held one page load and none of the five inputs, and the "F5 burst" file held three page loads. A rule that says 0 on a file with nothing in it proves nothing. I only noticed because I opened the files in Wireshark and checked that the requests were there. I re-recorded the first and dropped the second, because I never got a valid burst recording.

**5. I committed a secret.** While publishing the fixtures I pushed an unsanitized recording (a throwaway DVWA session cookie; the lab only listens on localhost). I found it by grepping what was actually committed, not the working folder. I deleted the file, recreated the DVWA container, and changed `.gitignore` to ignore every pcap in `attacks/` by default, with an explicit allow-list for the sanitized ones. The file is still in git history (commit `8f69326`); I chose not to rewrite public history for a localhost-only throwaway credential.

## 6. How the tests work

`tests/test_detection.py` replays each recording through Suricata 8.0.8 in Docker with a fresh log folder and counts alerts per rule id from `eve.json`. The expected counts are the table in section 4. GitHub Actions runs the same test on every push (Ubuntu runner, Python 3.12).

To check that the test can fail, I deliberately broke rule 1000003 by misspelling `sleep(`. Exactly one test failed (the sqlmap recording), and it passed again after I restored the rule.

Suricata runs single-threaded (`--runmode single`). In one early run an alert landed on a different packet than in later runs. I never reproduced that, so I don't know the cause, but five single-threaded runs gave identical output.

## 7. Limitations

- Rule 1000002 requires a plain separator between `UNION` and `SELECT`, so `UNION/**/SELECT` should evade it. I haven't tested that yet.
- Rule 1000004 still matches harmless text like `2 and 2=2`. I haven't tested that either.
- Nothing detects error-based SQL injection, which sqlmap also used.
- Rule 1000001 only sees scans that hit closed ports, and I haven't tested it against bursty legitimate traffic.
- Rules 2-5 alert on every matching request. There are no per-source thresholds, so one sqlmap run produces dozens of alerts.
- The harmless traffic is one person, one browser, one lab, with DVWA on its lowest security level. "No false positives" means none in these recordings.
- The rules read plain HTTP. HTTPS would need decryption, which this lab doesn't do.
- The tests compare counts, not which packets fired, and a deliberate tuning means updating the expected numbers by hand.
- Redacting cookies leaves TCP checksums invalid, so the recordings can't be replayed on a real network and Suricata runs with `-k none`.

## 8. What I would do next

1. Write an error-based rule and run sqlmap with `--tamper=space2comment` to measure how far the `UNION/**/SELECT` gap actually goes.
2. Add per-source thresholds to rules 2-5 and measure what alert volume drops and what information is lost.
3. Add Sigma rules for web server logs, to compare log-based detection with network-based detection.
4. Collect more varied harmless traffic.