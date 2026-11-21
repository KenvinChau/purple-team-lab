"""Sanitize recorded pcaps: blank cookies and CSRF tokens.

Every replacement keeps the byte length identical, so the packet structure
stays valid. TCP checksums become wrong; run Suricata with -k none.
Raw recordings live in captures/ (gitignored). Clean copies go to attacks/.
"""
import re
import sys
from pathlib import Path

SRC = Path("captures")
DST = Path("attacks")
FILES = [
    "sqlmap-sqli.pcap",
    "benign-browsing.pcap",
    "manual-sqli.pcap",
    "manual-sqli-2.pcap",
    "hard-negatives.pcap",
]

# Group 1 stays, group 2 is replaced with the same number of 'x'.
REDACT = [
    re.compile(rb"(\r\nCookie: )([^\r\n]+)", re.I),
    re.compile(rb"(\r\nSet-Cookie: )([^\r\n]+)", re.I),
    re.compile(rb"(user_token(?:=|' value='))([0-9a-fA-F]{32})"),
]

# Independent, broader checks: anything that still looks like a secret.
LEFTOVER = [
    re.compile(rb"PHPSESSID=([A-Za-z0-9,-]{8,})"),
    re.compile(rb"user_token\W{1,12}([0-9a-fA-F]{32})"),
]


def blank(match):
    return match.group(1) + b"x" * len(match.group(2))


def sanitize(data):
    counts = []
    for pattern in REDACT:
        data, n = pattern.subn(blank, data)
        counts.append(n)
    return data, counts


def leftovers(data):
    found = []
    for pattern in LEFTOVER:
        for m in pattern.finditer(data):
            if set(m.group(1)) != {ord("x")}:
                found.append(m.group(0)[:30])
    return found


def main():
    DST.mkdir(exist_ok=True)
    failed = False
    for name in FILES:
        src = SRC / name
        if not src.exists():
            print(f"MISSING  {src}")
            failed = True
            continue
        original = src.read_bytes()
        clean, counts = sanitize(original)
        assert len(clean) == len(original), "length changed"
        left = leftovers(clean)
        (DST / name).write_bytes(clean)
        print(f"{name}: cookie={counts[0]} set-cookie={counts[1]} "
              f"token={counts[2]} leftover={len(left)}")
        failed = failed or bool(left)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()