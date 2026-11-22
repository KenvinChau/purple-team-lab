"""Replay recorded traffic through Suricata and compare alert counts
per rule (sid) with the expected detection matrix."""
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "jasonish/suricata:8.0.8"  # pinned: the version these counts came from

# Expected alerts per rule id. A rule that is absent must stay silent.
EXPECTED = {
    "nmap-connect-scan.pcap": {1000001: 1},
    "sqlmap-sqli.pcap": {1000002: 8, 1000003: 7, 1000004: 57, 1000005: 15},
    "benign-browsing.pcap": {},
    "manual-sqli.pcap": {1000002: 1, 1000005: 1},
    "manual-sqli-2.pcap": {1000004: 1},
    "hard-negatives.pcap": {},
    "tamper-space2comment.pcap": {1000002: 10, 1000003: 11, 1000004: 57, 1000005: 15},
    "manual-error.pcap": {},
}


def run_suricata(pcap):
    with tempfile.TemporaryDirectory() as out:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{ROOT / 'attacks'}:/pcaps:ro",
            "-v", f"{ROOT / 'rules' / 'suricata'}:/rules:ro",
            "-v", f"{out}:/var/log/suricata",
            IMAGE,
            "-l", "/var/log/suricata", "--runmode", "single",
            "-r", f"/pcaps/{pcap}", "-S", "/rules/local.rules", "-k", "none",
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        counts = Counter()
        for line in (Path(out) / "eve.json").read_text().splitlines():
            event = json.loads(line)
            if event.get("event_type") == "alert":
                counts[event["alert"]["signature_id"]] += 1
        return dict(counts)


@pytest.mark.parametrize("pcap", sorted(EXPECTED))
def test_detection_matrix(pcap):
    assert run_suricata(pcap) == EXPECTED[pcap]