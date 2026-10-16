#!/usr/bin/env python3
"""
Day 17 — IOC Matcher (SOC theme, defensive-only)

Big idea: security teams keep a "watchlist" of known-bad things —
malicious IPs, shady domains, and malware file hashes. These clues are
called Indicators of Compromise (IOCs). This script checks a batch of
network events against that watchlist and raises an alert whenever
something matches, the way a real SOC analyst's triage tool would.

Everything is local and read-only: the watchlist and the events are
plain text, and the script changes nothing on your machine. This is
detection, not attack tooling.

Usage:
    python3 ioc_matcher.py                        # match built-in sample events against the watchlist
    python3 ioc_matcher.py --events sample_events.txt   # match your own event file instead
    python3 ioc_matcher.py --verbose              # also show events that matched nothing

Event file format (one per line, fields separated by spaces):
    timestamp  src_ip  dst_ip  domain  file_hash
Use "-" for an empty field. Example:
    2026-10-16T09:12:44  192.168.1.10  203.0.113.77  -  -
"""

import argparse

# ---------------------------------------------------------------------------
# The watchlist: sample Indicators of Compromise (IOCs).
# In a real SOC these come from threat-intelligence feeds (e.g. vendor
# reports, government advisories). Here they are clearly fake examples
# (documentation ranges like 203.0.113.x are reserved by RFC 5737 so they
# can never be real attacker IPs).
# Each indicator has a type (ip / domain / hash) and a severity.
# ---------------------------------------------------------------------------
WATCHLIST = [
    # Bad IPs — hosts known to run malware command-and-control servers.
    {"type": "ip",     "value": "203.0.113.77",    "severity": "HIGH",
     "note": "known malware command-and-control server"},
    {"type": "ip",     "value": "198.51.100.23",   "severity": "HIGH",
     "note": "known ransomware distribution host"},
    {"type": "ip",     "value": "192.0.2.44",      "severity": "MEDIUM",
     "note": "reported port-scanning source"},
    # Suspicious domains — phishing and malware download sites.
    {"type": "domain", "value": "invoice-verify-2026.example", "severity": "HIGH",
     "note": "phishing domain from a recent campaign"},
    {"type": "domain", "value": "free-prize-claim.example",    "severity": "HIGH",
     "note": "fake giveaway site that drops malware"},
    {"type": "domain", "value": "cdn-update-mirror.example",   "severity": "MEDIUM",
     "note": "typosquat of a software update domain"},
    # Malicious file hashes — fingerprints of known malware files.
    {"type": "hash",   "value": "d41d8cd98f00b204e9800998ecf8427e", "severity": "CRITICAL",
     "note": "known trojan dropper (SHA-256-style example fingerprint)"},
    {"type": "hash",   "value": "5d41402abc4b2a76b9719d911017c592", "severity": "CRITICAL",
     "note": "known ransomware payload (example fingerprint)"},
]

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# ---------------------------------------------------------------------------
# Built-in sample events: pretend these are lines from a firewall/proxy log.
# Two are malicious (match the watchlist), the rest are normal traffic.
# ---------------------------------------------------------------------------
SAMPLE_EVENTS = [
    "2026-10-16T09:12:44 192.168.1.10 203.0.113.77 - -",
    "2026-10-16T09:13:02 192.168.1.11 93.184.216.34 example.com -",
    "2026-10-16T09:14:37 192.168.1.10 - invoice-verify-2026.example -",
    "2026-10-16T09:15:09 192.168.1.12 142.250.80.14 google.com -",
    "2026-10-16T09:16:55 192.168.1.13 198.51.100.23 - d41d8cd98f00b204e9800998ecf8427e",
    "2026-10-16T09:17:21 192.168.1.14 8.8.8.8 dns.google -",
    "2026-10-16T09:18:03 192.168.1.10 - internal-wiki.corp -",
]


def parse_event(line):
    """Turn one log line into a dict; return None for blank lines."""
    parts = line.split()
    if len(parts) != 5:
        return None
    timestamp, src_ip, dst_ip, domain, file_hash = parts
    return {
        "timestamp": timestamp,
        "src_ip": src_ip if src_ip != "-" else "",
        "dst_ip": dst_ip if dst_ip != "-" else "",
        "domain": domain.lower() if domain != "-" else "",
        "file_hash": file_hash.lower() if file_hash != "-" else "",
        "raw": line,
    }


def check_event(event):
    """
    Compare one event against every indicator in the watchlist.
    Return a list of (indicator, which_field) matches.
    """
    hits = []
    for ioc in WATCHLIST:
        if ioc["type"] == "ip":
            if event["src_ip"] == ioc["value"]:
                hits.append((ioc, "src_ip"))
            if event["dst_ip"] == ioc["value"]:
                hits.append((ioc, "dst_ip"))
        elif ioc["type"] == "domain":
            if event["domain"] == ioc["value"].lower():
                hits.append((ioc, "domain"))
        elif ioc["type"] == "hash":
            if event["file_hash"] and event["file_hash"] == ioc["value"].lower():
                hits.append((ioc, "file_hash"))
    return hits


def print_alert(event, hits):
    """Print one SOC-style alert for an event that matched indicators."""
    # The alert's severity is the worst of its matched indicators.
    worst = max(hits, key=lambda h: SEVERITY_RANK[h[0]["severity"]])
    banner = "!" * 3
    print(f"\n{banner} ALERT [{worst[0]['severity']}] — {event['timestamp']} {banner}")
    for ioc, field in hits:
        print(f"  matched {ioc['type']:<6} {ioc['value']} (seen in {field})")
        print(f"           why it matters: {ioc['note']}")
    print("  suggested next steps: isolate the host, capture the full session,")
    print("  and check whether any other machines touched the same indicator.")


def main():
    parser = argparse.ArgumentParser(
        description="Match network events against an IOC watchlist (SOC triage demo).")
    parser.add_argument("--events", help="path to an event file (default: built-in samples)")
    parser.add_argument("--verbose", action="store_true",
                        help="also list events that matched nothing")
    args = parser.parse_args()

    if args.events:
        try:
            with open(args.events) as f:
                lines = f.read().splitlines()
        except OSError as exc:
            print(f"Could not read {args.events}: {exc}")
            return
    else:
        lines = SAMPLE_EVENTS

    events = [parse_event(line) for line in lines]
    events = [e for e in events if e is not None]

    print(f"Watchlist: {len(WATCHLIST)} indicators "
          f"({sum(1 for i in WATCHLIST if i['type'] == 'ip')} IPs, "
          f"{sum(1 for i in WATCHLIST if i['type'] == 'domain')} domains, "
          f"{sum(1 for i in WATCHLIST if i['type'] == 'hash')} hashes)")
    print(f"Events checked: {len(events)}")

    alerts = 0
    clean = 0
    for event in events:
        hits = check_event(event)
        if hits:
            alerts += 1
            print_alert(event, hits)
        else:
            clean += 1
            if args.verbose:
                print(f"  clean: {event['timestamp']} {event['src_ip']} -> "
                      f"{event['dst_ip'] or event['domain'] or '?'}")

    print(f"\nDone: {alerts} alert(s) from {len(events)} events, {clean} clean.")
    if alerts:
        print("SOC takeaway: each alert is a starting point, not a verdict —")
        print("an analyst would now investigate before calling it an incident.")


if __name__ == "__main__":
    main()
