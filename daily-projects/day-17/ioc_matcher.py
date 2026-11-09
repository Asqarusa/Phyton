#!/usr/bin/env python3
"""
Day 17 — IOC Matcher (SOC theme, defensive-only) — IMPROVED

Big idea: security teams keep a "watchlist" of known-bad things —
malicious IPs, shady domains, and malware file hashes. These clues are
called Indicators of Compromise (IOCs). This script checks a batch of
network events against that watchlist and raises an alert whenever
something matches, the way a real SOC analyst's triage tool would.

What's new in this version:
  * CIDR watchlist entries — one bad network block (203.0.113.0/24)
    catches every IP inside it, instead of listing addresses one by one.
  * Subdomain matching — a visit to mail.invoice-verify-2026.example
    now matches the watchlisted domain, because attackers hide behind
    subdomains.
  * --watchlist FILE — bring your own watchlist (one indicator per
    line: "type value severity note..."), with friendly errors for bad
    lines instead of a crash.
  * --json — machine-readable output for piping into other tools.
  * --min-severity LEVEL — only show alerts at or above that level,
    so a busy analyst can focus on HIGH and CRITICAL first.
  * A score per alert (severity points added up) plus a WATCH vs
    INVESTIGATE label, and a summary naming the most-hit indicator
    and the internal host that tripped the most alerts.
  * Honest exit codes: 0 = no alerts, 1 = alerts found, 2 = a usage
    or input-file problem. Malformed event lines are counted and
    reported instead of silently skipped.

Everything is local and read-only: the watchlist and the events are
plain text, and the script changes nothing on your machine. This is
detection, not attack tooling.

Usage:
    python3 ioc_matcher.py                        # match built-in sample events
    python3 ioc_matcher.py --events sample_events.txt
    python3 ioc_matcher.py --verbose              # also show events that matched nothing
    python3 ioc_matcher.py --watchlist sample_watchlist.txt
    python3 ioc_matcher.py --min-severity HIGH    # only HIGH and CRITICAL alerts
    python3 ioc_matcher.py --json                 # machine-readable output

Event file format (one per line, fields separated by spaces):
    timestamp  src_ip  dst_ip  domain  file_hash
Use "-" for an empty field. Example:
    2026-10-16T09:12:44  192.168.1.10  203.0.113.77  -  -

Watchlist file format (one indicator per line, "#" starts a comment):
    ip     203.0.113.77              HIGH      known malware command-and-control server
    domain invoice-verify-2026.example HIGH     phishing domain from a recent campaign
    hash   d41d8cd98f00b204e9800998ecf8427e CRITICAL known trojan dropper
    ip     192.0.2.0/24              MEDIUM    reported scanning network block
"""

import argparse
import ipaddress
import json
import sys

# ---------------------------------------------------------------------------
# The watchlist: sample Indicators of Compromise (IOCs).
# In a real SOC these come from threat-intelligence feeds (e.g. vendor
# reports, government advisories). Here they are clearly fake examples
# (documentation ranges like 203.0.113.x are reserved by RFC 5737 so they
# can never be real attacker IPs).
# Each indicator has a type (ip / domain / hash) and a severity.
# An "ip" value may be a single address (203.0.113.77) or a whole network
# block in CIDR form (192.0.2.0/24) — one line then covers 256 addresses.
# ---------------------------------------------------------------------------
WATCHLIST = [
    # Bad IPs — hosts known to run malware command-and-control servers.
    {"type": "ip",     "value": "203.0.113.77",    "severity": "HIGH",
     "note": "known malware command-and-control server"},
    {"type": "ip",     "value": "198.51.100.23",   "severity": "HIGH",
     "note": "known ransomware distribution host"},
    {"type": "ip",     "value": "192.0.2.44",      "severity": "MEDIUM",
     "note": "reported port-scanning source"},
    # A whole bad network block: any address inside 192.0.2.0/24 matches.
    {"type": "ip",     "value": "192.0.2.0/24",    "severity": "MEDIUM",
     "note": "reported scanning network block"},
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
VALID_TYPES = ("ip", "domain", "hash")

# ---------------------------------------------------------------------------
# Built-in sample events: pretend these are lines from a firewall/proxy log.
# Four are malicious (match the watchlist), the rest are normal traffic.
# The last two show off the new matching: a subdomain of a watchlisted
# domain, and an address inside a watchlisted network block.
# ---------------------------------------------------------------------------
SAMPLE_EVENTS = [
    "2026-10-16T09:12:44 192.168.1.10 203.0.113.77 - -",
    "2026-10-16T09:13:02 192.168.1.11 93.184.216.34 example.com -",
    "2026-10-16T09:14:37 192.168.1.10 - invoice-verify-2026.example -",
    "2026-10-16T09:15:09 192.168.1.12 142.250.80.14 google.com -",
    "2026-10-16T09:16:55 192.168.1.13 198.51.100.23 - d41d8cd98f00b204e9800998ecf8427e",
    "2026-10-16T09:17:21 192.168.1.14 8.8.8.8 dns.google -",
    "2026-10-16T09:18:03 192.168.1.10 - internal-wiki.corp -",
    "2026-10-16T09:19:40 192.168.1.15 192.0.2.99 - -",
    "2026-10-16T09:20:05 192.168.1.10 - mail.invoice-verify-2026.example -",
]


def parse_event(line):
    """Turn one log line into a dict; return None for blank/malformed lines."""
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


def load_watchlist(path):
    """
    Read a watchlist file: one indicator per line,
    "type value severity note...". Lines starting with "#" are comments.
    Returns (indicators, problems) where problems lists friendly error
    strings for lines that could not be used.
    """
    indicators = []
    problems = []
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError as exc:
        return None, [f"Could not read watchlist file {path}: {exc}"]
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            problems.append(f"line {number}: needs 'type value severity' — got: {raw!r}")
            continue
        ioc_type, value, severity = parts[0].lower(), parts[1], parts[2].upper()
        note = parts[3] if len(parts) > 3 else "no note given"
        if ioc_type not in VALID_TYPES:
            problems.append(f"line {number}: unknown type {ioc_type!r} "
                            f"(use ip, domain, or hash)")
            continue
        if severity not in SEVERITY_RANK:
            problems.append(f"line {number}: unknown severity {severity!r} "
                            f"(use LOW, MEDIUM, HIGH, or CRITICAL)")
            continue
        if ioc_type == "ip":
            try:
                # Accepts a single address or a CIDR network block.
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                problems.append(f"line {number}: {value!r} is not a valid IP "
                                f"address or network block")
                continue
        elif ioc_type == "domain":
            value = value.lower()
        elif ioc_type == "hash":
            value = value.lower()
            if not all(c in "0123456789abcdef" for c in value):
                problems.append(f"line {number}: hash {value!r} is not "
                                f"hexadecimal — did you paste it correctly?")
                continue
        indicators.append({"type": ioc_type, "value": value,
                           "severity": severity, "note": note})
    return indicators, problems


def _ip_matches(value, candidate):
    """True if candidate IP equals the watchlist IP, or sits inside its CIDR block."""
    if "/" in value:
        try:
            return ipaddress.ip_address(candidate) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    return candidate == value


def _domain_matches(value, candidate):
    """True on an exact match, or when the candidate is a subdomain of the value."""
    if not candidate:
        return False
    return candidate == value or candidate.endswith("." + value)


def check_event(event, watchlist):
    """
    Compare one event against every indicator in the watchlist.
    Return a list of (indicator, which_field) matches.
    """
    hits = []
    for ioc in watchlist:
        if ioc["type"] == "ip":
            for field in ("src_ip", "dst_ip"):
                if event[field] and _ip_matches(ioc["value"], event[field]):
                    hits.append((ioc, field))
        elif ioc["type"] == "domain":
            if _domain_matches(ioc["value"].lower(), event["domain"]):
                hits.append((ioc, "domain"))
        elif ioc["type"] == "hash":
            if event["file_hash"] and event["file_hash"] == ioc["value"].lower():
                hits.append((ioc, "file_hash"))
    return hits


def score_hits(hits):
    """Add up severity points: MEDIUM=1, HIGH=2, CRITICAL=3. Two MEDIUMs beat one HIGH."""
    return sum(SEVERITY_RANK[ioc["severity"]] for ioc, _ in hits)


def triage_label(score, worst_severity):
    """Plain-English priority: anything CRITICAL, or a score of 3+, gets investigated now."""
    if worst_severity == "CRITICAL" or score >= 3:
        return "INVESTIGATE NOW"
    return "WATCH"


def print_alert(event, hits):
    """Print one SOC-style alert for an event that matched indicators."""
    worst = max(hits, key=lambda h: SEVERITY_RANK[h[0]["severity"]])
    score = score_hits(hits)
    banner = "!" * 3
    print(f"\n{banner} ALERT [{worst[0]['severity']}] — {event['timestamp']} {banner}")
    print(f"  score: {score} point(s) — {triage_label(score, worst[0]['severity'])}")
    for ioc, field in hits:
        print(f"  matched {ioc['type']:<6} {ioc['value']} (seen in {field})")
        print(f"           why it matters: {ioc['note']}")
    print("  suggested next steps: isolate the host, capture the full session,")
    print("  and check whether any other machines touched the same indicator.")


def build_summary(events, alert_records, skipped):
    """Roll the run up into counts an analyst can scan in seconds."""
    by_severity = {level: 0 for level in SEVERITY_RANK}
    per_indicator = {}
    per_host = {}
    for event, hits in alert_records:
        worst = max(hits, key=lambda h: SEVERITY_RANK[h[0]["severity"]])
        by_severity[worst[0]["severity"]] += 1
        for ioc, _ in hits:
            per_indicator[ioc["value"]] = per_indicator.get(ioc["value"], 0) + 1
        host = event["src_ip"] or "unknown host"
        per_host[host] = per_host.get(host, 0) + 1
    summary = {
        "events_checked": len(events),
        "alerts": len(alert_records),
        "clean": len(events) - len(alert_records),
        "skipped_lines": skipped,
        "by_severity": {k: v for k, v in by_severity.items() if v},
        "most_matched_indicator": max(per_indicator, key=per_indicator.get) if per_indicator else None,
        "most_matched_indicator_hits": max(per_indicator.values()) if per_indicator else 0,
        "noisiest_host": max(per_host, key=per_host.get) if per_host else None,
        "noisiest_host_alerts": max(per_host.values()) if per_host else 0,
    }
    return summary


def print_summary(summary):
    print(f"\nDone: {summary['alerts']} alert(s) from {summary['events_checked']} events, "
          f"{summary['clean']} clean.")
    if summary["skipped_lines"]:
        print(f"Note: {summary['skipped_lines']} malformed line(s) were skipped — "
              f"each event needs 5 fields (timestamp src_ip dst_ip domain file_hash).")
    if summary["by_severity"]:
        breakdown = ", ".join(f"{n} {level}" for level, n in summary["by_severity"].items())
        print(f"By severity: {breakdown}.")
    if summary["most_matched_indicator"]:
        print(f"Most-matched indicator: {summary['most_matched_indicator']} "
              f"({summary['most_matched_indicator_hits']} hit(s)) — worth checking first.")
    if summary["noisiest_host"]:
        print(f"Noisiest host: {summary['noisiest_host']} "
              f"({summary['noisiest_host_alerts']} alert(s)) — start the investigation there.")
    if summary["alerts"]:
        print("SOC takeaway: each alert is a starting point, not a verdict —")
        print("an analyst would now investigate before calling it an incident.")


def main():
    parser = argparse.ArgumentParser(
        description="Match network events against an IOC watchlist (SOC triage demo).")
    parser.add_argument("--events", help="path to an event file (default: built-in samples)")
    parser.add_argument("--watchlist", help="path to a watchlist file (default: built-in list)")
    parser.add_argument("--verbose", action="store_true",
                        help="also list events that matched nothing")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of human-readable alerts")
    parser.add_argument("--min-severity", choices=list(SEVERITY_RANK), default="LOW",
                        help="only show alerts at or above this severity (default: LOW)")
    args = parser.parse_args()

    watchlist = WATCHLIST
    if args.watchlist:
        watchlist, problems = load_watchlist(args.watchlist)
        if watchlist is None:
            print(f"error: {problems[0]}", file=sys.stderr)
            return 2
        if problems:
            print("Watchlist warnings (those lines were skipped):", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
        if not watchlist:
            print("error: no usable indicators in the watchlist file.", file=sys.stderr)
            return 2

    if args.events:
        try:
            with open(args.events) as f:
                lines = f.read().splitlines()
        except OSError as exc:
            print(f"error: could not read {args.events}: {exc}", file=sys.stderr)
            return 2
    else:
        lines = SAMPLE_EVENTS

    events = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        event = parse_event(line)
        if event is None:
            skipped += 1
            continue
        events.append(event)

    min_rank = SEVERITY_RANK[args.min_severity]
    alert_records = []
    for event in events:
        hits = check_event(event, watchlist)
        if not hits:
            continue
        worst = max(hits, key=lambda h: SEVERITY_RANK[h[0]["severity"]])
        if SEVERITY_RANK[worst[0]["severity"]] < min_rank:
            continue
        alert_records.append((event, hits))

    summary = build_summary(events, alert_records, skipped)

    if args.json:
        payload = {
            "alerts": [
                {
                    "timestamp": event["timestamp"],
                    "severity": max(hits, key=lambda h: SEVERITY_RANK[h[0]["severity"]])[0]["severity"],
                    "score": score_hits(hits),
                    "triage": triage_label(
                        score_hits(hits),
                        max(hits, key=lambda h: SEVERITY_RANK[h[0]["severity"]])[0]["severity"]),
                    "matches": [
                        {"type": ioc["type"], "value": ioc["value"],
                         "field": field, "severity": ioc["severity"],
                         "note": ioc["note"]}
                        for ioc, field in hits
                    ],
                }
                for event, hits in alert_records
            ],
            "summary": summary,
        }
        print(json.dumps(payload, indent=2))
    else:
        counts = {t: sum(1 for i in watchlist if i["type"] == t) for t in VALID_TYPES}
        print(f"Watchlist: {len(watchlist)} indicators "
              f"({counts['ip']} IPs, {counts['domain']} domains, {counts['hash']} hashes)")
        print(f"Events checked: {len(events)}")
        for event, hits in alert_records:
            print_alert(event, hits)
        if args.verbose:
            for event in events:
                if not check_event(event, watchlist):
                    print(f"  clean: {event['timestamp']} {event['src_ip']} -> "
                          f"{event['dst_ip'] or event['domain'] or '?'}")
        print_summary(summary)

    # Exit code tells scripts what happened: 0 clean, 1 alerts, 2 input problem.
    return 1 if alert_records else 0


if __name__ == "__main__":
    sys.exit(main())
