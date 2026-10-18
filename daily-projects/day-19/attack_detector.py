# Web Access Log Attack Detector — Day 19
# ---------------------------------------------------------------
# A SOC (Security Operations Center) mini-tool: read web server
# access log lines (Apache/Nginx combined format) and flag
# suspicious requests the way a real analyst's first-pass triage
# would: SQL injection probes, path traversal, XSS attempts,
# directory scanning, and known scanner user-agents.
#
# ANALOGY: think of a web server as a shop and each log line as an
# entry in the security camera log. This script is the night-shift
# guard who rewinds the footage and circles every frame where
# someone tested the door handles, checked the windows, or wrote
# graffiti — then hands you a tidy incident summary.
#
# SAFE BY DESIGN:
#   * Reads log LINES as text — never touches the network.
#   * Ships with built-in sample data and a sample log file.
#   * Detects patterns only; it never blocks, attacks, or changes
#     anything. A detector is not a weapon.
#
# RUN:
#   python3 attack_detector.py                # built-in sample data
#   python3 attack_detector.py sample_access.log
# ---------------------------------------------------------------

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


def parse_lines(text):
    """Turn raw log text into a list of dicts; skip unparseable lines."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = LOG_LINE.match(line)
        if m:
            entries.append(m.groupdict())
    return entries


def analyze(entries):
    """Match every entry against signatures + scanner agents.

    Returns (alerts, stats):
      alerts: list of (ip, signature_name, severity, path, user_agent)
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
                alerts.append((ip, name, sev, path, agent))
        agent_l = agent.lower()
        for scanner in SCANNER_AGENTS:
            if scanner in agent_l:
                alerts.append((ip, f"Known scanner user-agent ({scanner})",
                               "MEDIUM", path, agent))
                break  # one alert per request is enough for the agent

    # Behavioral rule: >=5 error responses from one IP = spray behavior.
    # Signature matching catches KNOWN attacks; behavior rules catch
    # unknown ones doing noisy things. Real SIEMs combine both.
    sprayers = {ip: n for ip, n in errors_by_ip.items() if n >= 5}

    stats = {
        "total_requests": len(entries),
        "unique_ips": len(total_by_ip),
        "alerts": len(alerts),
        "sprayers": sprayers,
        "by_severity": Counter(a[2] for a in alerts),
        "by_signature": Counter(a[1] for a in alerts),
        "top_ips": total_by_ip.most_common(5),
    }
    return alerts, stats


def report(alerts, stats):
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
    print()

    if not alerts:
        print("No suspicious patterns found. (A clean log is a result too.)")
        return

    print("--- Attack signatures seen ---")
    for name, count in stats["by_signature"].most_common():
        print(f"  {count:>3}x  {name}")
    print()

    print("--- Alerts (highest severity first) ---")
    rank = {"HIGH": 0, "MEDIUM": 1}
    for ip, name, sev_, path, agent in sorted(
            alerts, key=lambda a: (rank.get(a[2], 9), a[0])):
        print(f"[{sev_:>6}] {ip:>15}  {name}")
        print(f"           path : {path[:90]}")
        if sev_ == "MEDIUM" and "scanner" in name:
            print(f"           agent: {agent[:60]}")
    print()

    if stats["sprayers"]:
        print("--- Behavioral flag: 404/5xx spray (>=5 errors from one IP) ---")
        for ip, n in stats["sprayers"].items():
            print(f"  {ip}: {n} error responses — likely directory scanning")
        print()

    print("--- Top talkers ---")
    for ip, n in stats["top_ips"]:
        print(f"  {ip}: {n} requests")
    print()
    print("SOC next steps: 1) confirm alerts are malicious (not your own")
    print("pentest), 2) check what those IPs touched after the probe,")
    print("3) block repeat offenders at the firewall, 4) patch the")
    print("vulnerability class, not just the one URL.")


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
            text = f.read()
        print(f"Reading log file: {sys.argv[1]}")
    else:
        text = SAMPLE_LOG
        print("(No file given — analyzing built-in sample log.)")

    entries = parse_lines(text)
    if not entries:
        print("No parseable log lines found. Expected Apache/Nginx "
              "combined log format.")
        return
    alerts, stats = analyze(entries)
    report(alerts, stats)


if __name__ == "__main__":
    main()
