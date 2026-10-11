"""
auth_log_parser.py — Day 06 of my daily cybersecurity learning series

SOC analysts read log files for a living: hundreds of login lines, one story
hiding inside. This script parses a Linux-style auth log and turns it into a
clean, human-readable incident summary:

  * total login attempts, successful vs failed
  * top source IP addresses
  * attempts per hour (a spike can mean an automated attack)
  * a watchlist of IPs worth a closer look

SAFE BY DEFAULT: only reads a local text file you point it at. No scanning,
no networking, no passwords anywhere.

Usage:
    python3 auth_log_parser.py sample_auth.log
    python3 auth_log_parser.py              # uses the bundled sample file
"""

import re
import sys
from collections import Counter
from pathlib import Path

# --- 1. Patterns: what a login line looks like ---------------------------------
# A real /var/log/auth.log line looks like:
#   Oct 11 09:14:22 webserver sshd[1234]: Failed password for root from 203.0.113.7 port 51234 ssh2
# We don't need the whole line — just three things: the result (failed /
# accepted), the username, and the source IP address.
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED_RE = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")
HOUR_RE = re.compile(r"\s(\d{2}):\d{2}:\d{2}")  # "Oct 11 09:14:22" -> "09"

# --- 2. Read the log file -------------------------------------------------------
def read_log(path: Path) -> list[str]:
    """Return every line of the file, or stop with a friendly message."""
    if not path.exists():
        print(f"[!] Can't find '{path}'.")
        print("    Usage: python3 auth_log_parser.py <logfile>")
        sys.exit(1)
    return path.read_text(errors="replace").splitlines()

# --- 3. Parse: one pass over the lines ------------------------------------------
def parse(lines: list[str]) -> dict:
    """
    Walk the log once and collect everything we need:
      failed  — list of (username, ip) tuples for failed logins
      ok      — list of (username, ip) tuples for successful logins
      hours   — how many attempts happened in each hour of the day
      targets — which usernames were tried the most (attackers love 'root')
    """
    failed, ok = [], []
    hours = Counter()
    targets = Counter()

    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            failed.append((user, ip))
            targets[user] += 1
        else:
            m = ACCEPTED_RE.search(line)
            if m:
                ok.append((m.group(1), m.group(2)))

        h = HOUR_RE.search(line)
        if h:
            hours[h.group(1)] += 1

    return {"failed": failed, "ok": ok, "hours": hours, "targets": targets}

# --- 4. Report: turn the numbers into a story -----------------------------------
def report(data: dict) -> None:
    failed = data["failed"]
    ok = data["ok"]
    total = len(failed) + len(ok)

    print("=" * 56)
    print("AUTH LOG SUMMARY")
    print("=" * 56)
    print(f"Total login attempts : {total}")
    print(f"  Successful         : {len(ok)}")
    print(f"  Failed             : {len(failed)}")
    print()

    # Top source IPs — where are the knocks on the door coming from?
    print("Top source IPs (most attempts):")
    ip_counts = Counter(ip for _, ip in failed + ok)
    for ip, count in ip_counts.most_common(5):
        print(f"  {ip:>15}  — {count} attempt(s)")
    print()

    # Hourly distribution — attacks often spike at odd hours, but so do backups.
    print("Attempts by hour (when were they trying?):")
    for hour in sorted(data["hours"]):
        bar = "#" * data["hours"][hour]  # a mini bar chart
        print(f"  {hour}:00  {bar} ({data['hours'][hour]})")
    print()

    # Most-targeted usernames — 'root' and 'admin' at the top is a classic
    # brute-force fingerprint.
    print("Most-targeted usernames:")
    for user, count in data["targets"].most_common(5):
        print(f"  {user:<15} — {count} failed attempt(s)")
    print()

    # Watchlist: any IP with 5+ failed attempts deserves a human look.
    # This is triage, not proof — a legit user with a wrong password can land
    # here too, which is why the threshold is a *signal*, not a verdict.
    watch = [(ip, c) for ip, c in Counter(ip for _, ip in failed).items() if c >= 5]
    print("Watchlist (5+ failed attempts from one IP):")
    if watch:
        for ip, count in sorted(watch, key=lambda x: -x[1]):
            print(f"  [!] {ip} — {count} failed attempts — investigate")
    else:
        print("  No IPs crossed the threshold. Nothing to chase today.")
    print()

    print("Note: these stats are triage signals, not verdicts. A failed login")
    print("can be a typo; a successful one at 3 AM from a new IP is worth a")
    print("check. Context turns data into detection.")

# --- 5. Main --------------------------------------------------------------------
def main() -> None:
    logfile = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_auth.log")
    lines = read_log(logfile)
    print(f"Parsed {len(lines)} log lines from {logfile}\n")
    report(parse(lines))

if __name__ == "__main__":
    main()
