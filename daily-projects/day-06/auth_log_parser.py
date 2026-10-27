"""
auth_log_parser.py — Day 06 of my daily cybersecurity learning series
(IMPROVED version, 2026-10-26)

SOC analysts read log files for a living: hundreds of login lines, one story
hiding inside. This script parses a Linux-style auth log and turns it into a
clean, human-readable incident summary:

  * total login attempts, successful vs failed (plus success rate)
  * top source IP addresses
  * attempts per hour (a spike can mean an automated attack)
  * a watchlist of IPs worth a closer look
  * NEW: success-after-failures alerts — an IP that fails several times and
    then suddenly gets in. That pattern can mean a password was guessed,
    so it deserves an urgent human check.

SAFE BY DEFAULT: only reads a local text file you point it at. No scanning,
no networking, no passwords anywhere.

Usage:
    python3 auth_log_parser.py sample_auth.log
    python3 auth_log_parser.py                  # uses the bundled sample file
    python3 auth_log_parser.py --demo           # built-in demo, no file needed
    python3 auth_log_parser.py --threshold 3 --top 3 mylog.log
    python3 auth_log_parser.py --json sample_auth.log
"""

import argparse
import json
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

# Lines that fail at least this many times before a success count as a
# possible compromise. Three is deliberately lower than the watchlist
# threshold: getting in after guessing is more serious than just knocking.
COMPROMISE_MIN_FAILS = 3

# Built-in demo story: an attacker guesses 'root' five times, then gets in,
# plus one normal admin login. Run with --demo, no file needed.
DEMO_LINES = [
    "Oct 11 02:10:01 webserver sshd[201]: Failed password for root from 203.0.113.99 port 51001 ssh2",
    "Oct 11 02:10:12 webserver sshd[202]: Failed password for root from 203.0.113.99 port 51002 ssh2",
    "Oct 11 02:10:25 webserver sshd[203]: Failed password for root from 203.0.113.99 port 51003 ssh2",
    "Oct 11 02:10:40 webserver sshd[204]: Failed password for root from 203.0.113.99 port 51004 ssh2",
    "Oct 11 02:11:02 webserver sshd[205]: Failed password for root from 203.0.113.99 port 51005 ssh2",
    "Oct 11 02:11:20 webserver sshd[206]: Accepted password for root from 203.0.113.99 port 51006 ssh2",
    "Oct 11 09:00:00 webserver sshd[207]: Accepted password for deploy from 10.0.0.15 port 42000 ssh2",
    "Oct 11 09:01:00 webserver sshd[208]: Failed password for deploy from 10.0.0.15 port 42001 ssh2",
    "This line is not a login line at all, and the parser says so plainly.",
]

# --- 2. Read the log file -------------------------------------------------------
def read_log(path: Path) -> list[str]:
    """Return every line of the file, or stop with a friendly message."""
    try:
        return path.read_text(errors="replace").splitlines()
    except FileNotFoundError:
        print(f"[!] Can't find '{path}'.")
        print("    Usage: python3 auth_log_parser.py <logfile>")
        print("    Tip: run with --demo to try the built-in sample, no file needed.")
        sys.exit(1)
    except IsADirectoryError:
        print(f"[!] '{path}' is a folder, not a log file. Point it at a file instead.")
        sys.exit(1)
    except OSError as exc:
        print(f"[!] Couldn't read '{path}': {exc}")
        sys.exit(1)


# --- 3. Parse: one pass over the lines ------------------------------------------
def parse(lines: list[str]) -> dict:
    """
    Walk the log once and collect everything we need:
      failed  — list of (username, ip) tuples for failed logins
      ok      — list of (username, ip) tuples for successful logins
      hours   — how many attempts happened in each hour of the day
      targets — which usernames were tried the most (attackers love 'root')
      unparsed — lines that are neither a login line, a comment, nor blank
      compromises — (ip, user, fails_before) where a success followed 3+
        failed attempts from the same IP for the same user
    """
    failed, ok = [], []
    hours = Counter()
    targets = Counter()
    unparsed = 0
    # Track failures seen so far per (ip, user), in log order, so a later
    # success can be checked against the failures that came before it.
    fails_so_far: Counter = Counter()
    compromises = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue  # comments and blank lines are not log lines

        m = FAILED_RE.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            failed.append((user, ip))
            targets[user] += 1
            fails_so_far[(ip, user)] += 1
        else:
            m = ACCEPTED_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                ok.append((user, ip))
                prior_fails = fails_so_far[(ip, user)]
                if prior_fails >= COMPROMISE_MIN_FAILS:
                    compromises.append((ip, user, prior_fails))
            else:
                unparsed += 1

        h = HOUR_RE.search(line)
        if h:
            hours[h.group(1)] += 1

    return {
        "failed": failed,
        "ok": ok,
        "hours": hours,
        "targets": targets,
        "unparsed": unparsed,
        "compromises": compromises,
    }


# --- 4. Summarise: numbers first, so both report styles share one source -------
def summarise(data: dict, threshold: int, top_n: int) -> dict:
    """Turn parsed data into plain numbers both output styles can use."""
    failed, ok = data["failed"], data["ok"]
    total = len(failed) + len(ok)
    ip_counts = Counter(ip for _, ip in failed + ok)
    fail_counts = Counter(ip for _, ip in failed)
    watch = [
        {"ip": ip, "failed": count}
        for ip, count in fail_counts.items()
        if count >= threshold
    ]
    watch.sort(key=lambda item: -item["failed"])
    return {
        "total": total,
        "successful": len(ok),
        "failed": len(failed),
        "success_rate_pct": round(100 * len(ok) / total, 1) if total else 0.0,
        "unparsed_lines": data["unparsed"],
        "top_ips": [
            {"ip": ip, "attempts": count}
            for ip, count in ip_counts.most_common(top_n)
        ],
        "attempts_by_hour": dict(sorted(data["hours"].items())),
        "most_targeted_users": [
            {"user": user, "failed": count}
            for user, count in data["targets"].most_common(top_n)
        ],
        "watchlist": watch,
        "compromises": [
            {"ip": ip, "user": user, "failed_before_success": fails}
            for ip, user, fails in data["compromises"]
        ],
    }


# --- 5. Report: turn the numbers into a story -----------------------------------
def report(summary: dict, threshold: int) -> None:
    print("=" * 56)
    print("AUTH LOG SUMMARY")
    print("=" * 56)
    print(f"Total login attempts : {summary['total']}")
    print(f"  Successful         : {summary['successful']}")
    print(f"  Failed             : {summary['failed']}")
    print(f"  Success rate       : {summary['success_rate_pct']}%")
    if summary["unparsed_lines"]:
        print(f"  Lines skipped      : {summary['unparsed_lines']} "
              "(not login lines — see the note at the end)")
    print()

    # Top source IPs — where are the knocks on the door coming from?
    print("Top source IPs (most attempts):")
    for item in summary["top_ips"]:
        print(f"  {item['ip']:>15}  — {item['attempts']} attempt(s)")
    print()

    # Hourly distribution — attacks often spike at odd hours, but so do backups.
    print("Attempts by hour (when were they trying?):")
    for hour, count in summary["attempts_by_hour"].items():
        bar = "#" * count  # a mini bar chart
        print(f"  {hour}:00  {bar} ({count})")
    print()

    # Most-targeted usernames — 'root' and 'admin' at the top is a classic
    # brute-force fingerprint.
    print("Most-targeted usernames:")
    for item in summary["most_targeted_users"]:
        print(f"  {item['user']:<15} — {item['failed']} failed attempt(s)")
    print()

    # Success after failures: the new, most urgent flag. A guessed password
    # looks exactly like this — many knocks, then the door opens.
    print("Success after failures (possible compromise — check urgently):")
    if summary["compromises"]:
        for item in summary["compromises"]:
            print(f"  [!!!] {item['ip']} got in as '{item['user']}' after "
                  f"{item['failed_before_success']} failed attempts")
    else:
        print("  None. No login followed a run of failed attempts.")
    print()

    # Watchlist: any IP with threshold-or-more failed attempts deserves a
    # human look. This is triage, not proof — a legit user with a wrong
    # password can land here too, which is why the threshold is a *signal*,
    # not a verdict.
    print(f"Watchlist ({threshold}+ failed attempts from one IP):")
    if summary["watchlist"]:
        for item in summary["watchlist"]:
            print(f"  [!] {item['ip']} — {item['failed']} failed attempts — investigate")
    else:
        print("  No IPs crossed the threshold. Nothing to chase today.")
    print()

    print("Note: these stats are triage signals, not verdicts. A failed login")
    print("can be a typo; a successful one at 3 AM from a new IP is worth a")
    print("check. Context turns data into detection.")


# --- 6. Main --------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Turn a Linux auth log into a SOC-style incident summary."
    )
    parser.add_argument("logfile", nargs="?", default="sample_auth.log",
                        help="log file to read (default: sample_auth.log)")
    parser.add_argument("--demo", action="store_true",
                        help="run the built-in demo story instead of a file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed attempts from one IP that land it on the "
                             "watchlist (default: 5)")
    parser.add_argument("--top", type=int, default=5,
                        help="how many top IPs / usernames to show (default: 5)")
    parser.add_argument("--json", action="store_true",
                        help="print the summary as JSON instead of a report")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be 1 or more")
    if args.top < 1:
        parser.error("--top must be 1 or more")

    if args.demo:
        lines = DEMO_LINES
        source = "built-in demo"
    else:
        logfile = Path(args.logfile)
        lines = read_log(logfile)
        source = str(logfile)

    summary = summarise(parse(lines), args.threshold, args.top)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Parsed {len(lines)} log lines from {source}\n")
        report(summary, args.threshold)


if __name__ == "__main__":
    main()
