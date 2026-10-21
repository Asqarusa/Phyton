#!/usr/bin/env python3
"""
brute_force_detector.py — Project 1 (improved): SOC Log Analyzer
-----------------------------------------------------------------
What it does (plain English):
    Reads a server login log and finds IP addresses that failed to log in
    too many times. Lots of failed logins from one address usually means
    someone is guessing passwords automatically — a "brute-force attack,"
    and spotting it is a core SOC analyst skill.

What's new in this improved version:
    * Command-line options: pick a log file, set the alert threshold,
      and set the burst-detection window without editing the code
      (python3 brute_force_detector.py --help to see them).
    * Burst detection: also flags IPs that fail very fast inside a short
      time window, not just high totals (speed is often the real signal).
    * Per-IP detail: shows which usernames each suspect targeted, when the
      attack started and ended, and how fast it went (attempts per minute).
    * Compromise check: raises the alarm to CRITICAL if a flagged IP ever
      had a SUCCESSFUL login — guessing that works means a possible breach.
    * Friendly error messages for missing, unreadable, or empty log files;
      malformed lines are counted and skipped instead of crashing the run.
    * Severity levels (CRITICAL / HIGH / MEDIUM) with suggested next steps.
    * New demo file: sample_auth_compromised.log shows what a successful
      break-in looks like — try: python3 brute_force_detector.py --log
      sample_auth_compromised.log

How to run:
    python3 brute_force_detector.py
    python3 brute_force_detector.py --log sample_auth_compromised.log
    python3 brute_force_detector.py --threshold 10 --window 5
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Settings (also settable on the command line, see --help)
# ---------------------------------------------------------------------------
DEFAULT_LOG_FILE = "sample_auth.log"  # log to read when no --log is given
DEFAULT_THRESHOLD = 5     # total failures from one IP that triggers an alert
DEFAULT_BURST_FAILS = 6   # failures inside one window that counts as a burst
DEFAULT_WINDOW_MIN = 10   # burst window size, in minutes

# ---------------------------------------------------------------------------
# Search patterns (regular expressions) — "smart Ctrl+F" for log lines.
# Failed lines look like:
#   Oct  8 09:12:01 server sshd[2211]: Failed password for root from 185.220.101.4 port 51234 ssh2
# Successful lines look like:
#   Oct  8 10:02:55 server sshd[2501]: Accepted password for askarbek from 192.168.1.25 port 44312 ssh2
# ---------------------------------------------------------------------------
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
SUCCESS_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
TIME_RE = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")


def parse_args():
    """Read command-line options; --help explains them all."""
    parser = argparse.ArgumentParser(
        description="Spot brute-force login attacks in a Linux auth log."
    )
    parser.add_argument(
        "--log", default=DEFAULT_LOG_FILE,
        help=f"log file to analyze (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=f"alert when one IP fails this many times total (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--burst", type=int, default=DEFAULT_BURST_FAILS,
        help=f"failures inside one --window that count as a burst (default: {DEFAULT_BURST_FAILS})",
    )
    parser.add_argument(
        "--window", type=int, default=DEFAULT_WINDOW_MIN,
        help=f"burst window size in minutes (default: {DEFAULT_WINDOW_MIN})",
    )
    args = parser.parse_args()
    # Basic sanity checks so a typo like --threshold -3 can't produce nonsense.
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.burst < 1:
        parser.error("--burst must be at least 1")
    if args.window < 1:
        parser.error("--window must be at least 1")
    return args


def parse_timestamp(line):
    """Turn 'Oct  8 09:12:01' at the start of a line into a datetime.

    Returns None if the line has no recognizable timestamp. The year is
    missing from syslog lines, so we fill in 2000 — only the gaps between
    attempts matter for burst detection, not the real year.
    """
    match = TIME_RE.match(line)
    if not match:
        return None
    month, day, hour, minute, second = match.groups()
    try:
        return datetime.strptime(
            f"{month} {day} 09:12:01".replace("09:12:01", f"{hour}:{minute}:{second}"),
            "%b %d %H:%M:%S",
        )
    except ValueError:
        return None


def analyze_log(log_file):
    """Read the log once and collect failures + successes per IP.

    Returns (attempts, stats) where attempts maps each IP to a dict with
    'fails' and 'successes' lists of (timestamp, username) pairs, and
    stats counts lines read, lines skipped, and files that had no data.
    """
    attempts = defaultdict(lambda: {"fails": [], "successes": []})
    stats = {"lines_read": 0, "lines_skipped": 0, "failed_lines": 0, "success_lines": 0}

    try:
        handle = open(log_file, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        print(f"ERROR: log file not found: {log_file}", file=sys.stderr)
        print("       Put the log file in this folder, or pass --log <path>.",
              file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"ERROR: no permission to read {log_file}.", file=sys.stderr)
        sys.exit(2)

    with handle:
        for line in handle:
            stats["lines_read"] += 1
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue  # blank lines and # comments carry no login data

            timestamp = parse_timestamp(line)

            failed = FAILED_RE.search(line)
            if failed:
                username, ip = failed.groups()
                attempts[ip]["fails"].append((timestamp, username))
                stats["failed_lines"] += 1
                continue

            success = SUCCESS_RE.search(line)
            if success:
                username, ip = success.groups()
                attempts[ip]["successes"].append((timestamp, username))
                stats["success_lines"] += 1
                continue

            stats["lines_skipped"] += 1  # a real log line, just not a login event

    return attempts, stats


def burst_speed(fail_times, window_minutes):
    """Count the most failures that fall inside ANY window_minutes-long window.

    This is the "how fast did they guess?" number. A sliding window catches
    attacks that totals alone can miss: 30 slow guesses in a day look
    different from 30 guesses in two minutes.
    """
    stamps = sorted(t for t in fail_times if t is not None)
    if not stamps:
        return 0
    window = timedelta(minutes=window_minutes)
    best = 1
    start = 0
    for end in range(len(stamps)):
        while stamps[end] - stamps[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def rate_per_minute(fail_times):
    """Average attempts per minute between the first and last failure."""
    stamps = sorted(t for t in fail_times if t is not None)
    if len(stamps) < 2:
        return None
    minutes = (stamps[-1] - stamps[0]).total_seconds() / 60
    if minutes <= 0:
        return float(len(stamps))  # all in the same minute: very fast
    return len(stamps) / minutes


def severity_for(fail_count, burst, had_success, threshold, burst_threshold):
    """Decide how worried we should be about one IP."""
    compromised = fail_count > 0 and had_success
    if compromised:
        return "CRITICAL"  # a guess SUCCEEDED — treat as a possible breach
    if fail_count >= 4 * threshold or burst >= 2 * burst_threshold:
        return "HIGH"
    if fail_count >= threshold or burst >= burst_threshold:
        return "MEDIUM"
    return "LOW"


def next_steps(severity):
    """What a human should do next, in plain language."""
    if severity == "CRITICAL":
        return ("Block this IP at the firewall NOW, force a password reset on the "
                "account that was breached, and check other logs for what this IP did next.")
    if severity == "HIGH":
        return ("Block this IP at the firewall (e.g. `ufw deny from <ip>`), and "
                "search your other logs for the same address.")
    return ("Add this IP to a watchlist; block it if the failures continue. "
            "Consider fail2ban to automate blocking.")


def print_report(attempts, stats, threshold, burst_fails, window_minutes):
    """Print the human-readable SOC-style report."""
    total_fails = sum(len(d["fails"]) for d in attempts.values())
    total_successes = sum(len(d["successes"]) for d in attempts.values())
    print(f"Log summary: {stats['lines_read']} lines read, "
          f"{stats['failed_lines']} failed logins, "
          f"{total_successes} successful logins, "
          f"{stats['lines_skipped']} unrelated lines skipped.")
    print(f"Alert rules: {threshold}+ failures from one IP, or "
          f"{burst_fails}+ failures inside {window_minutes} minutes.\n")

    suspects = []
    for ip, data in attempts.items():
        fail_count = len(data["fails"])
        burst = burst_speed([t for t, _ in data["fails"]], window_minutes)
        had_success = len(data["successes"]) > 0
        severity = severity_for(fail_count, burst, had_success, threshold, burst_fails)
        if severity in ("CRITICAL", "HIGH", "MEDIUM"):
            suspects.append((ip, data, fail_count, burst, had_success, severity))

    if not suspects:
        print("No brute-force activity detected. All clear.")
        return

    # Worst first: CRITICAL, then HIGH, then MEDIUM; ties broken by failure count.
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    suspects.sort(key=lambda s: (rank[s[5]], -s[2]))

    print("POSSIBLE BRUTE-FORCE ATTACKS (worst first):")
    for ip, data, fail_count, burst, had_success, sev in suspects:
        fail_times = [t for t, _ in data["fails"]]
        stamped = sorted(t for t in fail_times if t is not None)
        usernames = sorted({u for _, u in data["fails"]})
        print(f"\n  [{sev}] {ip} — {fail_count} failed logins")
        if stamped:
            start, end = stamped[0].strftime("%b %d %H:%M"), stamped[-1].strftime("%b %d %H:%M")
            print(f"        active {start} -> {end}")
        print(f"        fastest burst: {burst} failures inside {window_minutes} minutes")
        speed = rate_per_minute(fail_times)
        if speed is not None:
            print(f"        average speed: {speed:.1f} attempts/minute")
        print(f"        usernames targeted: {', '.join(usernames)}")
        if had_success:
            success_users = sorted({u for _, u in data["successes"]})
            print(f"        !! SUCCESSFUL LOGIN(S) from this IP as: {', '.join(success_users)}")
        print(f"        next step: {next_steps(sev)}")

    print(f"\n{len(suspects)} suspicious IP(s) flagged. "
          f"{len(attempts) - len(suspects)} other IP(s) stayed below the alert rules.")


def main():
    args = parse_args()
    attempts, stats = analyze_log(args.log)

    if stats["failed_lines"] == 0 and stats["success_lines"] == 0:
        print(f"NOTE: no login events found in {args.log}. "
              f"Is this an auth log (sshd 'Failed/Accepted password' lines)?")

    print_report(attempts, stats, args.threshold, args.burst, args.window)


if __name__ == "__main__":
    main()
