#!/usr/bin/env python3
"""
success_after_failures.py — a beginner's account-takeover detector.

A classic SOC analyst pattern: many FAILED logins followed by a SUCCESS
for the same user can mean someone guessed (or stuffed) a password.
This script reads a simple auth log and flags every user whose failures
turn into a success inside a short time window.

Safe by default: it only reads a text file and reports on it.
Run:  python3 success_after_failures.py [--file LOG] [--fails N] [--window MINUTES]
"""

import argparse
from collections import defaultdict
from datetime import datetime, timedelta

# Tunables: a flag needs at least FAIL_THRESHOLD failures before one success...
FAIL_THRESHOLD = 5        # ...within WINDOW minutes...
WINDOW_MINUTES = 15       # ...for the SAME user to look interesting.
DEFAULT_FILE = "auth-sample.log"


def parse_line(line):
    """Turn one log line into (timestamp, user, result, ip) or None."""
    parts = line.split()
    if len(parts) != 4 or parts[0].startswith("#"):
        return None                     # skip blanks/comments/malformed
    try:
        ts = datetime.fromisoformat(parts[0])
    except ValueError:
        return None
    user, result, ip = parts[1], parts[2].upper(), parts[3]
    if result not in ("FAIL", "SUCCESS"):
        return None
    return ts, user, result, ip


def find_takeover_candidates(path, fail_threshold, window_minutes):
    """
    Scan the log and return flagged cases.
    A case = (user, ip, fail_count, first_fail, success_time).
    The trigger: for one user, >= fail_threshold failures occur within
    `window_minutes` right before a SUCCESS login.
    """
    events = defaultdict(list)          # user -> list of (ts, result, ip)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
        return None

    parsed = 0
    for line in lines:
        entry = parse_line(line.strip())
        if entry:
            ts, user, result, ip = entry
            events[user].append((ts, result, ip))
            parsed += 1
    print(f"[i] Parsed {parsed} events for {len(events)} users from {path}")

    flagged = []
    window = timedelta(minutes=window_minutes)
    for user, user_events in events.items():
        user_events.sort()              # chronological per user
        for i, (ts, result, ip) in enumerate(user_events):
            if result != "SUCCESS":
                continue                # we anchor on each successful login
            # Count that user's FAILs inside the window just before it.
            recent_fails = [
                (fts, fip)
                for (fts, fres, fip) in user_events[:i]
                if fres == "FAIL" and 0 < (ts - fts).total_seconds() <= window.total_seconds()
            ]
            if len(recent_fails) >= fail_threshold:
                flagged.append({
                    "user": user,
                    "ip": ip,
                    "fails": len(recent_fails),
                    "first_fail": min(fts for fts, _ in recent_fails),
                    "success_time": ts,
                })
    return flagged


def main():
    parser = argparse.ArgumentParser(
        description="Flag users with many failures followed by a success (possible takeover).")
    parser.add_argument("--file", default=DEFAULT_FILE,
                        help=f"log file to read (default: {DEFAULT_FILE})")
    parser.add_argument("--fails", type=int, default=FAIL_THRESHOLD,
                        help=f"min failures to flag (default: {FAIL_THRESHOLD})")
    parser.add_argument("--window", type=int, default=WINDOW_MINUTES,
                        help=f"minutes of window (default: {WINDOW_MINUTES})")
    args = parser.parse_args()

    flagged = find_takeover_candidates(args.file, args.fails, args.window)
    if flagged is None:
        return
    print(f"[i] Threshold: {args.fails}+ failures within {args.window} min before a success")
    if not flagged:
        print("[ok] No takeover patterns found.")
        return
    print(f"\n[!] {len(flagged)} suspicious case(s):")
    for case in flagged:
        print(f"  - user '{case['user']}' from {case['ip']}: "
              f"{case['fails']} fails starting {case['first_fail']:%H:%M}, "
              f"then SUCCESS at {case['success_time']:%H:%M}")
        print("    SOC next step: force a password reset, check for other "
              "sessions from that IP, review what the account touched.")


if __name__ == "__main__":
    main()
