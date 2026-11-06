#!/usr/bin/env python3
"""
success_after_failures.py — a beginner's account-takeover detector.

A classic SOC analyst pattern: many FAILED logins followed by a SUCCESS
for the same user can mean someone guessed (or stuffed) a password.
This script reads a simple auth log and flags every user whose failures
turn into a success inside a short time window.

What's new in this version:
  * --demo runs on built-in sample data — no log file needed.
  * --json prints machine-readable output (great for piping into other tools).
  * Severity levels: HIGH when the success comes from a DIFFERENT IP than
    the failures (a strong takeover sign) or the fail count is very high.
  * "Still guessing" watchlist: users with many fails and NO success yet —
    an attack that may still be in progress.
  * --timeline USER prints one user's full event timeline in plain English.
  * Each case now shows attempts-per-minute and how long the guessing took.
  * Clear exit codes: 0 = clean, 1 = something flagged, 2 = usage/file error.
  * Friendlier errors and a count of skipped (malformed) lines.

Safe by default: it only reads a text file and reports on it.
Run:  python3 success_after_failures.py [--file LOG] [--fails N] [--window MINUTES]
      python3 success_after_failures.py --demo
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Tunables: a flag needs at least FAIL_THRESHOLD failures before one success...
FAIL_THRESHOLD = 5        # ...within WINDOW minutes...
WINDOW_MINUTES = 15       # ...for the SAME user to look interesting.
HIGH_FAIL_COUNT = 10      # ...this many fails always means HIGH severity.
DEFAULT_FILE = "auth-sample.log"

# Built-in demo data (documentation-range IPs only — never real addresses).
# alice: 2 typos, then in — normal. bob: 7 fails, then in — flagged.
# carol: 1 fail, then in — normal. eve: 8 fails, never gets in — watchlist.
# frank: 6 fails from one IP, success from a DIFFERENT IP — HIGH severity.
DEMO_LINES = """\
2026-10-15T07:02:11 alice FAIL 10.0.0.12
2026-10-15T07:02:44 alice FAIL 10.0.0.12
2026-10-15T07:03:05 alice SUCCESS 10.0.0.12
2026-10-15T07:41:00 bob FAIL 10.0.0.31
2026-10-15T07:41:22 bob FAIL 10.0.0.31
2026-10-15T07:41:49 bob FAIL 10.0.0.31
2026-10-15T07:42:10 bob FAIL 10.0.0.31
2026-10-15T07:42:31 bob FAIL 10.0.0.31
2026-10-15T07:42:52 bob FAIL 10.0.0.31
2026-10-15T07:43:10 bob FAIL 10.0.0.31
2026-10-15T07:43:31 bob SUCCESS 10.0.0.31
2026-10-15T08:15:00 carol FAIL 10.0.0.44
2026-10-15T08:16:12 carol SUCCESS 10.0.0.44
2026-10-15T09:00:00 dave SUCCESS 10.0.0.57
2026-10-15T09:30:05 eve FAIL 10.0.0.88
2026-10-15T09:30:19 eve FAIL 10.0.0.88
2026-10-15T09:30:37 eve FAIL 10.0.0.88
2026-10-15T09:31:02 eve FAIL 10.0.0.88
2026-10-15T09:31:20 eve FAIL 10.0.0.88
2026-10-15T09:31:55 eve FAIL 10.0.0.88
2026-10-15T09:32:40 eve FAIL 10.0.0.88
2026-10-15T09:33:15 eve FAIL 10.0.0.88
2026-10-15T10:10:00 frank FAIL 10.0.0.99
2026-10-15T10:10:18 frank FAIL 10.0.0.99
2026-10-15T10:10:41 frank FAIL 10.0.0.99
2026-10-15T10:11:02 frank FAIL 10.0.0.99
2026-10-15T10:11:25 frank FAIL 10.0.0.99
2026-10-15T10:11:47 frank FAIL 10.0.0.99
2026-10-15T10:12:30 frank SUCCESS 203.0.113.7
"""


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


def load_events(lines):
    """Parse lines into {user: [(ts, result, ip), ...]} plus a skipped count."""
    events = defaultdict(list)
    parsed = skipped = 0
    for line in lines:
        entry = parse_line(line.strip())
        if entry is None:
            if line.strip() and not line.strip().startswith("#"):
                skipped += 1            # a real line we couldn't understand
            continue
        ts, user, result, ip = entry
        events[user].append((ts, result, ip))
        parsed += 1
    for user_events in events.values():
        user_events.sort()              # chronological per user
    return events, parsed, skipped


def severity_for(case):
    """HIGH if the success IP is new, or the fail count is very high."""
    if case["ip_changed"] or case["fails"] >= HIGH_FAIL_COUNT:
        return "HIGH"
    return "MEDIUM"


def scan(events, fail_threshold, window_minutes):
    """
    Return (flagged_cases, watchlist, stats).
    A flagged case = (user, ip, fails, first_fail, success_time, ...) where
    >= fail_threshold failures happened within `window_minutes` before a SUCCESS.
    The watchlist = users with >= fail_threshold fails in the window who
    never succeeded — the guessing may still be going on.
    """
    window = timedelta(minutes=window_minutes)
    flagged = []
    watchlist = []
    for user, user_events in events.items():
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
                first_fail = min(fts for fts, _ in recent_fails)
                fail_ips = sorted({fip for _, fip in recent_fails})
                elapsed = (ts - first_fail).total_seconds() / 60.0
                case = {
                    "user": user,
                    "ip": ip,
                    "fails": len(recent_fails),
                    "first_fail": first_fail,
                    "success_time": ts,
                    "fail_ips": fail_ips,
                    "ip_changed": ip not in fail_ips,
                    "minutes": round(elapsed, 1),
                    "attempts_per_minute": round(len(recent_fails) / max(elapsed, 0.1), 1),
                }
                case["severity"] = severity_for(case)
                flagged.append(case)
        # Watchlist: many recent fails, no success after them at all.
        fails = [(ts, ip) for (ts, res, ip) in user_events if res == "FAIL"]
        successes = [ts for (ts, res, _ip) in user_events if res == "SUCCESS"]
        if len(fails) >= fail_threshold:
            last_fail = max(ts for ts, _ip in fails)
            if not successes or last_fail > max(successes):
                recent = [
                    (fts, fip) for (fts, fip) in fails
                    if (last_fail - fts).total_seconds() <= window.total_seconds()
                ]
                if len(recent) >= fail_threshold:
                    watchlist.append({
                        "user": user,
                        "fails": len(recent),
                        "last_fail": last_fail,
                        "ips": sorted({fip for _, fip in recent}),
                    })
    flagged.sort(key=lambda c: (c["severity"] != "HIGH", c["success_time"]))
    watchlist.sort(key=lambda w: w["last_fail"])
    stats = {"users": len(events),
             "events": sum(len(v) for v in events.values())}
    return flagged, watchlist, stats


def print_timeline(events, user):
    """Print one user's events in plain English, oldest first."""
    if user not in events:
        print(f"[!] No events for user '{user}'.")
        print(f"    Known users: {', '.join(sorted(events)) or '(none)'}")
        return 2
    print(f"Timeline for '{user}' ({len(events[user])} events):")
    for ts, result, ip in events[user]:
        word = "FAILED login" if result == "FAIL" else "SUCCESSFUL login"
        print(f"  {ts:%Y-%m-%d %H:%M:%S}  {word} from {ip}")
    return 0


def print_report(flagged, watchlist, stats, threshold, window_minutes, quiet):
    """Human-readable report. Returns exit code: 1 if anything flagged."""
    if not quiet:
        print(f"[i] Threshold: {threshold}+ failures within {window_minutes} min "
              f"before a success")
    if not flagged and not watchlist:
        print("[ok] No takeover patterns found.")
        return 0
    if flagged:
        print(f"\n[!] {len(flagged)} suspicious takeover case(s):")
        for case in flagged:
            print(f"  [{case['severity']}] user '{case['user']}' from {case['ip']}: "
                  f"{case['fails']} fails over {case['minutes']} min "
                  f"({case['attempts_per_minute']}/min), "
                  f"then SUCCESS at {case['success_time']:%H:%M}")
            if case["ip_changed"]:
                print(f"      !! success came from a NEW IP "
                      f"(fails were from {', '.join(case['fail_ips'])})")
            print("      SOC next step: force a password reset, check for other "
                  "sessions from that IP, review what the account touched.")
    if watchlist:
        print(f"\n[~] {len(watchlist)} user(s) still guessing (no success yet):")
        for entry in watchlist:
            print(f"  - user '{entry['user']}': {entry['fails']} fails, "
                  f"last at {entry['last_fail']:%H:%M} "
                  f"from {', '.join(entry['ips'])} — consider locking the account")
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Flag users with many failures followed by a success (possible takeover).")
    parser.add_argument("--file", default=DEFAULT_FILE,
                        help=f"log file to read (default: {DEFAULT_FILE})")
    parser.add_argument("--fails", type=int, default=FAIL_THRESHOLD,
                        help=f"min failures to flag (default: {FAIL_THRESHOLD})")
    parser.add_argument("--window", type=int, default=WINDOW_MINUTES,
                        help=f"minutes of window (default: {WINDOW_MINUTES})")
    parser.add_argument("--demo", action="store_true",
                        help="run on built-in sample data (no file needed)")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON instead of a text report")
    parser.add_argument("--timeline", metavar="USER",
                        help="show one user's full event timeline and exit")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the summary lines")
    args = parser.parse_args(argv)

    if args.fails < 1:
        parser.error("--fails must be 1 or more")
    if args.window < 1:
        parser.error("--window must be 1 or more")

    if args.demo:
        lines = DEMO_LINES.splitlines()
        source = "built-in demo data"
    else:
        try:
            with open(args.file, encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
            print(f"    Tip: try --demo to run on built-in sample data, "
                  f"or pass --file <path-to-your-log>.")
            return 2
        except OSError as exc:
            print(f"[!] Could not read {args.file}: {exc}")
            return 2
        source = args.file

    events, parsed, skipped = load_events(lines)
    if not (args.quiet or args.json):
        print(f"[i] Parsed {parsed} events from {source}")
        if skipped:
            print(f"[!] Skipped {skipped} line(s) I couldn't understand "
                  f"(wrong format — check the log)")

    if args.timeline:
        return print_timeline(events, args.timeline)

    flagged, watchlist, stats = scan(events, args.fails, args.window)

    if args.json:
        out = {
            "source": source,
            "threshold_fails": args.fails,
            "window_minutes": args.window,
            "users": stats["users"],
            "events": stats["events"],
            "skipped_lines": skipped,
            "flagged": [
                {**c,
                 "first_fail": c["first_fail"].isoformat(),
                 "success_time": c["success_time"].isoformat()}
                for c in flagged
            ],
            "watchlist": [
                {**w, "last_fail": w["last_fail"].isoformat()}
                for w in watchlist
            ],
        }
        print(json.dumps(out, indent=2))
        return 1 if (flagged or watchlist) else 0

    return print_report(flagged, watchlist, stats, args.fails,
                        args.window, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
