#!/usr/bin/env python3
"""
password_breach_check.py — "Has this password been leaked?" checker (SOC edition)

Big idea: attackers don't always guess your password — they try passwords that
have already leaked in real data breaches. This script asks a public breach
database "how many times has this password appeared in known breaches?" WITHOUT
ever sending your actual password. That's the k-anonymity trick explained below.

It is defensive/educational only: it only reads data from a public API and
checks hashes, never passwords. No passwords are stored, logged, or sent.

How it works (the k-anonymity trick, in plain English):
  1. Your laptop hashes the password with SHA-1 (a one-way fingerprint).
  2. It sends ONLY the first 5 characters of that hash to the API.
  3. The API returns every leaked hash starting with those 5 characters
     (hundreds of them) — so the server can't tell which one is yours.
  4. Your laptop compares the rest of the hash locally and tells you the count.

Usage:
    python3 password_breach_check.py            # prompted, hidden input
    echo "MyP@ssw0rd" | python3 password_breach_check.py
    python3 password_breach_check.py --demo     # offline demo, no network, no password needed
    python3 password_breach_check.py --json     # machine-readable output
    python3 password_breach_check.py --verbose  # also show the 5-char prefix sent + candidates returned

Never commit real passwords — this tool is for learning and for checking
passwords you are considering or retiring, not for live credentials.

What's new in this version (2026-10-28 improvement pass):
  - --demo: fully offline demo that walks through the k-anonymity split and
    the verdict tiers with sample counts — great for classrooms and for
    machines with no internet, and it never asks for a real password.
  - --json: machine-readable output (verdict, count, prefix sent) for scripts
    and SOC pipelines, without ever printing the password or full hash.
  - --verbose: shows exactly what leaves your machine (the 5-char prefix)
    and how many candidate suffixes came back, so the privacy claim is
    visible instead of just promised.
  - --timeout: tune how long to wait for the API (default 15s).
  - Friendlier errors: timeouts, rate limits (HTTP 429) and network failures
    each get a plain-English explanation and a next step, plus exit codes
    (0 = checked, 1 = API/network problem, 2 = bad input).
  - Finer verdict tiers: 0 / 1-9 / 10-999 / 1000+ breaches, each with its
    own advice, so "seen twice" no longer sounds as bad as "seen millions
    of times".
  - Input validation: empty passwords are rejected with a clear message
    instead of being hashed and checked pointlessly.
"""

import argparse
import hashlib
import getpass
import json
import sys
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"  # HaveIBeenPwned, free & rate-limited

# Sample counts for --demo only. These illustrate the verdict tiers; they are
# NOT live API results. Real checks always hit the API (unless --demo).
DEMO_CASES = [
    ("a long, unique passphrase you just made up", 0),
    ("a password reused from an old forum account", 4),
    ("a common password with a year tacked on", 312),
    ("one of the most-cracked passwords in the world", 9_542_110),
]


def split_hash(password):
    """Return (prefix, suffix) of the password's SHA-1 fingerprint."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def fetch_suffixes(prefix, timeout=15):
    """Send only the first 5 hex chars of the SHA-1; get back all matching suffixes."""
    with urllib.request.urlopen(API_URL + prefix, timeout=timeout) as response:
        text = response.read().decode("utf-8")
    # Response format per line: "SUFFIX:count" — parse into a dict.
    results = {}
    for line in text.splitlines():
        if ":" not in line:
            continue  # skip any malformed line instead of crashing
        suffix, count = line.split(":", 1)
        try:
            results[suffix.strip()] = int(count.strip())
        except ValueError:
            continue
    return results


def check_password(password, timeout=15):
    """Return (count, prefix, candidates_returned) for `password`.

    Only the 5-char prefix leaves the machine; the suffix match happens here.
    """
    prefix, suffix = split_hash(password)
    suffixes = fetch_suffixes(prefix, timeout=timeout)
    return suffixes.get(suffix, 0), prefix, len(suffixes)


def verdict(count):
    """Translate a breach count into plain advice (finer tiers than before)."""
    if count == 0:
        return ("SAFE-ish", "not seen in known breaches. "
                "Still use a strong, unique password — absence from this "
                "list is not proof a password is strong.")
    if count < 10:
        return ("RISKY", "seen a few times — it is already on attackers' "
                "lists. Pick something unique.")
    if count < 1000:
        return ("BREACHED", "seen hundreds of times — do not use it. "
                "Change it everywhere you reused it.")
    return ("HEAVILY BREACHED", "seen thousands or millions of times — "
            "it is one of the first passwords attackers try. "
            "Never use it, and change it everywhere you reused it.")


def run_demo():
    """Offline walkthrough: no network, no password asked for, nothing sent."""
    print("DEMO MODE — offline. No password is asked for and nothing is sent anywhere.\n")
    print("Step 1 — the k-anonymity split, using the famous example 'password':")
    prefix, suffix = split_hash("password")
    print(f"  Full fingerprint starts with: {prefix}... (the rest stays on your machine)")
    print(f"  Only these 5 characters would be sent to the database: {prefix}")
    print("  The database would reply with every leaked fingerprint starting")
    print(f"  with {prefix} — hundreds of them — and your laptop would check")
    print("  privately whether its own suffix is in that pile.\n")
    print("Step 2 — what the verdict tiers mean (sample counts, not live results):")
    for description, count in DEMO_CASES:
        level, advice = verdict(count)
        print(f"  [{level}] {count:,} breaches — {description}: {advice}")
    print("\nTakeaway: a password that has leaked even once is burned everywhere")
    print("you reused it. Unique passwords + a password manager stop that cascade.")
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Check whether a password appears in known data breaches, "
                    "without ever sending the password itself (k-anonymity).")
    parser.add_argument("--demo", action="store_true",
                        help="offline demo of the k-anonymity split + verdict tiers (no network)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of plain text")
    parser.add_argument("--verbose", action="store_true",
                        help="also show the 5-char prefix sent and how many candidates came back")
    parser.add_argument("--timeout", type=float, default=15,
                        help="seconds to wait for the breach database (default: 15)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.timeout <= 0:
        print("Error: --timeout must be a positive number of seconds.", file=sys.stderr)
        return 2

    if args.demo:
        return run_demo()

    # Read password without echoing it to the screen.
    if sys.stdin.isatty():
        password = getpass.getpass("Enter a password to check (it won't show on screen): ")
    else:
        password = sys.stdin.readline().rstrip("\n")

    if not password:
        print("Error: no password entered — nothing to check. Exiting.", file=sys.stderr)
        return 2
    if len(password) > 256:
        print("Error: that input is over 256 characters — did you paste a file by mistake?",
              file=sys.stderr)
        return 2

    try:
        count, prefix, candidates = check_password(password, timeout=args.timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            message = ("The breach database is rate-limiting requests right now "
                       "(HTTP 429). Wait a minute and try again — it is free "
                       "but throttled.")
        else:
            message = (f"The breach database returned an error (HTTP {exc.code}). "
                       "Try again in a few minutes.")
        if args.json:
            print(json.dumps({"error": message, "http_status": exc.code}))
        else:
            print(f"Could not check the password: {message}")
        return 1
    except TimeoutError:
        message = ("The breach database did not answer in time. Check your "
                   "internet connection and try again (or raise --timeout).")
        if args.json:
            print(json.dumps({"error": message}))
        else:
            print(f"Could not check the password: {message}")
        return 1
    except Exception as exc:  # network/DNS problem — say so, don't fake a result
        message = (f"Could not reach the breach database ({exc}). Check your "
                   "internet connection and try again.")
        if args.json:
            print(json.dumps({"error": message}))
        else:
            print(f"Could not check the password: {message}")
        return 1

    level, advice = verdict(count)
    if args.json:
        result = {"verdict": level, "breach_count": count,
                  "prefix_sent": prefix, "advice": advice}
        if args.verbose:
            result["candidates_returned"] = candidates
        print(json.dumps(result))
    else:
        print(f"Breaches containing this password: {count:,}")
        print(f"[{level}] {advice}")
        if args.verbose:
            print(f"(Privacy check: only the prefix '{prefix}' left your machine, "
                  f"and {candidates:,} candidate fingerprints came back to compare locally.)")

    # One SOC-style tip: this is exactly the "password hygiene" control
    # attackers hope you skip. Reused passwords turn one breach into many.
    return 0


if __name__ == "__main__":
    sys.exit(main())
