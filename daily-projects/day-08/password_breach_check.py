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

Never commit real passwords — this tool is for learning and for checking
passwords you are considering or retiring, not for live credentials.
"""

import hashlib
import getpass
import sys
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"  # HaveIBeenPwned, free & rate-limited


def fetch_suffixes(prefix):
    """Send only the first 5 hex chars of the SHA-1; get back all matching suffixes."""
    with urllib.request.urlopen(API_URL + prefix, timeout=15) as response:
        text = response.read().decode("utf-8")
    # Response format per line: "SUFFIX:count" — parse into a dict.
    results = {}
    for line in text.splitlines():
        suffix, count = line.split(":")
        results[suffix.strip()] = int(count.strip())
    return results


def check_password(password):
    """Return how many times `password` appeared in known breaches (0 = not seen)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]   # only the prefix leaves your machine
    return fetch_suffixes(prefix).get(suffix, 0)


def verdict(count):
    if count == 0:
        return "SAFE-ish: not seen in known breaches. Still use a strong, unique password."
    if count < 10:
        return "RISKY: seen a few times — pick something unique."
    return "BREACHED: seen this many times — NEVER use it. Change it everywhere you used it."


def main():
    # Read password without echoing it to the screen.
    if sys.stdin.isatty():
        password = getpass.getpass("Enter a password to check (never logged): ")
    else:
        password = sys.stdin.readline().strip()

    if not password:
        print("No password entered. Exiting.")
        return

    try:
        count = check_password(password)
    except Exception as exc:  # network or API problem — say so, don't fake a result
        print(f"Could not reach the breach database: {exc}")
        return

    print(f"Breaches containing this password: {count}")
    print(verdict(count))

    # One SOC-style tip: this is exactly the "password hygiene" control
    # attackers hope you skip. Reused passwords turn one breach into many.


if __name__ == "__main__":
    main()
