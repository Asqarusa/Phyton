#!/usr/bin/env python3
"""
file_integrity_checker.py — a tiny file-integrity monitor (SOC analyst style)

The idea, in one sentence: take a "fingerprint" of your important files today,
then re-check them later — if any fingerprint changed, someone (or something)
modified the file.

Real-world context: SOC teams run tools like this (called "file integrity
monitoring", or FIM) on servers. Attackers often change system or config files
to hide. A fingerprint mismatch is one of the earliest tripwires.

This script is defensive and local-only: it only reads files you point it at.
It never sends anything over the network.

Usage:
    # 1. Record the baseline (run once, when files are known-good):
    python3 file_integrity_checker.py snapshot files_to_watch.txt

    # 2. Verify later (run any time after):
    python3 file_integrity_checker.py verify files_to_watch.txt
"""

import hashlib
import json
import os
import sys

# Where the baseline fingerprints are stored (same folder as this script).
BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "baseline.json")

# How many bytes to read from a file at a time. Chunking keeps memory use
# flat even for big files.
CHUNK_SIZE = 65536


def fingerprint(path):
    """Compute the SHA-256 hash of a file, returned as a hex string.

    Think of SHA-256 as a fingerprint machine: feed it any bytes and it
    always produces a unique-looking 64-character code. Change even one
    byte of the file and the code looks completely different — which is
    exactly what makes tampering visible.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:          # "rb" = read raw bytes, not text
        while True:
            chunk = f.read(CHUNK_SIZE)    # read in small pieces, not all at once
            if not chunk:
                break                    # no more bytes -> we're done
            h.update(chunk)              # feed the piece into the fingerprint
    return h.hexdigest()


def load_watch_list(list_path):
    """Read the list of file paths to watch (one per line, # = comment)."""
    with open(list_path) as f:
        lines = [line.strip() for line in f]
    return [p for p in lines if p and not p.startswith("#")]


def cmd_snapshot(list_path):
    """Record today's fingerprints and save them as the baseline."""
    results = {}
    for path in load_watch_list(list_path):
        if not os.path.isfile(path):
            print(f"  [skip] not a file: {path}")
            continue
        results[os.path.abspath(path)] = fingerprint(path)
        print(f"  [ok] fingerprinted: {path}")
    with open(BASELINE_FILE, "w") as f:
        json.dump(results, f, indent=2)   # save so we can compare later
    print(f"\nBaseline saved to {BASELINE_FILE} ({len(results)} files)")


def cmd_verify(list_path):
    """Compare current files against the baseline and report changes."""
    if not os.path.exists(BASELINE_FILE):
        print("No baseline found. Run 'snapshot' first.")
        sys.exit(1)

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    watched = [os.path.abspath(p) for p in load_watch_list(list_path)]
    ok, changed, missing, new = 0, 0, 0, 0

    print(f"{'FILE':<40} STATUS")
    print("-" * 56)
    for path in watched:
        short = os.path.basename(path)
        if not os.path.isfile(path):
            print(f"{short:<40} MISSING (deleted?)")
            missing += 1
        elif path not in baseline:
            print(f"{short:<40} NEW (wasn't in baseline)")
            new += 1
        elif fingerprint(path) == baseline[path]:
            print(f"{short:<40} OK (unchanged)")
            ok += 1
        else:
            print(f"{short:<40} CHANGED! (contents differ)")
            changed += 1

    print("-" * 56)
    print(f"Summary: {ok} unchanged, {changed} changed, "
          f"{missing} missing, {new} new")
    if changed or missing:
        print("\nA CHANGED or MISSING file is exactly the tripwire firing: "
              "investigate before trusting that file.")
    elif new:
        print("\nNew files aren't in the baseline yet — re-run 'snapshot' "
              "if they belong here.")
    else:
        print("\nAll clear: every file matches its baseline fingerprint.")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("snapshot", "verify"):
        print(__doc__)
        sys.exit(1)
    command, list_path = sys.argv[1], sys.argv[2]
    if not os.path.isfile(list_path):
        print(f"Watch list not found: {list_path}")
        sys.exit(1)
    if command == "snapshot":
        cmd_snapshot(list_path)
    else:
        cmd_verify(list_path)


if __name__ == "__main__":
    main()
