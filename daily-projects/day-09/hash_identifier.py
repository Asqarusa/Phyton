#!/usr/bin/env python3
"""
Hash Identifier — a beginner SOC tool for learning about file/data fingerprints.

WHAT IT DOES
------------
1. IDENTIFY MODE: paste a cryptographic hash (e.g. from a malware report or a
   file-integrity alert) and the tool tells you which algorithm probably made
   it (MD5, SHA-1, SHA-256, SHA-512, bcrypt) and explains what each means for
   a SOC analyst.
2. HASH MODE: point it at one of YOUR OWN files and it computes the file's
   MD5 / SHA-1 / SHA-256 fingerprints — the same values analysts paste into
   threat-intelligence lookups to check if a file is known malware.

WHY THIS MATTERS FOR SOC WORK
------------------------------
A hash is a file's "digital fingerprint". When a SOC analyst finds a suspicious
file, the first thing they do is hash it and search that fingerprint in
threat-intelligence databases. If the fingerprint matches a known-malware
entry, they know instantly what they're dealing with — no need to open the
file. Identifying the hash TYPE matters because different tools and reports
use different algorithms, and some (like MD5) are no longer trustworthy.

RUN IT
------
    python3 hash_identifier.py              # runs the guided demo
    python3 hash_identifier.py identify     # paste your own hash to identify
    python3 hash_identifier.py hash <file>  # fingerprint one of YOUR files

Everything runs locally on your own laptop. No uploads, no network calls.
"""

import hashlib
import os
import re
import sys

# ---------------------------------------------------------------------------
# Hash "signatures" — what each algorithm's output looks like.
# A hash is always a fixed length for a given algorithm, which is the main
# clue we use to identify it.
# ---------------------------------------------------------------------------
HASH_SIGNATURES = [
    {
        "name": "bcrypt (password hash)",
        "pattern": r"^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$",
        "soc_note": (
            "Not a file fingerprint — this is how passwords are stored safely. "
            "The '$2b$12$' prefix tells you the algorithm (bcrypt) and the "
            "cost factor (12 = how hard it is to crack). SOC relevance: if you "
            "see these in a breached database dump, it means the company was "
            "storing passwords correctly."
        ),
    },
    {
        "name": "SHA-512",
        "pattern": r"^[0-9a-fA-F]{128}$",
        "soc_note": (
            "512-bit fingerprint, 128 hex characters. Very strong — used by "
            "Linux package managers and software vendors to prove downloads "
            "weren't tampered with. Analysts see these in vendor checksums."
        ),
    },
    {
        "name": "SHA-256",
        "pattern": r"^[0-9a-fA-F]{64}$",
        "soc_note": (
            "256-bit fingerprint, 64 hex characters. THE standard hash in "
            "modern SOC work — VirusTotal, malware sandboxes, and EDR tools "
            "all index files by SHA-256. If you can only remember one hash "
            "type, remember this one."
        ),
    },
    {
        "name": "SHA-1",
        "pattern": r"^[0-9a-fA-F]{40}$",
        "soc_note": (
            "160-bit fingerprint, 40 hex characters. Older standard — now "
            "considered weak (researchers can forge SHA-1 collisions), but "
            "you'll still see it in legacy reports and Git commit IDs."
        ),
    },
    {
        "name": "MD5 (or NTLM)",
        "pattern": r"^[0-9a-fA-F]{32}$",
        "soc_note": (
            "128-bit, 32 hex characters — but AMBIGUOUS. A plain MD5 file hash "
            "and a Windows NTLM password hash look identical (same length, "
            "same characters). MD5 is broken for security use — never trust it "
            "for integrity checks. NTLM hashes are what attackers try to steal "
            "from Windows machines (pass-the-hash attacks)."
        ),
    },
]


def identify_hash(value):
    """Return a list of (name, soc_note) candidates matching the given hash."""
    value = value.strip()
    matches = []
    for sig in HASH_SIGNATURES:
        if re.match(sig["pattern"], value):
            matches.append((sig["name"], sig["soc_note"]))
    return matches


def hash_file(path):
    """Compute MD5, SHA-1 and SHA-256 of a local file, reading in chunks."""
    digests = {
        "MD5": hashlib.md5(),
        "SHA-1": hashlib.sha1(),
        "SHA-256": hashlib.sha256(),
    }
    with open(path, "rb") as f:          # "rb" = read raw bytes, any file type
        while True:
            chunk = f.read(65536)        # 64 KB at a time — works on huge files
            if not chunk:
                break
            for h in digests.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in digests.items()}


def print_identification(value):
    print(f"\nInput: {value}")
    matches = identify_hash(value)
    if not matches:
        print("  -> Not a recognized hash format.")
        print("     Tip: hashes are fixed-length strings of hex characters")
        print("     (0-9, a-f). Common lengths: 32, 40, 64, 128.")
        return
    for name, note in matches:
        print(f"  -> Likely: {name}")
        print(f"     SOC note: {note}")


def run_demo():
    """Guided demo with known hashes + fingerprinting the sample file."""
    print("=" * 70)
    print("HASH IDENTIFIER — demo")
    print("=" * 70)
    print("\nPART 1 — Identify these hashes (answers computed from known values):")

    # Well-known reference hashes, so the demo is reproducible and verifiable.
    samples = {
        "MD5 of the word 'hello'": hashlib.md5(b"hello").hexdigest(),
        "SHA-1 of the word 'hello'": hashlib.sha1(b"hello").hexdigest(),
        "SHA-256 of the word 'hello'": hashlib.sha256(b"hello").hexdigest(),
        "SHA-512 of the word 'hello'": hashlib.sha512(b"hello").hexdigest(),
    }
    for label, h in samples.items():
        print(f"\n  [{label}]")
        print_identification(h)

    print("\n" + "-" * 70)
    print("PART 2 — Fingerprint a real file (the sample file next to this script):")
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "sample_file.txt")
    if os.path.exists(sample):
        print(f"\n  File: sample_file.txt ({os.path.getsize(sample)} bytes)")
        for name, digest in hash_file(sample).items():
            print(f"  {name:8} {digest}")
        print("\n  Try it: change one letter in sample_file.txt and run again —")
        print("  the fingerprints change completely. That's the 'avalanche")
        print("  effect', and it's exactly why hashes catch tampered files.")
    else:
        print("  sample_file.txt not found — run 'hash' mode on any of your files:")
        print("      python3 hash_identifier.py hash <your-file>")

    print("\n" + "=" * 70)
    print("KEY TAKEAWAY: hashes turn any file into a fixed fingerprint you can")
    print("look up, compare, and share without sharing the file itself.")
    print("=" * 70)


def main():
    args = sys.argv[1:]

    if not args:
        run_demo()
        return

    if args[0] == "identify":
        # Interactive mode: paste hashes until you type 'quit'.
        print("Paste a hash to identify it (type 'quit' to exit):")
        while True:
            try:
                value = input("hash> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if value.lower() in ("quit", "exit", "q"):
                break
            if value:
                print_identification(value)
        return

    if args[0] == "hash" and len(args) == 2:
        path = args[1]
        if not os.path.isfile(path):
            print(f"Error: '{path}' is not a file.")
            sys.exit(1)
        print(f"Fingerprints for: {path}")
        for name, digest in hash_file(path).items():
            print(f"  {name:8} {digest}")
        return

    print(__doc__)


if __name__ == "__main__":
    main()
