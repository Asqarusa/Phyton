#!/usr/bin/env python3
"""
Hash Identifier — a beginner SOC tool for learning about file/data fingerprints.

WHAT IT DOES
------------
1. IDENTIFY MODE: paste a cryptographic hash (e.g. from a malware report or a
   file-integrity alert) and the tool tells you which algorithm probably made
   it (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3, bcrypt) and
   explains what each means for a SOC analyst.
2. HASH MODE: point it at one of YOUR OWN files and it computes the file's
   MD5 / SHA-1 / SHA-256 / SHA-512 fingerprints — the same values analysts
   paste into threat-intelligence lookups to check if a file is known malware.
3. BATCH MODE: feed it a file with one hash per line and get a summary table.
4. TEXT MODE: hash any short word or phrase right on the command line.

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
    python3 hash_identifier.py                    # guided demo
    python3 hash_identifier.py identify           # paste your own hash to identify
    python3 hash_identifier.py --identify <hash>  # identify one hash, no prompts
    python3 hash_identifier.py hash <file>        # fingerprint one of YOUR files
    python3 hash_identifier.py --file <file>      # same, with --json / --all options
    python3 hash_identifier.py --text "hello"     # hash a word directly
    python3 hash_identifier.py --batch hashes.txt # identify many hashes at once
    python3 hash_identifier.py --demo             # guided demo (same as no args)

Everything runs locally on your own laptop. No uploads, no network calls.

What's new in this version (2026-10-31 improvement pass):
  - argparse CLI: --identify / --file / --text / --batch / --json / --demo
    (the old "identify" and "hash <file>" commands still work).
  - More hash types: SHA-224 (56 hex) and SHA-384 (96 hex) added, plus
    SHA3-256/SHA3-512 noted as look-alikes of SHA-256/SHA-512.
  - Ambiguity is explicit: a 64-hex hash is now reported as "SHA-256 or
    SHA3-256" with a plain-English note on how analysts tell them apart,
    instead of silently picking one.
  - --batch: identify a whole list of hashes from a file, with a summary
    table (how many of each type, how many unrecognized).
  - --text: hash a short word or phrase directly (great for the avalanche
    demo: "hello" vs "hallo" give totally different fingerprints).
  - File mode now also computes SHA-512, shows file size, and supports
    --json machine-readable output for SOC pipelines.
  - Friendlier errors: missing files, directories, and unreadable files
    each get a plain-English explanation and exit code 2; bad hashes get
    a hint about what a hash should look like (exit code 1 for no match
    is kept for scripts: use --json to get a structured result).
"""

import argparse
import hashlib
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Hash "signatures" — what each algorithm's output looks like.
# A hash is always a fixed length for a given algorithm, which is the main
# clue we use to identify it. Some lengths are shared by more than one
# algorithm — that ambiguity is real, and analysts deal with it every day.
# ---------------------------------------------------------------------------
HASH_SIGNATURES = [
    {
        "name": "bcrypt (password hash)",
        "pattern": r"^\$2[aby]\$\d{2}\$[./0-9A-Za-z]{53}$",
        "ambiguous_with": [],
        "soc_note": (
            "Not a file fingerprint — this is how passwords are stored safely. "
            "The '$2b$12$' prefix tells you the algorithm (bcrypt) and the "
            "cost factor (12 = how hard it is to crack). SOC relevance: if you "
            "see these in a breached database dump, it means the company was "
            "storing passwords correctly."
        ),
    },
    {
        "name": "SHA-512 (or SHA3-512)",
        "pattern": r"^[0-9a-fA-F]{128}$",
        "ambiguous_with": ["SHA3-512"],
        "soc_note": (
            "512-bit fingerprint, 128 hex characters. Very strong — used by "
            "Linux package managers and software vendors to prove downloads "
            "weren't tampered with. Analysts see these in vendor checksums. "
            "SHA3-512 looks identical (same length), so reports usually say "
            "which algorithm was used — length alone can't tell them apart."
        ),
    },
    {
        "name": "SHA-384",
        "pattern": r"^[0-9a-fA-F]{96}$",
        "ambiguous_with": [],
        "soc_note": (
            "384-bit fingerprint, 96 hex characters. A middle ground between "
            "SHA-256 and SHA-512 — you meet it in TLS certificates and signed "
            "software. Strong and modern; if you see 96 hex characters, this "
            "is almost certainly it."
        ),
    },
    {
        "name": "SHA-256 (or SHA3-256)",
        "pattern": r"^[0-9a-fA-F]{64}$",
        "ambiguous_with": ["SHA3-256"],
        "soc_note": (
            "256-bit fingerprint, 64 hex characters. THE standard hash in "
            "modern SOC work — VirusTotal, malware sandboxes, and EDR tools "
            "all index files by SHA-256. If you can only remember one hash "
            "type, remember this one. SHA3-256 has the same length, so when a "
            "report just says '64 hex characters', analysts check the source "
            "tool to confirm which one it is."
        ),
    },
    {
        "name": "SHA-224",
        "pattern": r"^[0-9a-fA-F]{56}$",
        "ambiguous_with": [],
        "soc_note": (
            "224-bit fingerprint, 56 hex characters. The compact cousin of "
            "SHA-256 — same family, shorter output. You see it in some TLS "
            "certificates and older HMAC setups. Uncommon in malware reports, "
            "which is itself a useful clue."
        ),
    },
    {
        "name": "SHA-1",
        "pattern": r"^[0-9a-fA-F]{40}$",
        "ambiguous_with": [],
        "soc_note": (
            "160-bit fingerprint, 40 hex characters. Older standard — now "
            "considered weak (researchers can forge SHA-1 collisions), but "
            "you'll still see it in legacy reports and Git commit IDs."
        ),
    },
    {
        "name": "MD5 (or NTLM)",
        "pattern": r"^[0-9a-fA-F]{32}$",
        "ambiguous_with": ["NTLM"],
        "soc_note": (
            "128-bit, 32 hex characters — but AMBIGUOUS. A plain MD5 file hash "
            "and a Windows NTLM password hash look identical (same length, "
            "same characters). MD5 is broken for security use — never trust it "
            "for integrity checks. NTLM hashes are what attackers try to steal "
            "from Windows machines (pass-the-hash attacks). Context decides: "
            "came from a file? Probably MD5. Came from a Windows credential "
            "dump? Probably NTLM."
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


def hash_file(path, include_sha512=True):
    """Compute fingerprints of a local file, reading in chunks.

    Returns a dict like {"MD5": ..., "SHA-1": ..., "SHA-256": ...,
    "SHA-512": ...}. Reading 64 KB at a time means even a 10 GB file
    won't eat all your memory.
    """
    algos = {
        "MD5": hashlib.md5(),
        "SHA-1": hashlib.sha1(),
        "SHA-256": hashlib.sha256(),
    }
    if include_sha512:
        algos["SHA-512"] = hashlib.sha512()
    with open(path, "rb") as f:          # "rb" = read raw bytes, any file type
        while True:
            chunk = f.read(65536)        # 64 KB at a time — works on huge files
            if not chunk:
                break
            for h in algos.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in algos.items()}


def hash_text(text):
    """Hash a short string with every supported algorithm (avalanche demo)."""
    data = text.encode("utf-8")
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-224": hashlib.sha224(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-384": hashlib.sha384(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }


def describe_hash(value):
    """Plain-English verdict for one hash string (used by --identify/--json)."""
    value = value.strip()
    matches = identify_hash(value)
    if not matches:
        return {
            "input": value,
            "recognized": False,
            "matches": [],
            "hint": (
                "Hashes are fixed-length strings of hex characters "
                "(0-9, a-f). Common lengths: 32 (MD5), 40 (SHA-1), "
                "56 (SHA-224), 64 (SHA-256), 96 (SHA-384), 128 (SHA-512)."
            ),
        }
    return {
        "input": value,
        "recognized": True,
        "matches": [
            {"name": name, "soc_note": note} for name, note in matches
        ],
        "hint": None,
    }


def print_identification(value):
    print(f"\nInput: {value}")
    result = describe_hash(value)
    if not result["recognized"]:
        print("  -> Not a recognized hash format.")
        print(f"     Tip: {result['hint']}")
        return
    for match in result["matches"]:
        print(f"  -> Likely: {match['name']}")
        print(f"     SOC note: {match['soc_note']}")


def run_batch(path):
    """Identify every hash in a file (one per line) and print a summary table."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: batch file '{path}' not found.")
        return 2
    except OSError as exc:
        print(f"Error: could not read '{path}': {exc}")
        return 2

    if not lines:
        print(f"Batch file '{path}' has no hashes in it (one hash per line).")
        return 2

    counts = {}
    unrecognized = []
    print(f"\nIdentifying {len(lines)} hash(es) from {path}:\n")
    for value in lines:
        result = describe_hash(value)
        if not result["recognized"]:
            unrecognized.append(value)
            print(f"  {value[:40]:40} -> NOT RECOGNIZED")
            continue
        name = result["matches"][0]["name"]
        counts[name] = counts.get(name, 0) + 1
        print(f"  {value[:40]:40} -> {name}")

    print("\n" + "-" * 60)
    print("SUMMARY")
    for name, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {name:28} {count}")
    if unrecognized:
        print(f"  {'Not recognized':28} {len(unrecognized)}")
    print(f"  {'Total':28} {len(lines)}")
    print("-" * 60)
    return 0


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
        "SHA-224 of the word 'hello'": hashlib.sha224(b"hello").hexdigest(),
        "SHA-256 of the word 'hello'": hashlib.sha256(b"hello").hexdigest(),
        "SHA-384 of the word 'hello'": hashlib.sha384(b"hello").hexdigest(),
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

    print("\n" + "-" * 70)
    print("PART 3 — NEW: the avalanche effect, up close.")
    print("  'hello' and 'hallo' differ by one letter. Watch the fingerprints:")
    for word in ("hello", "hallo"):
        print(f"\n  {word!r} -> SHA-256 {hashlib.sha256(word.encode()).hexdigest()}")
    print("  Same length, totally different output. One changed bit flips")
    print("  about half the characters — that's why a tampered file can")
    print("  never hide behind its original hash.")

    print("\n" + "=" * 70)
    print("KEY TAKEAWAY: hashes turn any file into a fixed fingerprint you can")
    print("look up, compare, and share without sharing the file itself.")
    print("=" * 70)


def check_file_path(path):
    """Validate a file path with a friendly error; returns an exit code or None."""
    if not os.path.exists(path):
        print(f"Error: '{path}' does not exist. Check the spelling and try again.")
        return 2
    if os.path.isdir(path):
        print(f"Error: '{path}' is a folder, not a file. Point it at a single file.")
        return 2
    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a regular file (it may be a device or link).")
        return 2
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Identify hash types and fingerprint your own files (SOC learning tool)."
    )
    parser.add_argument("--identify", metavar="HASH",
                        help="identify one hash and exit (no prompts)")
    parser.add_argument("--file", metavar="PATH",
                        help="fingerprint a file (MD5/SHA-1/SHA-256/SHA-512)")
    parser.add_argument("--text", metavar="WORD",
                        help="hash a short word or phrase with every algorithm")
    parser.add_argument("--batch", metavar="PATH",
                        help="identify every hash in a file (one per line)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable JSON output (with --identify/--file/--text)")
    parser.add_argument("--demo", action="store_true",
                        help="run the guided demo")
    # Old-style positional commands still work, for backwards compatibility.
    parser.add_argument("command", nargs="?", choices=["identify", "hash"],
                        help="legacy command: identify (interactive) or hash <file>")
    parser.add_argument("target", nargs="?", help="file for legacy 'hash' command")
    args = parser.parse_args()

    # --- New-style flags ---------------------------------------------------
    if args.demo:
        run_demo()
        return 0

    if args.identify is not None:
        result = describe_hash(args.identify)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_identification(args.identify)
        return 0 if result["recognized"] else 1

    if args.file is not None:
        problem = check_file_path(args.file)
        if problem is not None:
            return problem
        try:
            digests = hash_file(args.file)
        except OSError as exc:
            print(f"Error: could not read '{args.file}': {exc}")
            return 2
        if args.json:
            print(json.dumps({
                "file": args.file,
                "size_bytes": os.path.getsize(args.file),
                "hashes": digests,
            }, indent=2))
        else:
            print(f"Fingerprints for: {args.file} "
                  f"({os.path.getsize(args.file)} bytes)")
            for name, digest in digests.items():
                print(f"  {name:8} {digest}")
        return 0

    if args.text is not None:
        digests = hash_text(args.text)
        if args.json:
            print(json.dumps({"text": args.text, "hashes": digests}, indent=2))
        else:
            print(f"Hashes for {args.text!r}:")
            for name, digest in digests.items():
                print(f"  {name:8} {digest}")
        return 0

    if args.batch is not None:
        return run_batch(args.batch)

    # --- Legacy commands ---------------------------------------------------
    if args.command == "identify":
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
        return 0

    if args.command == "hash" and args.target:
        problem = check_file_path(args.target)
        if problem is not None:
            return problem
        try:
            digests = hash_file(args.target)
        except OSError as exc:
            print(f"Error: could not read '{args.target}': {exc}")
            return 2
        print(f"Fingerprints for: {args.target}")
        for name, digest in digests.items():
            print(f"  {name:8} {digest}")
        return 0

    if args.command == "hash" and not args.target:
        print("Error: 'hash' needs a file. Example: python3 hash_identifier.py hash myfile.txt")
        return 2

    # No arguments: run the demo, as before.
    run_demo()
    return 0


if __name__ == "__main__":
    sys.exit(main())
