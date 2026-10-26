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

    # 3. Machine-readable output (for cron / alerting scripts):
    python3 file_integrity_checker.py verify --json files_to_watch.txt

    # 4. Show only files that need attention (hide the OK rows):
    python3 file_integrity_checker.py verify --changed-only files_to_watch.txt

    # 5. A snapshot backs up the previous baseline to baseline.json.bak,
    #    and a damaged baseline.json fails with a clear error (exit 2)
    #    instead of a traceback.

Exit codes (so schedulers like cron can react automatically):
    0 = all clear / snapshot saved OK
    1 = tripwire fired — at least one file CHANGED or MISSING
    2 = usage or setup error (bad args, watch list not found, no baseline)
"""

import argparse
import glob
import hashlib
import json
import os
import sys
import time

# Where the baseline fingerprints are stored (same folder as this script).
BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "baseline.json")

# How many bytes to read from a file at a time. Chunking keeps memory use
# flat even for big files.
CHUNK_SIZE = 65536

# Statuses the verify report can produce (kept in one place so text and
# JSON output never drift apart).
OK, CHANGED, MISSING, NEW = "OK", "CHANGED", "MISSING", "NEW"


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


def describe_file(path):
    """Fingerprint a file and capture its size + last-modified time.

    Size and mtime are cheap early clues: they don't replace the hash, but
    they help an analyst triage a CHANGED file ("it grew by 200 bytes last
    night at 3 AM" is more useful than just "it's different").
    """
    st = os.stat(path)
    return {
        "sha256": fingerprint(path),
        "size": st.st_size,
        "mtime": st.st_mtime,
    }


def load_watch_list(list_path):
    """Read the watch list (one entry per line, # = comment).

    Each line may be a plain path OR a glob pattern like "configs/*.conf",
    so you can watch a whole folder with one line. Paths are resolved
    relative to the watch-list file itself, so the script works no matter
    which folder you run it from.
    """
    base_dir = os.path.dirname(os.path.abspath(list_path))
    entries = []
    with open(list_path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue                 # skip blanks and comments
            pattern = line if os.path.isabs(line) else os.path.join(base_dir, line)
            matches = sorted(glob.glob(pattern, recursive=True))
            if matches:                  # glob matched real files
                entries.extend(m for m in matches if os.path.isfile(m))
            elif os.path.isfile(pattern):
                entries.append(os.path.abspath(pattern))
            elif os.path.isdir(pattern):
                print(f"  [skip] '{line}' is a directory — "
                      f"list files or use a glob like '{line.rstrip('/')}/*'",
                      file=sys.stderr)
            else:
                print(f"  [skip] no files match: {line}", file=sys.stderr)
    # De-duplicate while keeping order (a file may match two patterns).
    seen, unique = set(), []
    for e in entries:
        key = os.path.abspath(e)
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


def friendly_time(ts):
    """Turn a raw timestamp into something a human can read at a glance."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def cmd_snapshot(list_path, quiet=False):
    """Record today's fingerprints and save them as the baseline."""
    results = {}
    skipped = 0
    for path in load_watch_list(list_path):
        try:
            results[path] = describe_file(path)
        except OSError as exc:
            # Permission denied / unreadable file: skip loudly instead of
            # crashing, so the rest of the baseline still gets saved.
            skipped += 1
            print(f"  [skip] can't read {path}: {exc.strerror or exc}",
                  file=sys.stderr)
            continue
        if not quiet:
            print(f"  [ok] fingerprinted: {path}")
    # Safety net: before overwriting, keep a copy of the previous baseline.
    # If a snapshot is ever taken at the wrong moment (files already
    # tampered with), the old "known-good" fingerprints are still recoverable.
    if os.path.exists(BASELINE_FILE):
        backup = BASELINE_FILE + ".bak"
        try:
            with open(BASELINE_FILE, "rb") as src, open(backup, "wb") as dst:
                dst.write(src.read())
            if not quiet:
                print(f"  (previous baseline backed up to {backup})")
        except OSError as exc:
            print(f"  [warn] couldn't back up old baseline: {exc}",
                  file=sys.stderr)
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(results, f, indent=2)   # save so we can compare later
    except OSError as exc:
        print(f"Error: couldn't write baseline file: {exc}", file=sys.stderr)
        return 2
    if not quiet:
        print(f"\nBaseline saved to {BASELINE_FILE} "
              f"({len(results)} files, {skipped} skipped)")
    return 0


def cmd_verify(list_path, as_json=False, quiet=False, changed_only=False):
    """Compare current files against the baseline and report changes.

    Returns an exit code: 0 all clear, 1 tripwire fired, 2 setup error.
    """
    if not os.path.exists(BASELINE_FILE):
        msg = ("No baseline found. Run 'snapshot' first to take your "
               "'day one' photo.")
        if as_json:
            print(json.dumps({"error": msg}, indent=2))
        else:
            print(msg)
        return 2

    try:
        with open(BASELINE_FILE) as f:
            baseline = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        # A damaged baseline used to crash the whole run with a traceback.
        # Now it fails loudly but gracefully — and points at the fix.
        # (A .bak copy from the last snapshot may still hold good data.)
        msg = (f"Baseline file is unreadable ({exc}). Re-run 'snapshot' "
               f"when files are known-good, or restore baseline.json.bak.")
        if as_json:
            print(json.dumps({"error": msg}, indent=2))
        else:
            print(msg, file=sys.stderr)
        return 2
    if not isinstance(baseline, dict):
        msg = ("Baseline file has an unexpected format. Re-run 'snapshot' "
               "when files are known-good.")
        if as_json:
            print(json.dumps({"error": msg}, indent=2))
        else:
            print(msg, file=sys.stderr)
        return 2

    watched = load_watch_list(list_path)
    findings = []   # one dict per watched file: {file, status, detail}

    for path in watched:
        name = os.path.basename(path)
        if not os.path.isfile(path):
            findings.append({"file": name, "status": MISSING,
                             "detail": "file is gone — deleted or moved?"})
        elif path not in baseline:
            findings.append({"file": name, "status": NEW,
                             "detail": "not in baseline — re-run snapshot "
                                       "if it belongs here"})
        else:
            old = baseline[path]
            try:
                now = describe_file(path)
            except OSError as exc:
                findings.append({"file": name, "status": MISSING,
                                 "detail": f"unreadable now: "
                                           f"{exc.strerror or exc}"})
                continue
            if now["sha256"] == old["sha256"]:
                findings.append({"file": name, "status": OK,
                                 "detail": "fingerprint matches"})
            else:
                # Hash differs — size + time clues help the analyst decide
                # how worried to be before opening the file.
                clues = []
                if now["size"] != old["size"]:
                    delta = now["size"] - old["size"]
                    clues.append(f"size {old['size']} -> {now['size']} "
                                 f"({delta:+,d} bytes)")
                if now["mtime"] != old["mtime"]:
                    clues.append(f"modified {friendly_time(now['mtime'])}")
                if not clues:
                    clues.append("same size & time but different contents "
                                 "(stealthy edit — investigate)")
                findings.append({"file": name, "status": CHANGED,
                                 "detail": "; ".join(clues)})

    # Ghost check: a file that WAS in the baseline but no longer matches any
    # watch-list entry. With plain paths this can't happen (a deleted file
    # still lists its path), but with glob patterns like "logs/*.log" a
    # deleted file simply vanishes from the glob — and silently dropping a
    # tripwire is the worst outcome for a monitoring tool. Flag it.
    watched_set = set(watched)
    for old_path in baseline:
        if old_path in watched_set or os.path.isfile(old_path):
            continue              # still watched, or removed from the list
                                  # on purpose (file still exists)
        findings.append({"file": os.path.basename(old_path),
                         "status": MISSING,
                         "detail": "was in baseline but matches no watch-list "
                                   "entry now — deleted?"})

    counts = {s: sum(1 for f in findings if f["status"] == s)
              for s in (OK, CHANGED, MISSING, NEW)}
    tripwire = counts[CHANGED] + counts[MISSING]

    if as_json:
        shown = ([f for f in findings if f["status"] != OK]
                 if changed_only else findings)
        print(json.dumps({"summary": counts, "findings": shown},
                         indent=2))
    elif not quiet:
        print(f"{'FILE':<36} STATUS   DETAIL")
        print("-" * 88)
        for f in findings:
            if changed_only and f["status"] == OK:
                continue    # quiet about the healthy files; show only
                            # what needs attention
            print(f"{f['file']:<36} {f['status']:<8} {f['detail']}")
        print("-" * 88)
        print(f"Summary: {counts[OK]} unchanged, {counts[CHANGED]} changed, "
              f"{counts[MISSING]} missing, {counts[NEW]} new")
        if tripwire:
            print("\nA CHANGED or MISSING file is exactly the tripwire firing: "
                  "investigate before trusting that file.")
        elif counts[NEW]:
            print("\nNew files aren't in the baseline yet — re-run 'snapshot' "
                  "if they belong here.")
        else:
            print("\nAll clear: every file matches its baseline fingerprint.")

    return 1 if tripwire else 0


def build_parser():
    """Command-line flags. Plain `snapshot <list>` / `verify <list>` still
    work, so the original one-liners from the first version keep working.

    Flags are accepted either before or after the command:
        verify w.txt --json        # machine-readable
        --json verify w.txt         # same thing
    """

    def add_flags(p, subcommand=False):
        # Sub-command copies use SUPPRESS so a flag given BEFORE the command
        # (e.g. `--json verify w.txt`) isn't clobbered by sub-parser defaults.
        dflt = argparse.SUPPRESS if subcommand else False
        p.add_argument("--json", dest="as_json", action="store_true",
                       default=dflt,
                       help="print the verify report as JSON (for scripts/cron)")
        p.add_argument("--quiet", "-q", dest="quiet", action="store_true",
                       default=dflt,
                       help="print only errors (cron-friendly)")
        p.add_argument("--changed-only", dest="changed_only",
                       action="store_true", default=dflt,
                       help="verify only: hide OK files, show only "
                            "CHANGED/MISSING/NEW findings")
        return p

    def add_watch_list(p):
        p.add_argument("watch_list", nargs="?", default=argparse.SUPPRESS,
                       help="path to the watch list (default: files_to_watch.txt "
                            "next to the script)")
        return p

    p = argparse.ArgumentParser(
        description="Tiny file-integrity monitor: snapshot fingerprints now, "
                    "verify them later to catch tampering.")
    add_flags(p)  # flags also accepted before the command
    sub = p.add_subparsers(dest="command", required=True,
                           help="snapshot = record today's baseline; "
                                "verify = compare against it")
    for name, help_text in (("snapshot", "record today's fingerprints"),
                            ("verify", "compare current files against the baseline")):
        sp = sub.add_parser(name, help=help_text)
        add_watch_list(sp)
        add_flags(sp, subcommand=True)
    return p


def main():
    args = build_parser().parse_args()
    # Flags may live on the main parser or the sub-command (SUPPRESS means
    # "only present if the user actually typed it") — resolve either way.
    watch_list = getattr(args, "watch_list", "files_to_watch.txt")
    as_json = getattr(args, "as_json", False)
    quiet = getattr(args, "quiet", False)
    changed_only = getattr(args, "changed_only", False)
    list_path = watch_list
    if not os.path.isabs(list_path):
        # Default resolves next to the script; an explicit relative path
        # resolves from wherever you run the command.
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default = os.path.join(script_dir, "files_to_watch.txt")
        list_path = (default if watch_list == "files_to_watch.txt"
                     and not os.path.isfile(list_path) else list_path)
    if not os.path.isfile(list_path):
        print(f"Watch list not found: {watch_list}\n"
              f"Create one (one path per line, # = comment), or pass its path.",
              file=sys.stderr)
        return 2
    if args.command == "snapshot":
        return cmd_snapshot(list_path, quiet=quiet)
    return cmd_verify(list_path, as_json=as_json, quiet=quiet,
                      changed_only=changed_only)


if __name__ == "__main__":
    sys.exit(main())
