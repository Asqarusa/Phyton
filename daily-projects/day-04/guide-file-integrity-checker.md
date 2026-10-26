# File Integrity Checker — Plain-English Guide

*Part of my daily "learning cybersecurity by building" series. Code: [daily-projects/day-04](https://github.com/Asqarusa/Phyton/tree/main/daily-projects/day-04)*

## What's new in this version (improved 2026-10-24)

This round finishes the improvement pass that stalled twice (Oct 22–23) and adds three more practical touches:

- **A safety net for the baseline itself.** Every new snapshot now saves the previous `baseline.json` as `baseline.json.bak` first. If you ever snapshot at the wrong moment — after a file was already tampered with — the old known-good fingerprints are still recoverable.
- **A damaged baseline no longer crashes the tool.** A corrupted `baseline.json` used to end in a Python traceback. Now verify reports a plain-English error, points you at the `.bak` restore, and exits with code 2 (setup error).
- **A `--changed-only` flag for verify.** When you watch dozens of files, you don't want to scroll past healthy ones. `verify --changed-only` hides the OK rows (in text and JSON output) and shows only what needs attention. The summary counts still cover every file.

*Non-tech analogy for this round:* the previous version gave the storage unit a timestamped photo album and an alarm bell; this version also keeps last month's album in a drawer (so a bad new photo can't erase the good one), explains problems in plain words instead of error codes, and lets you flip straight to the pages where something moved.

## What's new in this version (improved 2026-10-22)

I went back to my day-04 project and made it behave like a real monitoring tool:

- **Richer baseline.** Each snapshot now stores the file's size and last-modified time alongside its fingerprint. When a file changes, the report tells you *how* it changed — e.g. "size 183 → 207 (+24 bytes); modified 2026-10-22 21:19" — instead of just "it's different." That's the kind of clue a SOC analyst uses to triage.
- **Proper command-line flags.** The script now uses `argparse`: `verify --json w.txt` gives machine-readable JSON output, `--quiet` silences everything except errors, and a friendly help screen appears with `--help`. The old plain `snapshot w.txt` / `verify w.txt` one-liners still work.
- **Watch a whole folder with one line.** The watch list now accepts glob patterns like `configs/*.conf`, so one line covers every matching file.
- **Ghost detection.** If a watched file is deleted, a glob pattern would silently stop matching it — the tripwire would vanish without a trace. The improved verify now flags any baseline file that disappeared from the watch list as MISSING instead of quietly dropping it.
- **Exit codes for automation.** `0` = all clear, `1` = tripwire fired (changed or missing file), `2` = setup error. That means you can drop it into `cron` or any scheduler and get alerted automatically.
- **Friendlier failures.** Unreadable files are skipped with a clear message instead of crashing the whole run; a missing baseline or watch list explains what to do next.

*Non-tech analogy for the whole upgrade:* the first version was a photo album of your storage unit — this version adds a timestamp on every photo, notes which boxes got heavier, and rings a bell automatically if anything moved while you were away.

## The big idea (non-tech analogy first)

Imagine you have a storage unit with important boxes. One day you take a photo of the exact way every box is stacked. A month later, you compare a new photo with the old one — if a box moved even an inch, the photos won't match, and you know someone was in there.

This script does the same thing for computer files. The "photo" is called a **hash** — a fingerprint computed from the file's contents. Change even one letter in the file, and the fingerprint looks completely different. By comparing fingerprints taken at two points in time, we can tell whether any file was modified, deleted, or added.

Why does this matter? Attackers who break into a system often change config files or system files to hide their tracks. Security teams run exactly this kind of check — called **file integrity monitoring (FIM)** — on servers so they get alerted the moment a critical file changes unexpectedly. One of the earliest tripwires in a SOC analyst's toolkit.

## What the script does

It has two modes:

1. **Snapshot mode** — run once when your files are in a known-good state. It computes a fingerprint (SHA-256 hash) for every file in your watch list and saves them in `baseline.json`. This is your "photo from day one."
2. **Verify mode** — run any time after. It re-computes the fingerprints and compares them against the baseline, then prints a report:
   - **OK** — fingerprint matches, file untouched
   - **CHANGED!** — contents differ from baseline; investigate
   - **MISSING** — file was deleted; investigate
   - **NEW** — file wasn't in the baseline (maybe it belongs there, maybe not)

## How the code works, line by line (simple terms)

- **`import argparse, glob, hashlib, json, os, sys, time`** — borrows tools from Python's built-in toolbox: `hashlib` for fingerprinting, `json` for saving the baseline, `glob` for folder-wide watch patterns, `argparse` for proper command-line flags. Nothing to install.
- **`BASELINE_FILE`** — the name of the file where fingerprints get stored, kept in the same folder as the script.
- **`fingerprint(path)`** — the heart of the script. Opens the file in binary mode (raw bytes, so it works on any file type), reads it in 64 KB chunks so even huge files don't eat your memory, and feeds each chunk into SHA-256. Returns the final 64-character fingerprint.
- **`describe_file(path)`** *(new)* — fingerprints the file AND records its size and last-modified time, so a changed file comes with triage clues, not just a red flag.
- **`load_watch_list(list_path)`** *(improved)* — reads the watch list and expands glob patterns (e.g. `configs/*.conf`), resolving paths relative to the watch-list file. Directories and dead patterns are skipped with a clear message instead of crashing.
- **`friendly_time(ts)`** *(new)* — turns a raw timestamp into `2026-10-22 21:19:38` so the report reads like plain English.
- **`cmd_snapshot()`** *(improved)* — fingerprints each file with `describe_file`, skips unreadable files loudly instead of crashing, backs up the previous baseline to `baseline.json.bak` before overwriting, and reports how many files were saved. Returns an exit code.
- **`cmd_verify()`** *(improved)* — compares hash, size, and time; reports size deltas and modification times for changed files; includes the ghost check (baseline files that vanished from a glob pattern are flagged MISSING); supports `--json`, `--quiet`, and `--changed-only`; a damaged baseline now fails with a plain-English error (exit 2) instead of a traceback; returns `0`/`1`/`2` exit codes for automation.
- **`build_parser()`** *(new)* — defines the `snapshot`/`verify` commands and the `--json`/`--quiet` flags with `argparse`. Flags work before or after the command; the original bare one-liners keep working.
- **`main()`** — parses your input, finds the watch list (defaulting to the one next to the script), and calls the right function with a friendly error if something's missing.

## Key terms, translated

| Term | Plain English |
|---|---|
| Hash / fingerprint | A fixed-length code computed from a file's contents; the file's unique "signature" |
| SHA-256 | One well-tested recipe for computing that code (industry standard) |
| Baseline | The "before" photo — fingerprints taken when everything was fine |
| File integrity monitoring (FIM) | The professional name for this technique; used on real servers |
| Tripwire | Anything that signals "something happened here" — a changed hash is one |

## How to run it

You need only Python 3 — no installs, no admin rights, no network access.

```bash
# 1. Look at files_to_watch.txt and list the files you want monitored
#    (one path per line — plain paths or globs like "configs/*.conf")
# 2. Take the baseline (run once, while files are known-good):
python3 file_integrity_checker.py snapshot files_to_watch.txt

# 3. Verify later (run whenever you want to check):
python3 file_integrity_checker.py verify files_to_watch.txt

# 4. Machine-readable report (for cron jobs and alerting scripts):
python3 file_integrity_checker.py verify --json files_to_watch.txt

# 5. Silent mode — prints nothing unless something needs attention:
python3 file_integrity_checker.py verify --quiet files_to_watch.txt

# 6. Show only files that changed, went missing, or are new:
python3 file_integrity_checker.py verify --changed-only files_to_watch.txt

# Exit codes: 0 = all clear, 1 = a file changed or went missing, 2 = setup error
```

Try it yourself: take a snapshot, change one word in `sample_config.txt`, and verify again — you'll see `CHANGED!` with the size and timestamp clues, and `OK` for the other.

## What to learn next

- **Hashing vs. encryption:** a hash is one-way (you can't get the file back from it); encryption is two-way. Knowing which to use when is a foundational security skill.
- **Real FIM tools:** Wazuh, OSSEC, and Tripwire do this at enterprise scale, with alerts sent to a SOC.
- **Why attackers target config files:** adding a fake admin account, opening a firewall port, or swapping a login banner all start with changing a file — now you know how to catch it.
- **Extend it:** make the script watch a whole folder, email you on changes, or run on a schedule — each is a small, real project.

*Built and posted as part of my daily cybersecurity learning series — small project, plain-English write-up, every morning and evening.*
