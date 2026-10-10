# File Integrity Checker — Plain-English Guide

*Part of my daily "learning cybersecurity by building" series. Code: [daily-projects/day-04](https://github.com/Asqarusa/Phyton/tree/main/daily-projects/day-04)*

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

- **`import hashlib, json, os, sys`** — borrows tools from Python's built-in toolbox: `hashlib` for fingerprinting, `json` for saving the baseline as a readable file, `os`/`sys` for paths and command-line arguments. Nothing to install.
- **`BASELINE_FILE`** — the name of the file where fingerprints get stored, kept in the same folder as the script.
- **`fingerprint(path)`** — the heart of the script. Opens the file in binary mode (raw bytes, so it works on any file type), reads it in 64 KB chunks so even huge files don't eat your memory, and feeds each chunk into SHA-256. Returns the final 64-character fingerprint.
- **`load_watch_list(list_path)`** — reads `files_to_watch.txt` (one file path per line, `#` lines are comments) and returns the clean list.
- **`cmd_snapshot()`** — loops over the watch list, fingerprints each file, stores results keyed by full path, and writes them to `baseline.json`.
- **`cmd_verify()`** — loads the baseline, re-fingerprints each watched file, and prints a status table with a summary. Ends with plain advice: changed or missing files mean "investigate before trusting that file."
- **`main()`** — checks your command-line input (`snapshot` or `verify` plus a watch-list file) and calls the right function. If you run the script with no arguments, it prints the built-in usage guide.

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
# 2. Take the baseline (run once, while files are known-good):
python3 file_integrity_checker.py snapshot files_to_watch.txt

# 3. Verify later (run whenever you want to check):
python3 file_integrity_checker.py verify files_to_watch.txt
```

Try it yourself: take a snapshot, change one word in `sample_config.txt`, and verify again — you'll see `CHANGED!` for that file and `OK` for the other.

## What to learn next

- **Hashing vs. encryption:** a hash is one-way (you can't get the file back from it); encryption is two-way. Knowing which to use when is a foundational security skill.
- **Real FIM tools:** Wazuh, OSSEC, and Tripwire do this at enterprise scale, with alerts sent to a SOC.
- **Why attackers target config files:** adding a fake admin account, opening a firewall port, or swapping a login banner all start with changing a file — now you know how to catch it.
- **Extend it:** make the script watch a whole folder, email you on changes, or run on a schedule — each is a small, real project.

*Built and posted as part of my daily cybersecurity learning series — small project, plain-English write-up, every morning and evening.*
