# Auth Log Parser — Plain-English Guide

*Part of my daily "learning cybersecurity by building" series. Code: [daily-projects/day-06](https://github.com/Asqarusa/Phyton/tree/main/daily-projects/day-06)*

## The big idea (non-tech analogy first)

Imagine you're a security guard watching a building with a sign-in book. Every visitor writes their name, the time, and whether they were let in. One morning you flip through last night's pages and notice: the same stranger tried the back door eleven times at 3 AM, and someone targeted the CEO's office specifically. That pattern in the sign-in book *is* the story — you'd report it up immediately.

Linux servers keep exactly this kind of sign-in book: a file called the **auth log** (`/var/log/auth.log`) that records every login attempt — who tried, from which computer, and whether they got in. SOC (Security Operations Center) analysts read these logs all day, looking for the same patterns our guard found: one IP hammering the server, unusual usernames being tried, spikes at odd hours. This script does the first pass for them — it turns raw log lines into a readable summary with the red flags highlighted.

## What's new in this version (improved 2026-10-26)

Think of the original as a guard who counted knocks on the door. The improved version is a guard who also notices *when the door finally opens after all that knocking* — and who can hand you the report in a spreadsheet-friendly format:

- **Success-after-failures alerts (the big one).** If an IP fails 3+ times for the same username and then suddenly logs in successfully, the report flags it urgently (`[!!!]`). Knocking alone is suspicious; knocking and then getting in can mean a password was guessed. In the new built-in `--demo`, an attacker fails 5 times as `root` and then gets in — and the script catches it.
- **Command-line flags.** `--threshold` sets how many failed attempts put an IP on the watchlist (default 5), `--top` sets how many top IPs/usernames to show, and `--logfile` picks the file — no more editing the script to change a number.
- **`--json` output.** The same summary as structured JSON, so it can feed a spreadsheet, a dashboard, or the next tool in a pipeline instead of only being read by a human.
- **`--demo` mode.** A built-in sample story (the guessed-password case above) runs with no file at all — handy for learning or testing the script on a fresh machine.
- **Friendlier errors and honest counts.** A missing file, a folder passed by mistake, or a bad flag now explains itself instead of crashing, and lines that aren't login lines are counted as "Lines skipped" instead of silently vanishing (comments and blank lines still don't count).

## What the script does

Given an auth log file, it prints a summary report with six sections:

1. **Totals** — how many login attempts, and how many succeeded vs. failed.
2. **Top source IPs** — which computers knocked on the door most often.
3. **Attempts by hour** — a mini bar chart showing *when* the attempts happened. A sudden spike is often the fingerprint of an automated attack.
4. **Most-targeted usernames** — attackers love trying `root`, `admin`, and service accounts like `oracle` or `postgres`. If those top the list, someone's guessing.
5. **Watchlist** — any IP with 5+ failed attempts gets flagged for a human to investigate. The script is careful to frame this as *triage, not proof*: a locked-out coworker with a typo'd password lands on the same list as an attacker. The human decides.
6. **Success-after-failures alerts (new)** — a login that follows 3+ failed attempts from the same IP for the same username, flagged urgently: this is the pattern a guessed password leaves behind.

## How the code works, line by line (simple terms)

- **`import re, sys`** and **`from collections import Counter`** — `re` is Python's pattern-matcher (regular expressions), `sys` reads command-line arguments, and `Counter` is a built-in tally keeper that counts how often each item appears.
- **`FAILED_RE`, `ACCEPTED_RE`, `HOUR_RE`** — the three patterns the script hunts for. A real log line looks like `Failed password for root from 203.0.113.7 ...`. The first pattern captures the username and IP from a failed line, the second from a successful line, and the third grabs the hour (`09` from `09:14:22`). Think of them as cookie cutters: press onto a line, get the useful pieces out.
- **`read_log(path)`** — opens the file and returns its lines. If the file doesn't exist, it prints a friendly hint instead of a cryptic crash.
- **`parse(lines)`** — the engine. It walks the log exactly once (efficient — logs can be huge) and sorts every line into buckets: failed attempts, successful attempts, attempts per hour, and attempts per username. One pass, everything counted.
- **`report(data)`** — the storyteller. Takes the buckets and prints the five sections, including the mini bar chart (`"#" * count` repeats the `#` character — a delightfully simple visualization) and the watchlist.
- **`main()`** — the starting point: pick up the log file (from the command line, or the bundled sample file by default) and run the pipeline: read → parse → report.

## Key terms, translated

- **Auth log** — the server's sign-in book. Every login attempt, recorded.
- **SSH** — the secure way admins connect to a server remotely. Most brute-force attempts target SSH.
- **Brute force** — trying passwords over and over until one works. Loud, but it still works often enough that attackers keep doing it.
- **Triage** — sorting alerts into "probably fine," "needs a look," and "call someone now." What SOC analysts do before anything else.
- **False positive** — when something looks suspicious but is actually harmless (like the coworker with the wrong password). Good tooling minimizes them; good analysts know they're unavoidable.

## How to run it

```bash
python3 auth_log_parser.py sample_auth.log
python3 auth_log_parser.py --demo              # built-in demo, no file needed
python3 auth_log_parser.py --threshold 3 --top 3 sample_auth.log
python3 auth_log_parser.py --json sample_auth.log
```

No libraries to install — everything used comes with Python. Point it at your own log file by passing its path instead.

## What to learn next

- **Regex basics** — the patterns in this script are the tip of the iceberg. Sites like regex101.com let you experiment safely.
- **SIEMs (Security Information and Event Management)** — tools like Splunk and Elastic do this parsing at enterprise scale, with real-time alerts. This script is the "under the hood" version.
- **Baselining** — the real power comes from comparing *today's* summary to *normal* days. A spike is only suspicious if it's unusual.
- **Log forwarding** — servers ship their logs to a central collector (syslog) so attackers can't delete their tracks from the machine they broke into.
