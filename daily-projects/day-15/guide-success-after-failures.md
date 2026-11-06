# Detecting Account Takeovers: "Success After Failures"

*Day 15 of my daily security-projects series — built with Python, explained in plain English.*

## What's new in this version (improved 2026-11-04)

Think of the first version as a smoke alarm that only beeps. This version is a smoke alarm that also tells you *which room*, *how fast the smoke spread*, and *whether someone is still trying the door right now*:

- **Severity levels (HIGH / MEDIUM)** — a case is HIGH when the successful login comes from a *different* IP address than the failed attempts. That's like someone fumbling at the keypad, then the door opening from the other side of the building — a much stronger sign the account was taken over. The sample data now includes frank, whose 6 fails come from one address and whose success comes from a new one.
- **"Still guessing" watchlist** — the first version only cared about users who eventually got in. Now it also flags users with many fails and *no* success yet, like eve (8 fails, never in). That's an attack that may still be in progress — the moment to lock the account, not after the fact.
- **`--demo` mode** — the sample story is now built into the script, so it runs with zero setup: `python3 success_after_failures.py --demo`.
- **`--json` output** — results as structured data, ready to feed into another tool or a dashboard.
- **`--timeline USER`** — prints one user's whole login story in plain English, oldest first, so you can walk through exactly what happened.
- **Richer case details** — every flagged case now shows how many minutes the guessing took and the speed (attempts per minute), so you can tell a slow human from a fast script.
- **Clear exit codes** — 0 = clean, 1 = something flagged, 2 = a usage or file problem. That makes the script safe to chain into other tools: a monitoring job can act on the exit code alone.
- **Friendlier errors** — a missing file now points you to `--demo`, bad `--fails`/`--window` values are rejected with a plain message, and malformed log lines are counted and reported instead of silently dropped.

## The big idea

Imagine a security guard watching a keypad door. Someone types wrong codes five, six, seven times in a row — and then the door clicks open. Maybe the employee finally remembered their code. Or maybe someone *guessed* it. That "a lot of tries, then suddenly in" pattern is exactly how many stolen accounts start — and it's one of the first things a real security analyst (a "SOC analyst," the person watching the alarm screens) looks for every day.

## What the script does

`success_after_failures.py` reads a simple login log and flags any user who has **many failed logins followed by a successful login** within a short time window (default: 5+ fails in 15 minutes). It ignores normal stuff — one or two typos before a success is just a person with fat fingers — and raises a flag only on the noisy pattern that deserves a second look.

## How the code works, line by line (in simple terms)

1. **Settings at the top** — `FAIL_THRESHOLD = 5` and `WINDOW_MINUTES = 15` are the script's definition of "suspicious." They're arguments too (`--fails`, `--window`), so you can tune them without touching code.
2. **`parse_line()`** — turns one log line like `2026-10-15T07:41:00 bob FAIL 10.0.0.31` into a tidy record: timestamp, username, result, IP address. Anything malformed gets skipped safely.
3. **`scan()`** — the heart of it:
   - Groups every login event by username.
   - Sorts each user's events in time order.
   - Walks through them and, at *every successful login*, looks backward: "how many fails did this user have in the last 15 minutes?" If it's 5 or more, that's a flagged case.
4. **`main()`** — reads the command-line options, runs the scan, and prints a readable report with the time range, the user's IP, and a reminder of the SOC follow-up: reset the password, check for other sessions from that IP, see what the account touched after getting in.

## Key terms, translated

- **SOC analyst** — the security-team person who watches alerts and investigates suspicious activity.
- **Account takeover** — an attacker gaining control of someone else's account.
- **Brute force / password stuffing** — guessing passwords over and over, often reusing passwords leaked from other sites.
- **False positive** — an alert that *looks* bad but is innocent (like bob typing slowly). Tuning the threshold is how analysts balance catching real attacks vs. crying wolf.

## How to run it

```bash
python3 success_after_failures.py                 # uses auth-sample.log
python3 success_after_failures.py --demo          # built-in sample, no file needed
python3 success_after_failures.py --demo --json   # machine-readable results
python3 success_after_failures.py --demo --timeline bob  # bob's full story
python3 success_after_failures.py --fails 3 --window 10   # stricter tuning
python3 success_after_failures.py --file /path/to/your.log  # your own log
```

Your own log just needs lines like: `2026-10-15T09:00:00 username SUCCESS 10.0.0.1` (lines starting with `#` are ignored).

## What I learned

Try changing the threshold and watch the results change: with `--fails 3`, bob's later login (only 2 fails before it) still isn't flagged — two typos is normal. That tuning step is the actual job. Real analysts spend more time adjusting thresholds than writing detectors, because a noisy alert gets ignored and a quiet one gets missed.

## What to learn next

- Feed it real logs (export from your own laptop's auth log).
- Add alerts by email or webhook when something is flagged.
- Correlate across sources: did the "successful" IP also log into other accounts? That's how a SOC spots one attacker using many stolen passwords.
- Learn what comes after detection: the *incident response* steps — contain, reset, investigate, recover.

*Code: https://github.com/Asqarusa/Phyton/tree/main/daily-projects/day-15*
