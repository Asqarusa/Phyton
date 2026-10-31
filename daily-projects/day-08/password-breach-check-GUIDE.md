# Has This Password Been Leaked? — a k-anonymity breach checker

**Script:** `password_breach_check.py` · **Day 8** · SOC analysis series

## What's new in this version (improved 2026-10-28)

Think of it like upgrading a smoke detector: it still does the same job, but
now it also shows you its own wiring, speaks more clearly, and works even
when the internet is down for a demo.

- **Offline demo mode (`--demo`)**: runs with no internet and never asks for a
  password. It walks through the 5-character k-anonymity split step by step
  and shows what each verdict tier means — perfect for a classroom or a
  quick "how does this work?" demo.
- **Clearer verdicts**: instead of three broad buckets, there are now four —
  SAFE-ish (0 breaches), RISKY (1–9), BREACHED (10–999), and HEAVILY BREACHED
  (1,000+). "Seen twice" no longer sounds as scary as "seen 2 million times,"
  because it isn't.
- **Proof of privacy (`--verbose`)**: the script now prints exactly what left
  your machine (just the 5-character prefix) and how many candidate
  fingerprints came back — so the privacy claim is visible, not just promised.
- **Machine-readable output (`--json`)**: SOC tools and scripts can now read
  the verdict, breach count, and prefix sent as JSON, without ever seeing
  the password or the full fingerprint.
- **Friendlier errors and exit codes**: a timeout, a rate limit (HTTP 429),
  or a network failure each gets a plain-English explanation and a next step
  instead of a raw crash. Exit codes: 0 = checked, 1 = API/network problem,
  2 = bad input (empty password or bad timeout).
- **Input validation**: empty passwords are rejected with a clear message
  instead of being hashed and checked pointlessly.

Try it: `python3 password_breach_check.py --demo` — no password needed.

## The big idea (before any code)

Imagine you want to know if your phone number is on a scammer's list, but you
don't want to hand your number to a stranger to ask. So you send just the first
3 digits, they send back *everyone's* number starting with those digits, and
you check privately whether yours is in the pile. They never learned your number.

That's **k-anonymity** — asking a question about yourself without revealing
which answer is yours. This script does exactly that with passwords:

1. Your laptop scrambles the password into a SHA-1 fingerprint (a one-way code
   that can't be turned back into the password).
2. It sends **only the first 5 characters** of that fingerprint to the public
   HaveIBeenPwned database (free, run by security researcher Troy Hunt).
3. The database returns **hundreds of matching fingerprints** — so many that the
   server cannot tell which one belongs to you.
4. Your laptop compares them **locally** and tells you the breach count.

Your full password never leaves your machine. Your full fingerprint never
leaves your machine. Only 5 characters do.

## Why this matters in a SOC

Security Operations Center (SOC) analysts constantly deal with passwords. The
#1 real-world password attack isn't fancy hacking — it's **credential
stuffing**: attackers take passwords leaked from Breach A and try them on
Bank B, Email C, and every other site. If your password appears in *any*
breach, it's burned everywhere you reused it.

This script is the defensive version of that check: same data, used to
*protect* people instead of attacking them.

## How the code works (simple terms)

| Line(s) | What it does |
|---|---|
| `import hashlib` | Loads Python's built-in fingerprint-making toolbox. |
| `import getpass` | Lets the script read your password without showing it on screen. |
| `import urllib.request` | Python's built-in way to fetch web pages — no installs needed. |
| `API_URL = "https://api.pwnedpasswords.com/range/"` | The public breach database's address. |
| `fetch_suffixes(prefix)` | Sends the 5-char prefix, gets back a list of `SUFFIX:count` lines, and turns them into a lookup dictionary. |
| `hashlib.sha1(password.encode()).hexdigest().upper()` | Scrambles the password into its fingerprint. |
| `prefix, suffix = sha1[:5], sha1[5:]` | Splits the fingerprint: the prefix travels, the rest stays home. |
| `fetch_suffixes(prefix).get(suffix, 0)` | Checks locally: "is my suffix in the returned pile?" Default 0 = not found. |
| `verdict(count)` | Translates the number into plain advice: SAFE-ish, RISKY, or BREACHED. |
| `main()` | Reads the password, runs the check, prints the result. If the network fails, it says so instead of guessing. |

## Key terms, translated

- **Breach database** — a collection of passwords exposed in real past hacks.
- **SHA-1 / hashing** — a one-way scrambler: password → fingerprint. Can't go backwards.
- **k-anonymity** — hiding your question inside a crowd of similar questions.
- **Credential stuffing** — attackers replaying leaked passwords against other sites.
- **SOC** — the team that watches for and responds to cyberattacks, 24/7.

## How to run it

```bash
python3 password_breach_check.py --demo
# offline demo — no password needed, nothing sent anywhere

python3 password_breach_check.py
# enter a password when asked (it won't show on screen)
# ... or pipe one in:
echo "password123" | python3 password_breach_check.py

echo "password123" | python3 password_breach_check.py --verbose --json
# machine-readable result + the privacy check (prefix sent, candidates returned)
```

Try `password123` first — the result is eye-opening. Then try something long
and unique.

## What to learn next

- **Why SHA-1 is just fine here** (hash *leaks* are different from password
  *storage*, where you'd want bcrypt/Argon2 — a good rabbit hole).
- **Rate limiting**: the API is free but throttled; real SOC tools cache results.
- **Password managers**: the real fix for humans — unique random passwords
  everywhere, so one breach can't cascade.
- **MFA (multi-factor authentication)**: the safety net when a password does leak.

## Safety note

This tool only *reads* from a public database. It sends nothing sensitive. Never
paste real, in-use passwords into learning tools or share them anywhere —
check candidates and retired passwords, not live ones.
