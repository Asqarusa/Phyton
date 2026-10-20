# Day 24 — Windows Logon Event Decoder: a plain-English guide

## The big idea (start here)

Imagine an office building. Every time someone enters, the security desk writes
down a note. But a good security desk doesn't just write "someone came in" —
it writes down **which door they used**: the front door with a badge, the
loading dock, the video intercom that lets people in remotely.

Windows does exactly this. Every logon creates a security event, and the event
says **which kind of logon it was** — sitting at the keyboard, connecting over
the network to a shared folder, a Remote Desktop session from across town, or
a background service starting up. That number is called the **Logon Type**, and
reading it is one of the most basic, most useful SOC analyst skills there is.

Why it matters: "Successful logon" means something completely different
depending on the door. A Type 2 (keyboard) logon on a laptop at 9 AM is
Tuesday. A Type 10 (Remote Desktop) logon on a server at 3 AM from an address
you've never seen is an incident. The word "success" is the same; the story
isn't. This tool teaches you to read the story.

## What the script does

You feed it event-log lines — one per line, in a simple format — and it:

1. **Names each event** (4624 = successful logon, 4625 = failed logon,
   4672 = admin rights granted, 4720 = new account created, and more),
   with a plain-English explanation of each.
2. **Names the "door"** — the Logon Type (2 = at the keyboard, 3 = over the
   network, 10 = Remote Desktop, and so on), with what that door means in
   real life.
3. **Flags what's interesting** — night-time RDP, failed-logon bursts,
   cleartext logons, privilege and account-creation events — with a short
   note on why an analyst would look twice.
4. **Prints a triage summary** at the end: counts per event, failed logons
   per user with a burst warning, and a reminder that an alert is a lead,
   not a verdict.

It ships with a sample file (`sample_events.txt`) telling a realistic story:
a normal morning shift, one human typo, then a night-time password-guessing
attack against `administrator` over RDP that succeeds — followed by a new
account being created. All IPs are documentation ranges (RFC 5737), so
nothing is real.

It's 100% offline, read-only, standard-library-only. It parses text you give
it and explains it — it never touches a live system.

## How the code works (line by line, in simple terms)

- **The docstring at the top** — the built-in manual: what it does, the
  building-doors analogy, how to run it.
- **`EVENTS`** — a dictionary (a lookup table) mapping event IDs to
  `(label, plain-English meaning, risk level)`. When the script sees 4624,
  it looks up the entry instead of having a giant if/else chain. Adding a
  new event type later = adding one line.
- **`LOGON_TYPES`** — the same idea for the "door" numbers: each type gets
  a label, a real-life explanation, and a SOC note. Types 2, 3, and 10 are
  the ones you'll see most; 8 (cleartext) is the scary one.
- **`parse_line()`** — turns one line of text into a structured record.
  It splits on `|`, figures out whether the first field is a timestamp or
  an event ID, and fills in defaults (`?`) for anything missing. Lines
  starting with `#` are comments and get skipped — that's how the sample
  file tells its story with annotations.
- **`is_night_hour()`** — checks whether a timestamp falls between 22:00
  and 06:00. Simple, honest, no timezone magic — just enough to flag
  "why is someone remoting in at 3 AM?"
- **`explain()`** — the main worker for one event. It looks up the event
  and the logon type, prints the plain-English version, then applies a
  handful of simple rules to raise flags: failed logons, night-time RDP,
  cleartext logons, privilege/account events. No machine learning, no
  magic — just the same rules a junior analyst learns in week one.
- **`summarize()`** — the triage view: counts every event type, counts
  failed logons per user, and calls out a burst (5+ fails for one user)
  with concrete next steps. This is the "morning briefing" version of the
  data.
- **`run()` / `main()` / `argparse`** — `run()` ties parse → explain →
  summarize together; `main()` reads the command line: `--demo` for the
  built-in story, `--file` for your own file, or a single event line in
  quotes. No arguments prints help with a tip instead of crashing.
- **`DEMO_LINES`** — the built-in sample story, so the tool teaches
  something useful the very first time you run it with zero setup.

## Key terms, translated

| Term | Plain English |
|---|---|
| Event ID (e.g. 4624) | Windows' code number for "what happened" — every logon, logoff, and account change has one |
| 4624 / 4625 | Successful logon / failed logon — the two you'll see most |
| Logon Type | Which "door" was used: 2 = keyboard, 3 = network share, 10 = Remote Desktop, and more |
| 4672 | "Special privileges assigned" — this logon got admin-level rights |
| 4720 / 4732 | A new account was created / someone was added to a powerful group — classic attacker moves |
| RDP (Remote Desktop) | Controlling a computer's screen from across the network — Logon Type 10 |
| Lateral movement | An attacker hopping from one machine to another inside a network — often visible as Type 3 logon floods |
| Triage | Sorting alerts into "routine / interesting / urgent" — what the summary at the end does |
| RFC 5737 | The official list of fake IP ranges reserved for documentation — why the samples can never be real |

## How to run it

```bash
python3 logon_event_decoder.py --demo                  # the built-in story
python3 logon_event_decoder.py --file sample_events.txt
python3 logon_event_decoder.py "4624 | jdoe | 10"      # one event, quick check
```

No installs, no network, no admin rights — any laptop with Python 3 runs it.

## What to learn next

- **Read the real thing (safely).** On a Windows machine you own, open Event
  Viewer → Windows Logs → Security and look for 4624/4625 entries. You'll
  recognize the logon types immediately now.
- **4625 bursts → account lockout.** Day 1's brute-force detector and day
  15's success-after-failures tool are the automated versions of the burst
  check in the summary — same idea, bigger scale.
- **Type 3 floods → lateral movement.** If one machine makes Type 3 logons
  to dozens of others in minutes, that's the classic footprint of an
  attacker (or worm) spreading. Correlate with the IOC matcher from day 17.
- **Learn the "weird" types.** Type 8 (cleartext) shouldn't exist on a
  modern network — if you see it, something old and insecure is running.
  Type 9 (RunAs /netonly) is a favorite of both admins and attackers;
  context is everything.
- **The 4672 + 4720 combo.** Admin rights followed by a new account, at
  night, after failed logons — that's the sample story's ending, and it's
  also a textbook persistence pattern. Recognizing the *sequence* is what
  turns log-reading into detection.

---

*Built as a defensive learning exercise: read-only, offline, educational.
All sample data is synthetic; all IPs are RFC 5737 documentation ranges.*
