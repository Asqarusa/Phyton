# Day 17: Threat-Intelligence Watchlist Checker (IOC Matcher)

## The big idea (the non-tech analogy)

Imagine airport security with a "most wanted" list. Every passenger walks
past, an officer compares faces to the list, and if there's a match, the
passenger gets pulled aside for a closer look. Nobody is arrested on the
spot — a match just means "this needs a human to investigate."

A SOC (Security Operations Center) works exactly like that. Security teams
maintain a **threat-intelligence watchlist** — known-bad IP addresses,
malicious domains, and the fingerprints (hashes) of known malware files.
These clues are called **Indicators of Compromise**, or IOCs. Analysts
constantly compare the traffic they see against the watchlist, and every
match becomes an **alert** that a human investigates.

## What the script does

`ioc_matcher.py` plays the role of the officer with the list. You give it
network events (who talked to whom, which domains were visited, which file
hashes showed up) and it checks each one against a watchlist of 8 sample
IOCs: 3 bad IPs, 3 shady domains, 2 malware file hashes.

Run it with no arguments and it checks 7 built-in sample events:

```
!!! ALERT [CRITICAL] — 2026-10-16T09:16:55 !!!
  matched ip     198.51.100.23 (seen in dst_ip)
           why it matters: known ransomware distribution host
  matched hash   d41d8cd98f00b204e9800998ecf8427e (seen in file_hash)
           why it matters: known trojan dropper (SHA-256-style example fingerprint)
  suggested next steps: isolate the host, capture the full session,
  and check whether any other machines touched the same indicator.
```

One event matched **two** indicators — a bad IP *and* a malware hash —
which is exactly the kind of "piles of evidence" moment that makes an
analyst's pulse quicken. Each alert ends with suggested next steps,
because a real alert is the *start* of an investigation, not the end.

You can also feed it your own event file:

```
python3 ioc_matcher.py --events sample_events.txt --verbose
```

Event files are simple — one event per line, five fields separated by
spaces, `-` for an empty field:

```
timestamp  src_ip  dst_ip  domain  file_hash
```

## How the code works (line by line, in simple terms)

1. **WATCHLIST** — a Python list of dictionaries, one per indicator. Each
   has a `type` (ip, domain, or hash), the `value` to look for, a
   `severity` (MEDIUM, HIGH, CRITICAL), and a plain-English `note` about
   why it's bad. In a real SOC this list comes from threat-intelligence
   feeds; here the values are obviously fake example addresses so the
   demo can never flag anything real.
2. **SAMPLE_EVENTS** — seven pretend log lines, a mix of normal traffic
   (google.com, a company wiki) and malicious ones. This is the "footage"
   the tool analyzes.
3. **parse_event()** — turns one text line into a tidy dictionary with
   named fields (`src_ip`, `dst_ip`, `domain`, `file_hash`). Turning `-`
   into an empty string keeps the matching logic clean.
4. **check_event()** — the heart of the tool. For each indicator it asks:
   is this an IP that appears as the source or destination? A domain that
   matches? A hash that matches? Every match is collected with the field
   where it was found, so the alert can say *where* the bad thing showed
   up.
5. **print_alert()** — prints one SOC-style alert. The alert's severity is
   the worst of its matches (a CRITICAL hash beats a MEDIUM IP), and it
   ends with next steps: isolate the host, capture the session, look for
   the same indicator elsewhere.
6. **main()** — the conductor. Reads the events (built-in samples or your
   file), checks each one, prints alerts, and finishes with a summary
   count and one honest takeaway: an alert is a lead, not a verdict.

## Key terms, translated

- **IOC (Indicator of Compromise)** — a known-bad clue: an IP, domain, or
  file hash tied to an attack.
- **Threat intelligence** — the shared "most wanted list" the security
  community maintains; when one company discovers a malware server, they
  publish its IP so everyone else can watch for it.
- **Triage** — the analyst's first job: sort the flood of alerts into
  "ignore," "watch," and "investigate now."
- **False positive** — an alert on something innocent. Tuning a watchlist
  to minimize these is half the job.
- **Hash** — a file's fingerprint. If the fingerprint matches a known
  malware fingerprint, the file is guilty by association.

## How to run it

```bash
cd ~/workspace/linkedin-content/2026-10-16
python3 ioc_matcher.py                        # built-in sample events
python3 ioc_matcher.py --events sample_events.txt
python3 ioc_matcher.py --events sample_events.txt --verbose   # also show clean events
```

Python 3 only, no extra libraries — everything used is built into Python.

## What to learn next

- Real threat-intel feeds (AlienVault OTX, abuse.ch) publish IOCs by the
  thousand — the next step up is pulling one in automatically and
  re-checking yesterday's logs against *today's* watchlist.
- Alert fatigue is the SOC's biggest enemy: try scoring events instead of
  yes/no matching (one MEDIUM hit = watch, two hits = investigate).
- This is the same "compare against a list" idea behind spam filters,
  fraud detection, and the password breach checker from day-08.

## Safety note

This script is purely defensive and read-only: it matches text against a
local list and changes nothing. The sample indicators use reserved,
non-real documentation addresses (RFC 5737 ranges) and example domains,
so they can never correspond to real systems.
