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

## What's new in this version (2026-11-08 improvement)

The airport-security analogy still holds — but the officers got better
training. Six upgrades:

1. **Whole bad neighborhoods, not just single faces.** The watchlist can
   now hold a network block like `192.0.2.0/24` — one line that covers
   256 addresses. Before, every bad IP had to be listed one by one; now
   a known-bad network is caught no matter which address inside it
   shows up. The demo proves it: `192.0.2.99` trips the alert even
   though only `192.0.2.0/24` is on the list.
2. **Subdomains no longer slip past.** Attackers hide behind subdomains
   (`mail.invoice-verify-2026.example` instead of the exact bad domain).
   The matcher now catches those too — if any part of the domain ends
   with a watchlisted domain, it's a hit.
3. **Bring your own watchlist.** `--watchlist your_list.txt` loads
   indicators from a plain text file (one per line: type, value,
   severity, note). A sample file, `sample_watchlist.txt`, is included.
   Bad lines don't crash the script — they're reported with their line
   number and skipped, so one typo can't sink the whole run.
4. **A score on every alert.** Each alert now shows a points total
   (MEDIUM = 1, HIGH = 2, CRITICAL = 3) and a plain label: WATCH or
   INVESTIGATE NOW. The old version only said yes/no; now two clues
   piling up on one event visibly outrank a single clue — exactly the
   scoring idea the old "What to learn next" section suggested.
5. **Focus when it's busy.** `--min-severity HIGH` hides everything
   below HIGH, so an analyst drowning in alerts can look at the worst
   ones first. `--json` prints the same results as structured data for
   piping into other tools.
6. **A summary that points somewhere.** The run now ends with the
   most-matched indicator and the noisiest internal host — in the demo,
   `192.168.1.10` tripped 3 of the 5 alerts, so that's where an
   investigation starts. Malformed event lines are counted and reported
   instead of silently dropped, and the script exits with an honest
   code: 0 = clean, 1 = alerts found, 2 = input problem.

## What the script does

`ioc_matcher.py` plays the role of the officer with the list. You give it
network events (who talked to whom, which domains were visited, which file
hashes showed up) and it checks each one against a watchlist of 9 sample
IOCs: 4 bad IPs (including one whole network block), 3 shady domains,
2 malware file hashes.

Run it with no arguments and it checks 9 built-in sample events:

```
!!! ALERT [CRITICAL] — 2026-10-16T09:16:55 !!!
  score: 5 point(s) — INVESTIGATE NOW
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
   demo can never flag anything real. An ip value may also be a CIDR
   block like `192.0.2.0/24`, which covers a whole range at once.
2. **SAMPLE_EVENTS** — nine pretend log lines, a mix of normal traffic
   (google.com, a company wiki) and malicious ones. This is the "footage"
   the tool analyzes. Two lines show off the new matching: a subdomain
   of a bad domain, and an address inside a bad network block.
3. **load_watchlist()** — reads a watchlist file you supply with
   `--watchlist`. Each line is `type value severity note...`; bad lines
   (unknown type, bad IP, non-hex hash) are collected as friendly
   warnings with line numbers instead of crashing the run.
4. **parse_event()** — turns one text line into a tidy dictionary with
   named fields (`src_ip`, `dst_ip`, `domain`, `file_hash`). Turning `-`
   into an empty string keeps the matching logic clean. Lines with the
   wrong number of fields are counted as skipped and reported at the end.
5. **check_event()** — the heart of the tool. For each indicator it asks:
   is this an IP that appears as the source or destination — or sits
   inside a watchlisted network block? A domain that matches — or is a
   subdomain of a watchlisted one? A hash that matches? Every match is
   collected with the field where it was found, so the alert can say
   *where* the bad thing showed up.
6. **score_hits() / triage_label()** — add up severity points and turn
   the total into a plain label: WATCH, or INVESTIGATE NOW when the
   worst hit is CRITICAL or the score reaches 3.
7. **print_alert()** — prints one SOC-style alert. The alert's severity is
   the worst of its matches (a CRITICAL hash beats a MEDIUM IP), and it
   ends with next steps: isolate the host, capture the session, look for
   the same indicator elsewhere.
8. **build_summary() / print_summary()** — roll the run up: alerts by
   severity, the most-matched indicator, and the internal host with the
   most alerts, so the analyst knows where to start.
9. **main()** — the conductor. Reads the events (built-in samples or your
   file) and the watchlist (built-in or your file), checks each event,
   prints alerts (or JSON with `--json`), and finishes with a summary
   count and one honest takeaway: an alert is a lead, not a verdict. It
   exits 0 when nothing matched, 1 when alerts were found, and 2 when
   an input file couldn't be read — so other scripts can react to the
   result automatically.

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
python3 ioc_matcher.py --watchlist sample_watchlist.txt       # your own watchlist
python3 ioc_matcher.py --min-severity HIGH    # only HIGH and CRITICAL alerts
python3 ioc_matcher.py --json                 # machine-readable output
```

Python 3 only, no extra libraries — everything used is built into Python.

Exit codes: 0 means no alerts, 1 means alerts were found, 2 means an
input file couldn't be read or a flag was wrong. That lets other scripts
(or a nightly cron job) react automatically — for example, only emailing
an analyst when the exit code is 1.

## What to learn next

- Real threat-intel feeds (AlienVault OTX, abuse.ch) publish IOCs by the
  thousand — the next step up is pulling one in automatically and
  re-checking yesterday's logs against *today's* watchlist. The
  `--watchlist` flag is the first step toward that: any feed that can
  print `type value severity note` lines can now feed this tool.
- Alert fatigue is the SOC's biggest enemy: this version scores events
  instead of yes/no matching (one MEDIUM hit = watch, two hits or a
  CRITICAL = investigate). The next step is tuning: which scores
  deserve a page at 3 AM, and which can wait until morning?
- This is the same "compare against a list" idea behind spam filters,
  fraud detection, and the password breach checker from day-08.

## Safety note

This script is purely defensive and read-only: it matches text against a
local list and changes nothing. The sample indicators use reserved,
non-real documentation addresses (RFC 5737 ranges) and example domains,
so they can never correspond to real systems.
