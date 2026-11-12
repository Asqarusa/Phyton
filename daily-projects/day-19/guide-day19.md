# Web Access Log Attack Detector — a SOC analyst's first-pass triage

**Day 19 · SOC analysis series · by Askarbek Akhrorov**
Code: `attack_detector.py` (+ `sample_access.log`, `sample_new_attacks.log`)

## What's new in this version (2026-11-12)

The guard got a better notebook and a memory. The analogy still
holds — a shop's security camera log, reviewed by the night-shift
guard — but now the guard can do six new things:

1. **Two new attack fingerprints.** The tool now also catches
   **Log4Shell** probes (`${jndi:ldap://...}` — a booby-trapped
   string that tries to make a Java app fetch attacker code) and
   **SSRF / cloud-metadata** probes (requests for
   `169.254.169.254`, the special address where cloud servers keep
   their credentials). Log4Shell was the "try adding it yourself"
   exercise in the old guide — now it's built in.
2. **A real command line.** No more editing the script to change
   behavior: `--file`, `--demo`, `--json`, `--min-severity HIGH`
   (hide the MEDIUM noise), `--ip 203.0.113.90` (investigate one
   address), and `--spray-threshold` (decide how many errors make
   a spray). Try `python3 attack_detector.py --help`.
3. **A per-IP summary table.** Instead of one long alert list, you
   now get one line per suspicious address: how many alerts, its
   worst severity, its favorite attack, and whether it's spraying.
   That's the line you'd paste into a ticket.
4. **Baselines: --save and --compare.** Save today's attacker list
   with `--save baseline.json`, run it again tomorrow with
   `--compare baseline.json`, and the tool tells you who is NEW,
   who is GONE, and whose alert count CHANGED. Real SOC teams
   watch for *change*, not just for badness.
5. **Exit codes for automation.** 0 = clean log, 1 = alerts found,
   2 = something went wrong (missing file, bad flag). That means
   the tool can now run inside a script or a cron job and the
   script can react to the result.
6. **Friendlier errors, honest counting.** A missing file now says
   so plainly instead of crashing, and lines that don't look like
   log lines are *counted and reported* ("Unparseable lines: 1")
   instead of silently vanishing — a mangled log should never
   look like a clean log.

New demo file: `sample_new_attacks.log` shows the two new
signatures in action (plus one deliberately broken line, so you
can see the unparseable-line counter work).

## The big idea (analogy first)

Think of a web server as a shop, and its access log as the security
camera's logbook: one line per visitor, noting when they came, what
they looked at, and what they asked for. This tool is the night-shift
guard who rewinds that footage and circles every frame where someone
tested the door handles, checked the windows, or spray-painted
graffiti — then hands the morning manager a tidy one-page summary.

A real SOC (Security Operations Center) does exactly this at huge
scale: machines watch the logs first, humans investigate the hits.

## What the script does

It reads web server access log lines (the standard Apache/Nginx
"combined" format) and flags:

1. **SQL injection probes** — like `?id=1' OR '1'='1` or
   `UNION SELECT 1,2,3--`. These are attempts to trick the
   database behind a website into answering questions it shouldn't.
2. **Path traversal attempts** — like `/../../etc/passwd`.
   Trying to climb *out* of the website's folder into the
   server's private files.
3. **XSS / script injection** — like `<script>alert(1)</script>`
   in a search box. Trying to plant code that runs in *other
   visitors'* browsers.
4. **Remote file include / command execution probes** — like
   `; cat /etc/passwd`. Trying to make the server run commands.
5. **Sensitive file / directory probing** — like `/.git/config`,
   `/.env`, `/wp-login.php`. Looking for accidentally published
   secrets and admin pages.
6. **Known scanner user-agents** — tools like `nikto` and `sqlmap`
   announce themselves in the "browser name" field. That's like a
   burglar arriving in a van with "BURGLAR" painted on it — scanners
   spray hundreds of requests looking for holes.
7. **Log4Shell probes (NEW)** — `${jndi:ldap://...}` in a request.
   A Java logging library once treated that string as an order to
   download and run code from the attacker's server. One line in a
   search box could take over a server — that's why it was one of
   the most-scanned patterns of recent years.
8. **SSRF / cloud-metadata probes (NEW)** — requests for
   `169.254.169.254` or `metadata.google.internal`. That address
   is where cloud servers keep their own credentials; if the web
   server can be tricked into fetching it, the attacker steals
   those credentials. SSRF = "server-side request forgery": the
   attacker makes *your* server make the request for them.

It also applies a **behavioral rule**: any IP that racks up 5 or
more error responses (404/500) is probably spraying the site —
signature matching catches *known* attacks; behavior rules catch
noisy *unknown* ones. Real SIEM systems combine both. The threshold
is now tunable with `--spray-threshold`.

The output is a SOC-style triage summary: totals, attack
signatures seen, alerts sorted by severity, 404-spray flags, a
per-IP summary table, top talkers, and suggested next steps.
With `--json` the same report comes out as JSON, ready to pipe
into another tool.

## How the code works, line by line (simple terms)

- **SIGNATURES list** — a table of attack "fingerprints": a name,
  a severity (HIGH/MEDIUM), and a *regular expression* (a text
  pattern). These are documented, classic attack strings from
  web-security references (OWASP) — matching known patterns is
  exactly how real intrusion-detection rules work. Two new rows:
  Log4Shell and the cloud-metadata probe.
- **SCANNER_AGENTS list** — names of well-known scanning tools.
  If one appears in the visitor's user-agent field, flag it.
- **LOG_LINE** — one regular expression that takes a raw log line
  apart into pieces: the visitor's IP, the time, the request, the
  status code (200 = ok, 404 = not found, 500 = server error),
  and the user-agent. Note it allows *spaces* inside the path —
  real attack requests often contain them.
- **SAMPLE_LOG** — built-in example data. Every IP uses
  documentation-only ranges (203.0.113.x, 198.51.100.x, 192.0.2.x
  — reserved by RFC 5737), so the sample can never point at a
  real computer.
- **NEW_ATTACKS_LOG** — the demo add-on: one Log4Shell probe, one
  cloud-metadata probe, one clean request. Shown by `--demo`.
- **parse_lines()** — turns the raw text into a list of small
  dictionaries, one per request. Now it also returns how many
  lines it couldn't understand, so bad data is visible.
- **analyze()** — the detective work. For each request it checks
  every signature against the requested path, checks the
  user-agent for scanners, and counts errors per IP. Returns the
  list of alerts plus summary statistics — now including a
  per-IP summary (alerts, worst severity, top signature, spray
  flag) for every suspicious address.
- **build_baseline() / compare_baseline()** — the memory. The
  first shrinks a run down to `{IP: alert count}` for saving;
  the second diffs a saved baseline against a new run and labels
  each address NEW, GONE, or CHANGED.
- **filter_stats()** — keeps the report honest when you filter:
  totals still describe the whole log, but the alert counts and
  the per-IP table describe only what `--min-severity` or `--ip`
  asked to see.
- **report()** — prints the summary: totals, signatures seen,
  alerts from most to least severe, spray flags, the per-IP
  summary table, baseline changes if any, top talkers, and the
  SOC "next steps" checklist.
- **to_json()** — the same report as JSON, for piping into a
  SIEM or another script.
- **parse_args() / main()** — the new command line: reads the
  flags, loads the log (or the built-in sample), runs the
  analysis, prints text or JSON, saves or compares a baseline,
  and exits 0 (clean), 1 (alerts), or 2 (error).

## Key terms translated

| Term | Plain English |
|---|---|
| Access log | The web server's guest book: who asked for what, when |
| Signature | A known-bad pattern — like a fingerprint on file |
| SQL injection | Tricking a website's database with crafted input |
| Path traversal | Using `../` to escape the website folder |
| XSS (cross-site scripting) | Planting code that runs in other people's browsers |
| User-agent | The "name tag" a browser (or scanner) sends with each request |
| 404 spray | Hammering a site with requests for random pages — a scanner's habit |
| SIEM | The big log-watching software real SOC teams use |
| Log4Shell | A Java logging bug where `${jndi:...}` made servers run attacker code |
| SSRF | Tricking *your* server into fetching a URL for the attacker |
| Cloud metadata | The special address where a cloud server keeps its own credentials |
| Baseline | Yesterday's attacker list, saved so you can spot what's new today |

## How to run it

```bash
# Built-in sample data (no setup needed):
python3 attack_detector.py

# Demo: sample plus the two new attack types:
python3 attack_detector.py --demo

# Your own log file (Apache/Nginx combined format):
python3 attack_detector.py /path/to/access.log

# Only the serious stuff:
python3 attack_detector.py --min-severity HIGH access.log

# Investigate one address:
python3 attack_detector.py --ip 203.0.113.90 access.log

# Machine-readable output for another tool:
python3 attack_detector.py --json access.log

# Save today's attackers, compare tomorrow:
python3 attack_detector.py --save baseline.json access.log
python3 attack_detector.py --compare baseline.json access.log
```

Nothing is installed, nothing touches the network, nothing is
blocked or changed — detection only.

## What to learn next

- Try adding your own signature (e.g. a scan for `/.aws/credentials`
  or `${7*7}` template-injection probes) and watch the detector
  catch it — that's how detection engineering works.
- Real tools of this family: **Snort/Suricata** (network
  intrusion detection), **WAFs** like ModSecurity (which block,
  not just detect), and **SIEMs** like Wazuh or Splunk.
- Learn one of these attacks deeply — start with SQL injection
  — so you understand *why* the pattern looks the way it does.
  Signatures make sense only when you know the attack.

**Takeaway:** an alert is not a verdict — it's a lead. The tool
narrows 10,000 lines to 19 worth a human's eyes. That ratio is
the whole job of SOC triage. And with baselines, the second
question gets answered too: *is today worse than yesterday?*
