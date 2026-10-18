# Web Access Log Attack Detector — a SOC analyst's first-pass triage

**Day 19 · SOC analysis series · by Askarbek Akhrorov**
Code: `attack_detector.py` (+ `sample_access.log`)

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

It also applies a **behavioral rule**: any IP that racks up 5 or
more error responses (404/500) is probably spraying the site —
signature matching catches *known* attacks; behavior rules catch
noisy *unknown* ones. Real SIEM systems combine both.

The output is a SOC-style triage summary: totals, attack
signatures seen, alerts sorted by severity, 404-spray flags, top
talkers, and suggested next steps.

## How the code works, line by line (simple terms)

- **SIGNATURES list** — a table of attack "fingerprints": a name,
  a severity (HIGH/MEDIUM), and a *regular expression* (a text
  pattern). These are documented, classic attack strings from
  web-security references (OWASP) — matching known patterns is
  exactly how real intrusion-detection rules work.
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
- **parse_lines()** — turns the raw text into a list of small
  dictionaries, one per request; skips lines it can't understand.
- **analyze()** — the detective work. For each request it checks
  every signature against the requested path, checks the
  user-agent for scanners, and counts errors per IP. Returns the
  list of alerts plus summary statistics.
- **report()** — prints the summary: totals, signatures seen,
  alerts from most to least severe, spray flags, top talkers,
  and the SOC "next steps" checklist.
- **main()** — if you pass a filename, it reads that log;
  otherwise it analyzes the built-in sample.

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

## How to run it

```bash
# Built-in sample data (no setup needed):
python3 attack_detector.py

# Your own log file (Apache/Nginx combined format):
python3 attack_detector.py /path/to/access.log
```

Nothing is installed, nothing touches the network, nothing is
blocked or changed — detection only.

## What to learn next

- Try adding your own signature (e.g. `log4shell`'s `${jndi:`)
  and watch the detector catch it — that's how detection
  engineering works.
- Real tools of this family: **Snort/Suricata** (network
  intrusion detection), **WAFs** like ModSecurity (which block,
  not just detect), and **SIEMs** like Wazuh or Splunk.
- Learn one of these attacks deeply — start with SQL injection
  — so you understand *why* the pattern looks the way it does.
  Signatures make sense only when you know the attack.

**Takeaway:** an alert is not a verdict — it's a lead. The tool
narrows 10,000 lines to 19 worth a human's eyes. That ratio is
the whole job of SOC triage.
