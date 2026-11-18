# Day 23 — Suspicious Domain Detector (DGA Spotter)

A small Python tool that reads a list of domain names and flags the ones
that *look* machine-generated — the way a SOC analyst triages DNS logs.

## The big idea (non-tech analogy)

Imagine you're a bouncer with a guest list. Normal guests have names like
"Maria Lopez" — human, memorable, pronounceable. Then someone shows up
as "Xkqz Ptmbw Vdr1234." You don't know for sure it's a fake ID, but the
*randomness* of the name is a reason to look closer.

Domain names work the same way. `google.com` and `github.com` are built
for humans to remember. But a lot of malware does the opposite: it uses a
**Domain Generation Algorithm (DGA)** to invent thousands of
random-looking domains every day (`xkqzptmwbvdr1234.top`,
`k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz`) and quietly phones home to whichever
one the attacker bothered to register. If one computer on your network is
suddenly asking for dozens of gibberish domains, that's a classic sign of
an infected host.

This script is the "smell test" an analyst runs first: it scores each
domain 0–100 on how machine-generated it looks, explains every point it
gave, and sorts results into CLEAN / SUSPICIOUS / LIKELY DGA.

## What's new in this version (2026-11-17)

- **Two new checks (now 9 total):** a *no-vowel* check (a long name with
  zero vowels, like `qwrtypsdfghjk`, is not a human word) and a
  *punycode* check (`xn--` labels are the trick behind lookalike
  domains such as `xn--g00gle-9ya.com`).
- **A real command line:** `--help` explains every flag; `--file` reads a
  list, `--json` prints machine-readable results, `--min-score` and
  `--top` filter the output, `--quiet` shows only flagged domains.
  (Typing a filename directly still works, exactly as before.)
- **Honest INVALID verdicts:** typos and junk (`not a domain!!!`,
  `bad_host.com`, `a..b.com`) are now reported INVALID with a
  plain-English reason instead of getting a misleading score.
- **Whitelist:** `--whitelist sample_whitelist.txt` marks your known-good
  domains CLEAN so they never raise an alert or pollute the summary.
- **Smarter summary:** a "worst offenders" top 3, plus a *possible DGA
  family* warning when 3+ flagged domains share one TLD — in real life
  that pattern means one infected host asking for many generated names.
- **Exit codes for scripts:** 0 = all clean, 1 = something flagged,
  2 = usage or file error — so you can chain it into other tools.
- **Two new sample files:** `sample_dga_family.txt` (10 names from one
  fake DGA family — try `--file sample_dga_family.txt` and watch the
  family warning fire) and `sample_whitelist.txt`.
- **Two new demo domains:** a no-vowel name and a punycode lookalike.
  The demo now checks 13 domains: 6 CLEAN / 6 SUSPICIOUS / 1 LIKELY DGA.

## What the script does

1. Takes domains from a file (one per line, `--file` or just the
   filename), from `--demo` built-in samples, or straight from the
   command line.
2. Runs 9 simple checks on each domain and adds up a score:
   - **Length** — DGA names tend to be long (more characters = more randomness).
   - **Entropy** — a math measure of randomness; human words score ~2–3.5,
     gibberish pushes past 4.
   - **Digit ratio** — humans rarely cram digits into names; DGAs do.
   - **Hyphens** — one or two are normal; a pile is a DGA/phishing habit.
   - **Subdomain depth** — `a.b.c.d.tracker-data.click` is weirder than `example.com`.
   - **Risky TLD** — cheap, lightly-policed endings (`.xyz`, `.top`, `.buzz`)
     show up disproportionately in abuse.
   - **Consonant pile-ups** — real words mix vowels and consonants;
     `xkqzpt` is not a human word.
   - **No vowels (new)** — a name with 8+ letters and (almost) no vowels
     is not pronounceable, so it is not human-made.
   - **Punycode / lookalike (new)** — `xn--` labels are how attackers
     build domains that *look* like a trusted brand.
3. Prints a verdict per domain (CLEAN / SUSPICIOUS / LIKELY DGA /
   INVALID) with the exact reasons, a summary count, the worst
   offenders, a DGA-family hint when several flagged domains share a
   TLD, and SOC next steps. `--json` gives the same results as JSON,
   and the exit code tells scripts whether anything was flagged.

Everything is **offline and read-only** — the script only analyzes the
text you give it. It never queries DNS and never visits any site.

## How the code works (line by line, in simple terms)

- **`shannon_entropy(text)`** — counts how often each character appears,
  then converts that into "bits of surprise per character." A string of
  all `a`s scores ~0 (zero surprise); a jumble of unique characters
  scores 4+. This is the same math behind data compression.
- **`longest_consonant_run(text)`** — walks the name one letter at a
  time, tracking the longest streak of consonants. `google` tops out at
  2; `xkqzptmwbvdr` hits 12.
- **`validate_domain(domain)`** — new in this version: checks the shape
  of the input first (allowed characters, label lengths, at least one
  dot, letters-only TLD) and returns a plain-English problem, so junk
  input gets an INVALID verdict instead of a fake score.
- **`score_domain(domain)`** — the heart of the tool. It validates the
  domain, strips the TLD off, runs the 9 checks above, and adds points
  for each suspicious trait. The `reasons` list records *why* each
  point was given, so the verdict is always explainable. Scores ≥ 60 →
  LIKELY DGA; ≥ 35 → SUSPICIOUS; otherwise CLEAN.
- **`load_lines(path)`** — new in this version: reads a one-domain-per-line
  file (skipping blanks and `#` comments) and exits with a friendly
  error if the file is missing or unreadable.
- **`parse_args(argv)`** — new in this version: the argparse command line
  (`--demo`, `--file`, `--whitelist`, `--json`, `--min-score`, `--top`,
  `--quiet`) with plain-English `--help` text.
- **`main()`** — prints a results table, counts each verdict, lists the
  worst offenders, warns when several flagged domains share a TLD
  (possible DGA family), then lists the 4 SOC next steps (check DNS
  logs, look for one host asking for many flagged domains, confirm
  before blocking, track repeat offenders). Returns exit code 0 (all
  clean), 1 (something flagged) or 2 (usage/file error).

## Key terms, translated

| Term | Plain English |
|---|---|
| **DGA (Domain Generation Algorithm)** | Malware trick: the infected computer and the attacker both generate the same thousands of random domain names per day, so defenders can't block just one. |
| **Entropy** | How random a string looks, measured in bits. Higher = more random. |
| **C2 (Command & Control)** | The attacker's server that infected computers phone home to for instructions. |
| **TLD (Top-Level Domain)** | The ending: `.com`, `.org`, `.xyz`. Some cheap ones are abused more. |
| **DGA family** | Many domains from the same generator (same pattern, same TLD) — one infected host usually queries a whole family, not just one name. |
| **Whitelist** | A list of domains you already trust; the tool skips scoring them so they never cry wolf. |
| **Punycode** | A way to write non-English letters in a domain (`xn--...`); attackers abuse it to build lookalikes of trusted brands. |

## How to run it

```bash
python3 dga_domain_detector.py --demo
python3 dga_domain_detector.py --file sample_domains.txt
python3 dga_domain_detector.py sample_domains.txt          # same thing, shorter
python3 dga_domain_detector.py google.com k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz
python3 dga_domain_detector.py --file sample_dga_family.txt   # watch the family warning
python3 dga_domain_detector.py --file sample_domains.txt --whitelist sample_whitelist.txt
python3 dga_domain_detector.py --demo --json                # machine-readable output
python3 dga_domain_detector.py --demo --min-score 60        # only the worst ones
```

Sample output:

```
k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz           73      LIKELY DGA
    -> very long name (27 chars): +20
    -> very high entropy (4.38): +25
    -> many digits (44%): +8
    -> abuse-prone TLD (.xyz): +10
    -> no vowels in 15 letters: +10

Summary: CLEAN: 6, SUSPICIOUS: 6, LIKELY DGA: 1, INVALID: 0

Worst offenders:
   73  k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz (LIKELY DGA)
   52  xkqzptmwbvdr1234.top (SUSPICIOUS)
   52  login-secure-verify-account-8891.info (SUSPICIOUS)

[!] 3 flagged domains share .xyz — possible DGA family generating names on one TLD. Check which host queried them and when.
```

## What to learn next

- Real SOC teams pair this with actual DNS logs: *which computer* asked
  for the bad domain matters more than the domain itself.
- Professionals add more signals: domain age (registered yesterday?),
  passive DNS history, and threat-intel blocklists.
- The same entropy math shows up in password-strength meters (see day-11)
  and in spotting encoded payloads (Base64 blobs in logs).

## The one-line takeaway

Randomness is a fingerprint: legitimate names are built for human memory,
so when a domain *looks* like static, treat it as a lead worth
investigating — but always confirm before you block, because a score is a
lead, not proof.
