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

## What the script does

1. Takes domains from a file (one per line), from `--demo` built-in
   samples, or straight from the command line.
2. Runs 7 simple checks on each domain and adds up a score:
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
3. Prints a verdict per domain (CLEAN / SUSPICIOUS / LIKELY DGA) with the
   exact reasons, a summary count, and SOC next steps.

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
- **`score_domain(domain)`** — the heart of the tool. It strips the TLD
  off, runs the 7 checks above, and adds points for each suspicious
  trait. The `reasons` list records *why* each point was given, so the
  verdict is always explainable. Scores ≥ 60 → LIKELY DGA; ≥ 35 →
  SUSPICIOUS; otherwise CLEAN.
- **`load_domains(args)`** — figures out the input: `--demo` returns the
  built-in mixed list; a filename reads one-domain-per-line (skipping `#`
  comments); anything else is treated as domains typed on the command line.
- **`main()`** — prints a results table, counts each verdict, then lists
  the 4 SOC next steps (check DNS logs, look for one host asking for many
  flagged domains, confirm before blocking, track repeat offenders).

## Key terms, translated

| Term | Plain English |
|---|---|
| **DGA (Domain Generation Algorithm)** | Malware trick: the infected computer and the attacker both generate the same thousands of random domain names per day, so defenders can't block just one. |
| **Entropy** | How random a string looks, measured in bits. Higher = more random. |
| **C2 (Command & Control)** | The attacker's server that infected computers phone home to for instructions. |
| **TLD (Top-Level Domain)** | The ending: `.com`, `.org`, `.xyz`. Some cheap ones are abused more. |
| **Subdomain** | The part before the main name: `mail` in `mail.google.com`. Deep stacks of them look odd. |

## How to run it

```bash
python3 dga_domain_detector.py --demo
python3 dga_domain_detector.py sample_domains.txt
python3 dga_domain_detector.py google.com k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz
```

Sample output:

```
k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz           63      LIKELY DGA
    -> very long name (27 chars): +20
    -> very high entropy (4.38): +25
    -> many digits (44%): +8
    -> abuse-prone TLD (.xyz): +10
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
