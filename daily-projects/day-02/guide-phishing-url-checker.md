# Phishing URL Checker — Plain-English Guide (Improved)

## 🆕 What's new in this version

This is an upgraded version of the original checker. The old version scored 10 red flags; this one scores **14** — and the guide's own "learn next" section asked for the first one. Ask and you shall receive.

- **Typosquat detection** — remember `paypa1.com` vs `paypal.com`? The script now does the math (a classic edit-distance algorithm called Levenshtein) and flags any domain piece that's *one keystroke away* from a real brand. A tired eye reads "micros0ft" as Microsoft; the math knows better. This is the feature the original guide listed under "what to learn next" — now it's built in.
- **Disguised IP addresses** — the old version caught plain IPs like `192.168.1.100`. Attackers also write IPs in hex (`0xC0.0xA8.0x1.0x1`), octal, or one giant number to dodge exactly that check. This version catches all of them.
- **Lure-word detection** — `verify`, `urgent`, `suspended`, `prize`… attackers bait victims with words that trigger fear or greed. The script now spots them in the URL.
- **Non-standard ports** — legit sites live on ports 80/443. A sketchy link on `:8443` gets a bonus point.
- **Points shown per flag** — every red flag now shows exactly how many points it added (`+3`), so the score is fully transparent. Just like a real analyst documents their reasoning.
- **Batch summary ("analyst dashboard")** — at the end of a run you get verdict counts *and* the most common red flags across the whole batch, so patterns jump out.
- **`--json` mode** — `python3 phishing_url_checker.py --json my_urls.txt` prints machine-readable JSON, ready to feed into a spreadsheet or a bigger security pipeline.
- **Friendlier errors** — garbage input like `not a url` gets an "INVALID — check the URL" verdict instead of a confusing score; missing files get a clear error instead of a traceback.

## The big idea (non-tech analogy first)

Imagine you get a letter from your "bank" asking you to confirm your account.
You don't just trust the envelope — you check the return address, the
letterhead, the spelling. A phishing URL checker does the same thing for
links: it reads the "envelope" of a web link and looks for signs the return
address is fake.

In a real Security Operations Center (SOC), analysts get suspicious links
reported by users all day. Nobody has time to investigate every link deeply,
so the first pass is always triage: *does this link smell wrong?* This
script automates that first pass.

**The golden rule of link safety: never click a suspicious link to find out
where it goes.** This script never opens any URL — it only analyzes the text
of the link itself. That's how professionals investigate links safely.

## What the script does

You give it a list of URLs (or just one). For each URL it checks 14 common
phishing red flags (10 in the original version, 4 new here), adds up a risk score, and gives a verdict:

- **LOW RISK** (score 0–1) — nothing suspicious found
- **SUSPICIOUS** (score 2–4) — worth a closer look
- **HIGH RISK** (score 5+) — treat as a likely phishing link

Each verdict comes with a list of the exact red flags found, so you can see
*why* the script is worried — just like a real analyst documents their
reasoning.

## The 10 red flags (and why they matter)

1. **No HTTPS** — `http://` instead of `https://`. Traffic isn't encrypted.
   Alone this proves nothing (some legit sites are sloppy), but combined
   with other flags it's a bad sign.
2. **Raw IP address as the host** — `http://192.168.1.100/login`. Legit
   companies use domain names; attackers use IPs because domains cost money
   and leave a paper trail.
3. **Punycode (`xn--`)** — a trick that makes a fake domain *look* identical
   to a real one using characters from other alphabets.
4. **The "@" trick** — in `https://paypal.com@evil.com`, the browser treats
   everything before `@` as a throwaway username. The *real* site is
   `evil.com`.
5. **Suspicious top-level domains** — `.xyz`, `.top`, `.club`, `.tk` and
   friends are cheap and abused heavily by scammers.
6. **Brand imitation** — contains "paypal" or "apple" but isn't the brand's
   real domain. `paypal-login.xyz` is not PayPal.
7. **URL shorteners** — `bit.ly/...` hides the real destination. Not proof
   of evil, but worth expanding before trusting.
8. **Many hyphens** — real companies rarely register
   `secure-bankofamerica-account-verify.tk`. Attackers do, because the real
   names are taken.
9. **Very long URLs** — junk padding pushes the real host out of view on a
   small phone screen.
10. **Excessive subdomains** — `login.apple.id.account.verify.evil.club`:
    the real domain is the *last two parts*. Everything to the left is
    decoration.

## How the code works, line by line (simple terms)

- **The imports** (`re`, `sys`, `urllib.parse`) — Python's built-in toolboxes.
  `urllib.parse` is the star: it splits a URL into scheme, hostname, path,
  etc., so we don't have to do it by hand.
- **The red-flag lists** (`SUSPICIOUS_TLDS`, `BRAND_NAMES`, `URL_SHORTENERS`)
  — this is a miniature version of *threat intelligence*: lists of known-bad
  patterns. Real SOC tools download these from feeds; we hard-code a few to
  teach the concept.
- **`extract_host(url)`** — takes a messy URL and returns the clean hostname.
  If you hand it a bare `example.com` it politely adds `http://` first.
- **`check_url(url)`** — the heart of the program. It runs the 10 checks,
  each one adding points to `score` and appending a human-readable reason to
  the `reasons` list. Then it converts the score into a verdict. Returning
  `(score, reasons, verdict)` together means the caller gets both the answer
  *and* the evidence.
- **`load_urls()` / `read_file()`** — flexible input: no arguments → sample
  file; a `.txt` file → check it; plain URLs → check them directly.
- **`main()`** — prints a report per URL, counts how many were flagged, and
  ends with the most important tip: *the real domain is the last two parts*.

## Key terms translated

| Term | Plain English |
|---|---|
| Phishing | Fake messages/links that impersonate someone you trust to steal logins or money |
| SOC (Security Operations Center) | The team that watches a company's network for attacks, 24/7 |
| Triage | Quick first sorting: urgent vs. fine, before a deep investigation |
| Threat intelligence | Shared lists of known-bad domains, IPs, and patterns analysts check against |
| Punycode | A way to write non-English characters in domain names — abusable for lookalike fakes |
| URL shortener | A service that turns a long link into a short one — convenient, but hides the destination |

## How to run it

```bash
# Check the built-in sample list (mix of legit and phishing-style links)
python3 phishing_url_checker.py

# Check your own list of links (one per line)
python3 phishing_url_checker.py my_links.txt

# Check a single link on the spot
python3 phishing_url_checker.py "https://suspicious-link.example"

# Machine-readable output (JSON) — for spreadsheets or security pipelines
python3 phishing_url_checker.py --json my_links.txt
```

Needs nothing but Python 3 — no installs, no internet, no admin rights.

## What to learn next

- **Read a real phishing email header.** URLs are one clue; email headers
  show the true sender. Try spotting a forged `From` field.
- **Look up URL-reputation APIs** (VirusTotal, Google Safe Browsing). Real
  SOCs combine local heuristics like these with global threat feeds.
- **Learn about DNS.** This script trusts the text of the URL; DNS is how
  computers resolve names to IPs — understanding it explains *why* the last
  two domain parts are the ones that matter.
- **Try typosquatting detection.** Our brand check is simple; a next step is
  measuring how *similar* a domain is to a real brand (e.g. `paypa1.com`).
