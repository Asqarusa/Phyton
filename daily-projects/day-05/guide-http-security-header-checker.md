# HTTP Security Header Checker — plain-English guide

**Day 5 · networking theme · Python, standard library only**

## What's new in this version (Oct 2026 update)

The first version of this script only answered one question per header: *is it there or not?* This update asks a sharper second question: ***is it actually doing its job?***

Non-tech analogy first: imagine inspecting a house. The old script checked whether each door *has* a lock. The new one also checks whether the lock is *locked* — because a header can be present but badly configured (like an HSTS header that expires after 60 seconds, or a content-security policy that allows `'unsafe-inline'`). That state is now graded **WEAK** — half a point instead of a full point or zero.

The other upgrades:

- **Half-point scoring** — each header is now GOOD (1 point), WEAK (0.5), or MISSING (0), for a score out of 5 that reflects reality better.
- **Value-quality graders** — one per header. They catch real-world misconfigurations: HSTS with a tiny `max-age` or missing `includeSubDomains`, CSP with `unsafe-inline` / `unsafe-eval` / wildcards, a typo'd `X-Frame-Options` value like the obsolete `ALLOW-FROM`, anything that isn't exactly `nosniff`, and a `Referrer-Policy` of `unsafe-url` (which shares the full page URL with other sites).
- **Bonus check** — `Permissions-Policy` is now reported (not scored). It limits powerful browser features like camera and microphone.
- **Command-line flags** — `--url`, `--timeout`, `--json` (machine-readable output for piping into other tools), and `--demo` with two built-in sample sites (a strong one and a weak one) so the whole tool is testable offline.
- **Friendlier errors** — junk URLs and timeouts now explain what to do instead of dumping a traceback. More version-leaking headers are also flagged (`X-AspNetMvc-Version`, `Via`).

## The big idea (start here)

Every time your browser opens a website, the site doesn't just send back the page — it also sends back a small set of **invisible labels** called *HTTP response headers*. Think of them like the stamps and handling instructions on a delivery box: "fragile," "this side up," "do not leave in the rain."

Some of those labels are **security instructions for the browser**. A website can stamp its box with things like "always deliver over a secure channel" or "don't let anyone repackage this page inside their own frame." They cost the website owner nothing — one line of configuration each — yet many sites forget them.

This script is a **label reader**. You give it a website address; it makes one normal visit (exactly like opening the page once in a browser), reads the labels, and grades the site's basic security hygiene. It's read-only and safe: it never attacks anything, it just *reads the packaging*.

## What the script does

1. **Asks for a website URL** (defaults to `https://example.com` if you just press Enter; adds `https://` automatically if you type a bare domain).
2. **Makes one GET request** — via `--url` (or type it when prompted, as before) with a configurable `--timeout` (default 10 seconds) — the same request a browser makes. Add `--demo strong` or `--demo weak` to try the built-in sample sites with no network at all.
3. **Section 1 — Transport security:** Is the connection HTTPS? If HTTPS is used but there's no `Strict-Transport-Security` header, it warns that browsers could still be tricked onto plain HTTP (a downgrade attack).
4. **Section 2 — The five core security headers, now value-graded:** For each one it prints GOOD, WEAK (present but badly configured — with a note explaining exactly what's wrong), or MISSING. GOOD shows the actual value plus a short confirmation note; WEAK explains the flaw; MISSING shows what a good value looks like.
5. **Section 3 — Cookie flags:** If the server sets cookies, checks each for the `Secure`, `HttpOnly`, and `SameSite` flags that protect cookies from theft, and names any that are missing.
6. **Section 4 — Info disclosure (note only):** Flags headers like `Server: ...` that reveal the exact web-server software/version. That's free reconnaissance for an attacker — like a burglar reading the brand of your alarm system off the box. Now also covers `X-AspNetMvc-Version` and `Via`.
7. **Bonus — Permissions-Policy (not scored):** Reports whether the site limits powerful browser features (camera, mic, geolocation). Optional, but a nice extra.
8. **Summary:** A score out of 5 with half points (GOOD=1, WEAK=0.5, MISSING=0) and a verdict from EXCELLENT down to MISSING, plus the key takeaway. Add `--json` for the same findings as machine-readable JSON — handy for piping into other tools or a spreadsheet.

## How the code works, in simple terms

- **`SECURITY_HEADERS` dictionary** — our checklist. Each entry stores the header name, a plain-English explanation of its job, and what a good value looks like. This is the *knowledge base*; everything else is plumbing.
- **`INFO_HEADERS` dictionary** — headers that aren't security features but leak too much info. Kept separate because finding one is a *note*, not a failure.
- **`normalize_url()`** — tidies up what the user types: empty input becomes `https://example.com`, a bare domain gets `https://` added. Small politeness function.
- **`fetch_headers()`** — the only part that touches the network. It builds a request (identifying itself honestly as a learning project) and opens it with a timeout. `with ... as response:` makes sure the connection closes itself. Returns the headers, the final URL (after any redirects), and the status code.
- **`check_security_headers()`** — builds a case-insensitive lookup of the returned headers (HTTP header names aren't case-sensitive, so `content-security-policy` must match `Content-Security-Policy`) and produces one row per checklist item.
- **`check_info_disclosure()`** and **`check_cookie_flags()`** — two focused graders: one notes version-leaking headers, the other parses each `Set-Cookie` line for the three protective flags.
- **`VALUE_GRADERS` dictionary** — one small grading function per header. Each one inspects the header's *value* and returns GOOD or WEAK with a plain-English note about exactly what's wrong (e.g. "max-age is only 60s; guides recommend ≥ 1 year"). This is the heart of the update: presence isn't enough, configuration matters.
- **`check_security_headers()`** — now produces GOOD / WEAK / MISSING rows using the graders, with a note column for the weak cases.
- **`header_score()`** — GOOD=1, WEAK=0.5, MISSING=0; `verdict()` thresholds stayed the same ratios, so the plain-language verdicts mean what they always meant.
- **`parse_args()`** — command-line flags via `argparse` (`--url`, `--timeout`, `--json`, `--demo`). The old interactive prompt is gone in favor of flags, which also makes the tool scriptable.
- **`DEMO_RESPONSES`** — two canned header sets (strong site / weak site) so `--demo` runs fully offline — great for learning and for testing the graders.
- **`json_report()`** — same findings as structured JSON for piping into other tools; `human_report()` keeps the classic readable layout with a new BONUS section for `Permissions-Policy`.
- **`valid_url()`** — rejects junk input (bad schemes, spaces in hostnames) with a friendly hint instead of a traceback.
- **`main()`** — the flow controller. Picks demo data or fetches live (handling the same two graceful failure modes as before, plus friendlier timeout/invalid-URL messages), grades, then prints the human report or JSON. Exits 0 on success, 1 when the site couldn't be reached or the input was invalid.

## Key terms translated

| Term | Plain English |
|---|---|
| HTTP response header | An invisible label the server attaches to every page it sends |
| HTTPS | HTTP wrapped in encryption — nobody in the middle can read or change it |
| HSTS (`Strict-Transport-Security`) | A header that tells the browser: *never* contact this site over insecure HTTP again |
| CSP (`Content-Security-Policy`) | A allow-list of where scripts/images may load from — the best defense against injected scripts (XSS) |
| Clickjacking | Tricking you into clicking something by hiding the real page inside an invisible frame |
| MIME sniffing | The browser *guessing* a file's type instead of trusting what the server said — attackers abuse this to sneak in scripts; `nosniff` forbids the guessing |
| Referrer | The page URL your browser shares with the next site when you click a link |
| Cookie flags (`Secure`, `HttpOnly`, `SameSite`) | Cookie settings: only send over HTTPS / invisible to JavaScript / only sent to the site that set it |
| Info disclosure | A server accidentally telling attackers its exact software and version |

## How to run it

```bash
python3 http_security_header_checker.py --url github.com
python3 http_security_header_checker.py --demo          # offline: strong site
python3 http_security_header_checker.py --demo weak    # offline: weak site
python3 http_security_header_checker.py --url example.com --json
```

- Type a bare domain like `github.com` — `https://` is added automatically.
- `--timeout 20` if a slow site times out; `--json` for machine-readable output.
- Requires Python 3 and internet access (unless you use `--demo`). No installs, no extra packages (standard library only: `urllib`, `argparse`, `json`, `re`, `sys`).

## What to learn next

1. **Try real sites** and compare — big tech companies score 5/5; small blogs often score 0/5. Notice that a missing header ≠ "hacked"; it means *less defended*.
2. **Read about CSP** (`developer.mozilla.org` → Content Security Policy). It's the most powerful header here — and the hardest to write well.
3. **Check your own projects**: if you ever deploy a website, these five headers are five one-line config changes — the cheapest security upgrade there is.
4. **Next in the series**: how cookies themselves work, and why `HttpOnly` matters (that's a demo for another day).
5. **For SOC analysts**: reading response headers is a first step in web reconnaissance — the same headers attackers check to find soft targets. Defenders read them to find what to fix.

*Day 5 of a daily cybersecurity practice series — small projects, plain English, real skills.*
