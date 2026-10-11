# HTTP Security Header Checker — plain-English guide

**Day 5 · networking theme · Python, standard library only**

## The big idea (start here)

Every time your browser opens a website, the site doesn't just send back the page — it also sends back a small set of **invisible labels** called *HTTP response headers*. Think of them like the stamps and handling instructions on a delivery box: "fragile," "this side up," "do not leave in the rain."

Some of those labels are **security instructions for the browser**. A website can stamp its box with things like "always deliver over a secure channel" or "don't let anyone repackage this page inside their own frame." They cost the website owner nothing — one line of configuration each — yet many sites forget them.

This script is a **label reader**. You give it a website address; it makes one normal visit (exactly like opening the page once in a browser), reads the labels, and grades the site's basic security hygiene. It's read-only and safe: it never attacks anything, it just *reads the packaging*.

## What the script does

1. **Asks for a website URL** (defaults to `https://example.com` if you just press Enter; adds `https://` automatically if you type a bare domain).
2. **Makes one GET request** with a 10-second timeout — the same request a browser makes.
3. **Section 1 — Transport security:** Is the connection HTTPS? If HTTPS is used but there's no `Strict-Transport-Security` header, it warns that browsers could still be tricked onto plain HTTP (a downgrade attack).
4. **Section 2 — The five core security headers:** For each one it prints PRESENT or MISSING, explains *why it matters* in plain English, and — if present — shows the actual value; if missing — shows what a good value looks like.
5. **Section 3 — Cookie flags:** If the server sets cookies, checks each for the `Secure`, `HttpOnly`, and `SameSite` flags that protect cookies from theft, and names any that are missing.
6. **Section 4 — Info disclosure (note only):** Flags headers like `Server: ...` that reveal the exact web-server software/version. That's free reconnaissance for an attacker — like a burglar reading the brand of your alarm system off the box.
7. **Summary:** A score out of 5 and a verdict from EXCELLENT down to MISSING, plus the key takeaway.

## How the code works, in simple terms

- **`SECURITY_HEADERS` dictionary** — our checklist. Each entry stores the header name, a plain-English explanation of its job, and what a good value looks like. This is the *knowledge base*; everything else is plumbing.
- **`INFO_HEADERS` dictionary** — headers that aren't security features but leak too much info. Kept separate because finding one is a *note*, not a failure.
- **`normalize_url()`** — tidies up what the user types: empty input becomes `https://example.com`, a bare domain gets `https://` added. Small politeness function.
- **`fetch_headers()`** — the only part that touches the network. It builds a request (identifying itself honestly as a learning project) and opens it with a timeout. `with ... as response:` makes sure the connection closes itself. Returns the headers, the final URL (after any redirects), and the status code.
- **`check_security_headers()`** — builds a case-insensitive lookup of the returned headers (HTTP header names aren't case-sensitive, so `content-security-policy` must match `Content-Security-Policy`) and produces one row per checklist item.
- **`check_info_disclosure()`** and **`check_cookie_flags()`** — two focused graders: one notes version-leaking headers, the other parses each `Set-Cookie` line for the three protective flags.
- **`verdict()`** — turns the score into plain language. 5/5 → Excellent, 3–4 → Good, 1–2 → Needs work, 0 → Missing.
- **`main()`** — the flow controller. Asks for the URL, fetches (handling the two graceful failure modes: a server error page still gets its headers checked; a dead/unreachable site gets a friendly message), then prints the four sections and the summary. Exits 0 on success, 1 when the site couldn't be reached.

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
python3 http_security_header_checker.py
```

- Press Enter to check the default `https://example.com`, or type any public site.
- Type a bare domain like `github.com` — `https://` is added automatically.
- Requires Python 3 and internet access. No installs, no extra packages (standard library only: `urllib`, `sys`).

## What to learn next

1. **Try real sites** and compare — big tech companies score 5/5; small blogs often score 0/5. Notice that a missing header ≠ "hacked"; it means *less defended*.
2. **Read about CSP** (`developer.mozilla.org` → Content Security Policy). It's the most powerful header here — and the hardest to write well.
3. **Check your own projects**: if you ever deploy a website, these five headers are five one-line config changes — the cheapest security upgrade there is.
4. **Next in the series**: how cookies themselves work, and why `HttpOnly` matters (that's a demo for another day).
5. **For SOC analysts**: reading response headers is a first step in web reconnaissance — the same headers attackers check to find soft targets. Defenders read them to find what to fix.

*Day 5 of a daily cybersecurity practice series — small projects, plain English, real skills.*
