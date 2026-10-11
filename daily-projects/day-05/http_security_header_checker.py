#!/usr/bin/env python3
"""
HTTP Security Header Checker — Day 5 of a daily cybersecurity practice series.

What it does:
    Makes one normal GET request to a public website (the kind your browser
    makes every time you open a page), reads the HTTP *response headers* the
    server sends back, and grades the site's basic security hygiene:
      1. Are the five "must-have" security headers present?
      2. Is the connection protected with HTTPS (Strict-Transport-Security)?
      3. Do cookies carry the Secure / HttpOnly / SameSite flags?
      4. Is the server leaking version info (info-disclosure note)?

Safety notes (please read):
    - This only READS. It never attacks, brute-forces, or changes anything.
    - It sends exactly one GET request, like a browser visiting the page once.
    - Only ever point it at public websites you are allowed to visit in a
      browser. It is NOT a vulnerability scanner and does not test for real
      vulnerabilities — it just reports which defensive headers are missing.

Run it:  python3 http_security_header_checker.py
"""

import sys
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# The five "must-have" security headers.
# Key   -> (plain-English job description, what to look for)
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security":
        ("Forces the browser to always use HTTPS with this site, so nobody "
         "can quietly downgrade you to insecure HTTP.",
         "Should say max-age=<seconds>, e.g. max-age=31536000"),
    "Content-Security-Policy":
        ("Tells the browser which sources of scripts/images are allowed. It "
         "is the single best defense against cross-site scripting (XSS).",
         "Should list allowed sources, e.g. default-src 'self'"),
    "X-Frame-Options":
        ("Stops other sites from embedding this page in an invisible frame "
         "(a trick called clickjacking).",
         "Should be DENY or SAMEORIGIN"),
    "X-Content-Type-Options":
        ("With value 'nosniff', stops the browser from guessing a file's "
         "type — which attackers abuse to sneak scripts past filters.",
         "Should be exactly: nosniff"),
    "Referrer-Policy":
        ("Controls how much of the page URL is shared with other sites when "
         "you click a link. Less sharing = less private info leaking.",
         "Safer values: strict-origin-when-cross-origin, no-referrer, same-origin"),
}

# Headers that are not security features but can leak too much info about
# the server — useful knowledge for attackers mapping a network.
INFO_HEADERS = {
    "Server": "may reveal the exact web server software and version",
    "X-Powered-By": "may reveal the exact framework/language version",
    "X-AspNet-Version": "may reveal the exact .NET version",
}

REQUEST_TIMEOUT_SECONDS = 10


def normalize_url(raw: str) -> str:
    """Make sure the URL has a scheme; default to HTTPS if missing."""
    raw = raw.strip()
    if not raw:
        return "https://example.com"
    if "://" not in raw:
        return "https://" + raw
    return raw


def fetch_headers(url: str):
    """Fetch the response headers for one GET request. Returns (headers, final_url, status)."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurityHeaderChecker/1.0 (learning project)"},
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return response.headers, response.geturl(), response.status


def check_security_headers(headers) -> list:
    """Return a list of (header, status, value, job) rows."""
    rows = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for name, (job, good) in SECURITY_HEADERS.items():
        value = lowered.get(name.lower())
        rows.append((name, "PRESENT" if value else "MISSING", value or "-", job, good))
    return rows


def check_info_disclosure(headers) -> list:
    """Return note-only rows for headers that can leak server version info."""
    rows = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for name, risk in INFO_HEADERS.items():
        value = lowered.get(name.lower())
        if value:
            rows.append((name, value, risk))
    return rows


def check_cookie_flags(headers) -> list:
    """Check Set-Cookie flags. Returns rows of (cookie_preview, missing_flags)."""
    rows = []
    cookies = headers.get_all("Set-Cookie") or []
    for cookie in cookies:
        low = cookie.lower()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        preview = cookie.split(";")[0][:60]
        rows.append((preview, missing))
    return rows


def print_section(title: str):
    print("\n" + "=" * 62)
    print(title)
    print("=" * 62)


def verdict(score: int, total: int) -> str:
    ratio = score / total
    if ratio == 1.0:
        return "EXCELLENT — all five core security headers are present."
    if ratio >= 0.6:
        return "GOOD — solid basics, but some defenses are missing."
    if ratio > 0:
        return "NEEDS WORK — several basic defenses are missing."
    return "MISSING — none of the five core security headers were found."


def main() -> int:
    print("=" * 62)
    print("  HTTP SECURITY HEADER CHECKER")
    print("  Read-only: one normal GET request, like opening the page.")
    print("=" * 62)

    raw = input("\nEnter a website URL [default: https://example.com]: ")
    url = normalize_url(raw)
    print(f"\nChecking: {url}\n")

    try:
        headers, final_url, status = fetch_headers(url)
    except urllib.error.HTTPError as e:
        # HTTP errors (404, 403, ...) still return headers — still useful.
        headers, final_url, status = e.headers, e.geturl(), e.code
        print(f"(server answered with HTTP {status}; checking its headers anyway)")
    except (urllib.error.URLError, OSError) as e:
        print(f"Could not reach the site: {e}")
        print("Check the URL and your internet connection, then try again.")
        return 1

    parsed = urllib.parse.urlparse(final_url)
    print(f"Final URL after redirects : {final_url}")
    print(f"HTTP status               : {status}")

    # --- 1. HTTPS check -----------------------------------------------------
    print_section("1) TRANSPORT SECURITY")
    if parsed.scheme == "https":
        print("  [OK] Served over HTTPS — traffic is encrypted.")
    else:
        print("  [!] Served over plain HTTP — traffic can be read or modified.")
    rows = check_security_headers(headers)
    hsts = next((r for r in rows if r[0] == "Strict-Transport-Security"), None)
    if parsed.scheme == "https" and hsts and hsts[1] == "MISSING":
        print("  [!] No HSTS header: browsers could still be tricked onto HTTP.")

    # --- 2. The five core headers ------------------------------------------
    print_section("2) CORE SECURITY HEADERS")
    score = 0
    for name, state, value, job, good in rows:
        mark = "[OK]" if state == "PRESENT" else "[!]"
        if state == "PRESENT":
            score += 1
        print(f"  {mark} {name}: {state}")
        print(f"       Why it matters : {job}")
        if state == "PRESENT":
            print(f"       Value          : {value}")
        else:
            print(f"       Good value     : {good}")

    # --- 3. Cookie flags ----------------------------------------------------
    print_section("3) COOKIE FLAGS")
    cookie_rows = check_cookie_flags(headers)
    if not cookie_rows:
        print("  (no cookies were set by this response)")
    for preview, missing in cookie_rows:
        if not missing:
            print(f"  [OK] {preview}  — flags look good")
        else:
            print(f"  [!]  {preview}")
            print(f"       Missing flags  : {', '.join(missing)}")
            print("       (Secure/ HttpOnly / SameSite protect cookies from theft)")

    # --- 4. Info disclosure -------------------------------------------------
    print_section("4) INFO DISCLOSURE (note only)")
    info_rows = check_info_disclosure(headers)
    if not info_rows:
        print("  [OK] No obvious version-leaking headers found.")
    for name, value, risk in info_rows:
        print(f"  [i]  {name}: {value}")
        print(f"       This {risk}; hide or shorten it to give attackers less.")

    # --- Summary -------------------------------------------------------------
    print_section("SUMMARY")
    print(f"  Core headers present: {score} / {len(SECURITY_HEADERS)}")
    print(f"  {verdict(score, len(SECURITY_HEADERS))}")
    print("\nTakeaway: these headers are free one-line defenses. A site missing")
    print("them is not automatically hacked — but it is less defended than it")
    print("could be, and a SOC analyst reads them the way a doctor reads vitals.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
