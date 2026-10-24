#!/usr/bin/env python3
"""
HTTP Security Header Checker — Day 5 of a daily cybersecurity practice series.

IMPROVED VERSION (2026-10-23): the original only reported whether each header
was PRESENT or MISSING. This version also grades the *quality* of the values —
a header can be present but weak (like a lock installed but left unlocked):

  1. Header VALUE quality checks: HSTS max-age too short, CSP allowing
     'unsafe-inline', X-Frame-Options with a typo'd value, etc. now score WEAK.
  2. Half-point scoring: GOOD = 1, WEAK = 0.5, MISSING = 0 (score out of 5).
  3. Bonus note: Permissions-Policy is now reported (not scored).
  4. CLI flags: --url, --timeout, --json, --demo (no more input() only).
  5. --demo mode: two built-in sample responses (strong site / weak site), so
     the tool is fully testable offline.
  6. Friendlier errors: invalid URLs and timeouts explain what to do.

What it does:
    Makes one normal GET request to a public website (the kind your browser
    makes every time you open a page), reads the HTTP *response headers* the
    server sends back, and grades the site's basic security hygiene:
      1. Are the five "must-have" security headers present — and well set?
      2. Is the connection protected with HTTPS (Strict-Transport-Security)?
      3. Do cookies carry the Secure / HttpOnly / SameSite flags?
      4. Is the server leaking version info (info-disclosure note)?

Safety notes (please read):
    - This only READS. It never attacks, brute-forces, or changes anything.
    - It sends exactly one GET request, like a browser visiting the page once.
    - Only ever point it at public websites you are allowed to visit in a
      browser. It is NOT a vulnerability scanner and does not test for real
      vulnerabilities — it just reports which defensive headers are missing.

Run it:  python3 http_security_header_checker.py --url https://example.com
          python3 http_security_header_checker.py --demo        # offline demo
          python3 http_security_header_checker.py --url github.com --json
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# The five "must-have" security headers.
# Key -> (plain-English job description, what to look for)
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
    "X-AspNetMvc-Version": "may reveal the exact ASP.NET MVC version",
    "Via": "reveals proxy / CDN hops in front of the server",
}

# One year in seconds — the minimum max-age security guides recommend for HSTS.
HSTS_MIN_MAX_AGE = 31536000

# CSP fragments that cancel out most of the header's protection.
CSP_WEAK_PATTERNS = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*",
                     "http:", "'unsafe-hashes'"]

# Referrer-Policy values that share the full URL with other sites.
WEAK_REFERRER_VALUES = {"unsafe-url", "no-referrer-when-downgrade", ""}

DEFAULT_TIMEOUT_SECONDS = 10

# ---------------------------------------------------------------------------
# Offline demo data: two canned responses so the tool can be explored and
# tested without any network access.
# ---------------------------------------------------------------------------
DEMO_RESPONSES = {
    "strong": (
        "https://demo-strong-site.test/",
        200,
        {
            "Strict-Transport-Security":
                "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy":
                "default-src 'self'; script-src 'self' https://cdn.demo.test",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax",
        },
    ),
    "weak": (
        "http://demo-weak-site.test/",
        200,
        {
            "Strict-Transport-Security": "max-age=60",
            "Content-Security-Policy":
                "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
            "X-Frame-Options": "ALLOW-FROM https://old.test",
            "Referrer-Policy": "unsafe-url",
            "Server": "Apache/2.4.1 (OldOS)",
            "X-Powered-By": "PHP/5.6.40",
            "Set-Cookie": "prefs=dark-mode",
        },
    ),
}


def parse_args(argv=None):
    """Parse command-line flags (keeps interactive mode as a fallback)."""
    parser = argparse.ArgumentParser(
        description="Check a website's HTTP security headers (read-only, "
                    "one GET request, like opening the page once).")
    parser.add_argument("--url", default="",
                        help="Website to check (default: https://example.com).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS,
                        help="Request timeout in seconds (default 10).")
    parser.add_argument("--json", action="store_true",
                        help="Print machine-readable JSON instead of the "
                             "human report (useful for piping into other tools).")
    parser.add_argument("--demo", choices=["strong", "weak"],
                        nargs="?", const="strong",
                        help="Use built-in sample data instead of the network "
                             "(strong or weak site; fully offline).")
    return parser.parse_args(argv)


def normalize_url(raw: str) -> str:
    """Make sure the URL has a scheme; default to HTTPS if missing."""
    raw = raw.strip()
    if not raw:
        return "https://example.com"
    if "://" not in raw:
        return "https://" + raw
    return raw


def valid_url(url: str) -> bool:
    """Reject obviously broken URLs with a friendly message later."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        # Hostnames can't contain spaces or control characters.
        if not host or any(ch.isspace() for ch in host):
            return False
        return parsed.scheme in ("http", "https")
    except ValueError:
        return False


def fetch_headers(url: str, timeout: int):
    """Fetch the response headers for one GET request.
    Returns (headers_dict, final_url, status)."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SecurityHeaderChecker/1.0 (learning project)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return dict(response.headers), response.geturl(), response.status


def grade_hsts(value: str) -> tuple:
    """Grade an HSTS value. Returns (state, note)."""
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else 0
    notes = []
    if max_age < HSTS_MIN_MAX_AGE:
        notes.append(f"max-age is only {max_age}s; guides recommend "
                     f">= {HSTS_MIN_MAX_AGE}s (1 year)")
    low = value.lower()
    if "includesubdomains" not in low:
        notes.append("missing includeSubDomains — subdomains are unprotected")
    if not notes:
        notes.append("strong: long max-age with includeSubDomains")
    state = "GOOD" if not notes or notes[0].startswith("strong") else "WEAK"
    return state, "; ".join(notes)


def grade_csp(value: str) -> tuple:
    """Grade a Content-Security-Policy value. Returns (state, note)."""
    low = value.lower()
    found = [p for p in CSP_WEAK_PATTERNS if p.lower() in low]
    if found:
        return ("WEAK",
                "contains weak source(s): " + ", ".join(found) +
                " — these punch holes in the policy")
    if "default-src" not in low and "script-src" not in low:
        return ("WEAK", "no default-src or script-src — the policy covers "
                        "almost nothing")
    return ("GOOD", "restricts script sources without obvious holes")


def grade_frame_options(value: str) -> tuple:
    """Grade an X-Frame-Options value. Returns (state, note)."""
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return ("GOOD", f"value '{value.strip()}' blocks framing attacks")
    return ("WEAK", f"value '{value.strip()}' is not DENY or SAMEORIGIN "
                    "(ALLOW-FROM is obsolete and ignored by modern browsers)")


def grade_content_type_options(value: str) -> tuple:
    """Grade an X-Content-Type-Options value. Returns (state, note)."""
    if value.strip().lower() == "nosniff":
        return ("GOOD", "exactly 'nosniff' — browsers won't guess file types")
    return ("WEAK", f"value '{value.strip()}' is not 'nosniff' — only that "
                    "exact value works")


def grade_referrer_policy(value: str) -> tuple:
    """Grade a Referrer-Policy value. Returns (state, note)."""
    if value.strip().lower() in WEAK_REFERRER_VALUES:
        return ("WEAK", f"value '{value.strip()}' shares the full page URL "
                        "with other sites")
    return ("GOOD", f"value '{value.strip()}' limits URL sharing")


# Which grader to call per header; anything without a grader is GOOD if present.
VALUE_GRADERS = {
    "Strict-Transport-Security": grade_hsts,
    "Content-Security-Policy": grade_csp,
    "X-Frame-Options": grade_frame_options,
    "X-Content-Type-Options": grade_content_type_options,
    "Referrer-Policy": grade_referrer_policy,
}


def check_security_headers(headers: dict) -> list:
    """Return rows of (name, state, value, job, good_example, note).

    State is GOOD / WEAK (present but badly configured) / MISSING.
    """
    rows = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for name, (job, good) in SECURITY_HEADERS.items():
        value = lowered.get(name.lower())
        if not value:
            rows.append((name, "MISSING", "-", job, good, ""))
            continue
        grader = VALUE_GRADERS.get(name)
        state, note = grader(value) if grader else ("GOOD", "")
        rows.append((name, state, value, job, good, note))
    return rows


def check_info_disclosure(headers: dict) -> list:
    """Return note-only rows for headers that can leak server version info."""
    rows = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for name, risk in INFO_HEADERS.items():
        value = lowered.get(name.lower())
        if value:
            rows.append((name, value, risk))
    return rows


def check_permissions_policy(headers: dict):
    """Bonus check (not scored): Permissions-Policy limits browser features."""
    lowered = {k.lower(): v for k, v in headers.items()}
    return lowered.get("permissions-policy")


def check_cookie_flags(headers: dict) -> list:
    """Check Set-Cookie flags. Returns rows of (cookie_preview, missing_flags)."""
    rows = []
    raw = headers.get("Set-Cookie") or headers.get("set-cookie")
    cookies = [raw] if isinstance(raw, str) else (raw or [])
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


def header_score(rows: list) -> float:
    """GOOD = 1 point, WEAK = 0.5, MISSING = 0."""
    points = {"GOOD": 1.0, "WEAK": 0.5, "MISSING": 0.0}
    return sum(points[state] for _, state, *_ in rows)


def verdict(score: float, total: int) -> str:
    ratio = score / total
    if ratio == 1.0:
        return "EXCELLENT — all five core security headers are present and well set."
    if ratio >= 0.6:
        return "GOOD — solid basics, but some defenses are missing or weak."
    if ratio > 0:
        return "NEEDS WORK — several basic defenses are missing or weak."
    return "MISSING — none of the five core security headers were found."


def print_section(title: str):
    print("\n" + "=" * 62)
    print(title)
    print("=" * 62)


def state_mark(state: str) -> str:
    return {"GOOD": "[OK]", "WEAK": "[~]", "MISSING": "[!]"}.get(state, "[?]")


def human_report(url, final_url, status, rows, cookie_rows, info_rows,
                 permissions_policy, score) -> None:
    """Print the classic human-readable report."""
    print("=" * 62)
    print("  HTTP SECURITY HEADER CHECKER")
    print("  Read-only: one normal GET request, like opening the page.")
    print("=" * 62)
    print(f"\nChecking: {url}\n")

    parsed = urllib.parse.urlparse(final_url)
    print(f"Final URL after redirects : {final_url}")
    print(f"HTTP status               : {status}")

    # --- 1. HTTPS check -----------------------------------------------------
    print_section("1) TRANSPORT SECURITY")
    if parsed.scheme == "https":
        print("  [OK] Served over HTTPS — traffic is encrypted.")
    else:
        print("  [!] Served over plain HTTP — traffic can be read or modified.")
    hsts = next((r for r in rows if r[0] == "Strict-Transport-Security"), None)
    if parsed.scheme == "https" and hsts and hsts[1] == "MISSING":
        print("  [!] No HSTS header: browsers could still be tricked onto HTTP.")

    # --- 2. The five core headers ------------------------------------------
    print_section("2) CORE SECURITY HEADERS (value quality graded)")
    for name, state, value, job, good, note in rows:
        mark = state_mark(state)
        print(f"  {mark} {name}: {state}")
        print(f"       Why it matters : {job}")
        if state == "MISSING":
            print(f"       Good value     : {good}")
        else:
            print(f"       Value          : {value}")
            if note:
                print(f"       Note           : {note}")

    # --- 3. Cookie flags ----------------------------------------------------
    print_section("3) COOKIE FLAGS")
    if not cookie_rows:
        print("  (no cookies were set by this response)")
    for preview, missing in cookie_rows:
        if not missing:
            print(f"  [OK] {preview}  — flags look good")
        else:
            print(f"  [!]  {preview}")
            print(f"       Missing flags  : {', '.join(missing)}")
            print("       (Secure / HttpOnly / SameSite protect cookies from theft)")

    # --- 4. Info disclosure -------------------------------------------------
    print_section("4) INFO DISCLOSURE (note only)")
    if not info_rows:
        print("  [OK] No obvious version-leaking headers found.")
    for name, value, risk in info_rows:
        print(f"  [i]  {name}: {value}")
        print(f"       This {risk}; hide or shorten it to give attackers less.")

    # --- Bonus: Permissions-Policy ------------------------------------------
    print_section("BONUS) PERMISSIONS-POLICY (not scored)")
    if permissions_policy:
        print(f"  [OK] Present: {permissions_policy}")
        print("       Limits powerful browser features (camera, mic, geolocation).")
    else:
        print("  (not set — optional; a nice extra that limits browser features)")

    # --- Summary -------------------------------------------------------------
    print_section("SUMMARY")
    score_text = ("%g" % score)
    print(f"  Core header score: {score_text} / {len(SECURITY_HEADERS)} "
          f"(GOOD=1, WEAK=0.5, MISSING=0)")
    print(f"  {verdict(score, len(SECURITY_HEADERS))}")
    print("\nTakeaway: these headers are free one-line defenses. A site missing")
    print("them is not automatically hacked — but it is less defended than it")
    print("could be, and a SOC analyst reads them the way a doctor reads vitals.")


def json_report(url, final_url, status, rows, cookie_rows, info_rows,
                permissions_policy, score) -> str:
    """Machine-readable version of the same findings."""
    return json.dumps({
        "url": url,
        "final_url": final_url,
        "http_status": status,
        "score": score,
        "max_score": len(SECURITY_HEADERS),
        "verdict": verdict(score, len(SECURITY_HEADERS)),
        "headers": [
            {"name": name, "state": state, "value": value, "note": note}
            for name, state, value, _job, _good, note in rows
        ],
        "cookies": [
            {"cookie": preview, "missing_flags": missing}
            for preview, missing in cookie_rows
        ],
        "info_disclosure": [
            {"header": name, "value": value, "risk": risk}
            for name, value, risk in info_rows
        ],
        "permissions_policy": permissions_policy,
    }, indent=2)


def main(argv=None) -> int:
    args = parse_args(argv)

    # --- Demo mode: no network, built-in sample data -------------------------
    if args.demo:
        url, status, headers = DEMO_RESPONSES[args.demo]
        final_url = url
    else:
        url = normalize_url(args.url)
        if not valid_url(url):
            print(f"'{args.url or url}' doesn't look like a valid website address.")
            print("Try something like: python3 http_security_header_checker.py "
                  "--url github.com")
            return 1
        if args.timeout < 1:
            print("Timeout must be at least 1 second.")
            return 1
        try:
            headers, final_url, status = fetch_headers(url, args.timeout)
        except urllib.error.HTTPError as e:
            # HTTP errors (404, 403, ...) still return headers — still useful.
            headers, final_url, status = dict(e.headers), e.geturl(), e.code
            print(f"(server answered with HTTP {status}; checking its headers anyway)")
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            print(f"Could not reach the site: {reason}")
            if "timed out" in str(reason).lower():
                print("The site took too long to answer — try --timeout 20.")
            else:
                print("Check the URL and your internet connection, then try again.")
            return 1
        except OSError as e:
            print(f"Network problem: {e}")
            print("Check your internet connection, then try again.")
            return 1

    rows = check_security_headers(headers)
    cookie_rows = check_cookie_flags(headers)
    info_rows = check_info_disclosure(headers)
    permissions_policy = check_permissions_policy(headers)
    score = header_score(rows)

    if args.json:
        print(json_report(url, final_url, status, rows, cookie_rows,
                          info_rows, permissions_policy, score))
    else:
        human_report(url, final_url, status, rows, cookie_rows, info_rows,
                     permissions_policy, score)
    return 0


if __name__ == "__main__":
    sys.exit(main())
