#!/usr/bin/env python3
"""
Phishing URL Checker — a tiny SOC-style triage tool.

What it does:
    Reads a list of URLs (from the sample file or passed as arguments) and
    scores each one for common phishing red flags — no network calls at all,
    just string analysis. The goal is to teach *how analysts triage suspicious
    links* during a real investigation.

Why it matters for a SOC analyst:
    Phishing is still the #1 way attackers get a foothold in a network.
    Analysts see suspicious URLs all day and must quickly decide which ones
    deserve deeper investigation. This script automates that first pass.

Safety:
    The script never visits the URLs — it only analyzes the text of the link.
    That's the safe way to investigate a suspicious link: never click it.

Usage:
    python3 phishing_url_checker.py                  # checks sample_urls.txt
    python3 phishing_url_checker.py <urls.txt>       # checks your own file
    python3 phishing_url_checker.py https://example.com  # checks one URL directly
"""

import re          # for pattern matching (e.g. spotting IP addresses)
import sys         # for reading command-line arguments
from urllib.parse import urlparse  # for splitting a URL into its parts


# --- Red-flag lists ---------------------------------------------------------
# These are small "threat intel" lists baked into the tool. A real SOC would
# pull them from a feed, but hard-coding a few teaches the concept.

SUSPICIOUS_TLDS = {
    # Top-level domains abused heavily by phishers / scammers.
    ".xyz", ".top", ".club", ".loan", ".click", ".work", ".support",
    ".gq", ".ml", ".tk", ".cf", ".ga", ".buzz",
}

BRAND_NAMES = [
    # Big brands attackers love to impersonate.
    "paypal", "apple", "microsoft", "amazon", "netflix", "google",
    "bankofamerica", "wellsfargo", "chase", "facebook", "instagram",
]

URL_SHORTENERS = {
    # Shortened links hide the real destination — always worth a closer look.
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorturl.at",
}


def extract_host(url):
    """Pull the hostname (the 'website name' part) out of a URL."""
    url = url.strip()
    if not url:
        return "", "", None
    # Add a scheme if the user gave a bare domain like "example.com".
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.hostname or "", url, parsed


def check_url(url):
    """
    Score one URL. Returns (score, reasons, verdict).

    Each suspicious trait adds points. The more points, the riskier the link.
    """
    host, full_url, parsed = extract_host(url)
    score = 0
    reasons = []

    # 1. Not using HTTPS? Traffic to the site isn't encrypted.
    if full_url.startswith("http://"):
        score += 1
        reasons.append("uses HTTP instead of HTTPS (traffic not encrypted)")

    # 2. Host is a raw IP address instead of a domain name?
    #    Legit sites almost never do this; phishers love it.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 3
        reasons.append("host is a raw IP address, not a domain name")

    # 3. Punycode / internationalized domain (xn--)? Classic trick to make a
    #    fake domain *look* like a real one.
    if "xn--" in host:
        score += 2
        reasons.append("punycode domain (can visually mimic a trusted site)")

    # 4. An "@" before the path? Browsers treat everything before "@" as a
    #    username, so http://paypal.com@evil.com actually goes to evil.com.
    #    urlparse exposes this as parsed.username.
    if parsed is not None and parsed.username:
        score += 3
        reasons.append("'@' trick — real destination may differ from what's shown")

    # 5. Suspicious TLD?
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 2
            reasons.append(f"suspicious top-level domain '{tld}'")
            break

    # 6. Brand name in the URL but NOT the real domain?
    #    e.g. "paypal-login.xyz" uses the brand but isn't paypal.com.
    lowered = full_url.lower()
    for brand in BRAND_NAMES:
        if brand in lowered and not host.endswith(brand + ".com"):
            # Allow the real domain (paypal.com) — flag only lookalikes.
            score += 2
            reasons.append(f"imitates brand '{brand}' without being its real domain")
            break

    # 7. URL shortener hiding the destination?
    if host in URL_SHORTENERS:
        score += 1
        reasons.append("URL shortener hides the real destination")

    # 8. Lots of hyphens in the domain? Fake domains are often stuffed with
    #    hyphens: "secure-paypal-account-verify.xyz".
    if host.count("-") >= 3:
        score += 1
        reasons.append(f"many hyphens in domain ({host.count('-')}) — typical of fakes")

    # 9. Very long URL? Phishers pad links with junk to push the real host
    #    out of view on a small screen.
    if len(full_url) > 120:
        score += 1
        reasons.append(f"unusually long URL ({len(full_url)} chars)")

    # 10. Many subdomains? e.g. login.paypal.com.malicious.xyz
    #     More than 3 dots is a common deception pattern.
    if host.count(".") > 3:
        score += 1
        reasons.append("excessive subdomains — read the REAL domain (last two parts)")

    # --- Verdict ---
    if score >= 5:
        verdict = "HIGH RISK"
    elif score >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return score, reasons, verdict


def load_urls():
    """Get the URLs to check: from args, a file, or the sample list."""
    args = sys.argv[1:]

    if not args:
        # Default: check the sample file next to this script.
        return read_file("sample_urls.txt")

    if len(args) == 1 and args[0].endswith(".txt"):
        return read_file(args[0])

    # Otherwise treat each argument as a URL.
    return args


def read_file(path):
    """Read one URL per line, skipping blanks and '#' comments."""
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def main():
    print("=" * 60)
    print("PHISHING URL CHECKER — quick triage of suspicious links")
    print("=" * 60)

    try:
        urls = load_urls()
    except FileNotFoundError as e:
        print(f"Could not open file: {e.filename}")
        sys.exit(1)

    if not urls:
        print("No URLs to check.")
        return

    risky = 0
    for url in urls:
        score, reasons, verdict = check_url(url)
        print(f"\nURL:     {url}")
        print(f"Verdict: {verdict} (risk score {score})")
        if reasons:
            print("Red flags:")
            for r in reasons:
                print(f"  - {r}")
        else:
            print("  (no red flags found)")
        if verdict != "LOW RISK":
            risky += 1

    print("\n" + "=" * 60)
    print(f"Checked {len(urls)} URL(s): {risky} flagged for investigation.")
    print("Tip: the real domain is the LAST two parts before the TLD.")
    print("=" * 60)


if __name__ == "__main__":
    main()
