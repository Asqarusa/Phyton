#!/usr/bin/env python3
"""
Phishing URL Checker — a tiny SOC-style triage tool (improved).

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
    python3 phishing_url_checker.py my_urls.txt       # checks your own file
    python3 phishing_url_checker.py https://example.com  # checks one URL
    python3 phishing_url_checker.py --json my_urls.txt   # machine-readable output
"""

import argparse  # for friendly command-line options
import json      # for the optional --json report
import re        # for pattern matching (e.g. spotting IP addresses)
import sys       # for clean exits on errors
from urllib.parse import urlparse  # for splitting a URL into its parts


# --- Red-flag lists ---------------------------------------------------------
# These are small "threat intel" lists baked into the tool. A real SOC would
# pull them from a feed, but hard-coding a few teaches the concept.

SUSPICIOUS_TLDS = {
    # Top-level domains abused heavily by phishers / scammers.
    ".xyz", ".top", ".club", ".loan", ".click", ".work", ".support",
    ".gq", ".ml", ".tk", ".cf", ".ga", ".buzz", ".sbs", ".quest",
}

BRAND_NAMES = [
    # Big brands attackers love to impersonate.
    "paypal", "apple", "microsoft", "amazon", "netflix", "google",
    "bankofamerica", "wellsfargo", "chase", "facebook", "instagram",
    "linkedin", "ebay", "walmart",
]

URL_SHORTENERS = {
    # Shortened links hide the real destination — always worth a closer look.
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "shorturl.at", "rebrand.ly", "cutt.ly",
}

LURE_WORDS = {
    # Words attackers sprinkle into fake URLs to create urgency or trust.
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "suspend", "locked", "urgent", "prize",
    "winner", "free", "signin", "recover",
}


def levenshtein(a, b):
    """Count how many single-character edits turn word `a` into word `b`.

    Example: levenshtein("paypa1", "paypal") == 1 (one character changed).
    This is how we catch "typosquat" domains that are one keystroke off
    from a real brand — invisible to a tired eye, obvious to the math.
    """
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insert = previous[j] + 1
            delete = current[j - 1] + 1
            replace = previous[j - 1] + (char_a != char_b)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def registered_domain(host):
    """The 'core' of the domain: the last two parts (e.g. 'evil.club')."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return host.lower()


def is_encoded_ip(host):
    """Catch IP addresses written in disguise: hex (0xC0.0xA8.0x1.0x1),
    octal (0300.0250.0001.0001), or one giant integer (3232235777).
    Attackers use these to dodge the plain-IP check."""
    pieces = host.split(".")
    if len(pieces) == 4 and all(
        re.fullmatch(r"(0x[0-9a-fA-F]+|0[0-7]+|\d+)", p) for p in pieces
    ):
        return True
    return bool(re.fullmatch(r"\d{8,10}", host))  # one big integer


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
    Score one URL. Returns (score, findings, verdict).

    `findings` is a list of (points, reason) so the report shows exactly
    where each point came from — an analyst always documents their reasoning.
    """
    host, full_url, parsed = extract_host(url)
    findings = []

    def add(points, reason):
        findings.append((points, reason))

    # Reject junk input early: a hostname can only hold letters, digits,
    # dots and hyphens. ("not a url" is not something to score — it's broken.)
    if not re.fullmatch(r"[A-Za-z0-9_.\-:]+", host):
        return 0, [(0, "could not parse a hostname — check the URL")], "INVALID"
    if not host:
        return 0, [(0, "could not parse a hostname — check the URL")], "INVALID"

    # 1. Not using HTTPS? Traffic to the site isn't encrypted.
    if full_url.startswith("http://"):
        add(1, "uses HTTP instead of HTTPS (traffic not encrypted)")

    # 2. Host is a raw IP address instead of a domain name?
    #    Legit sites almost never do this; phishers love it.
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add(3, "host is a raw IP address, not a domain name")
    elif is_encoded_ip(host):
        # 3. ...or an IP in disguise (hex / octal / single integer).
        add(3, "host is an IP address in disguise (encoded/obfuscated)")

    # 4. Punycode / internationalized domain (xn--)? Classic trick to make a
    #    fake domain *look* like a real one.
    if "xn--" in host:
        add(2, "punycode domain (can visually mimic a trusted site)")

    # 5. An "@" before the path? Browsers treat everything before "@" as a
    #    username, so http://paypal.com@evil.com actually goes to evil.com.
    #    urlparse exposes this as parsed.username.
    if parsed is not None and parsed.username:
        add(3, "'@' trick — real destination may differ from what's shown")

    # 6. Suspicious TLD?
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            add(2, f"suspicious top-level domain '{tld}'")
            break

    # 7. Typosquat: part of the domain is one keystroke off a real brand?
    #    paypa1.com looks like paypal.com to a tired eye — not to the math.
    #    We check the core domain AND each hyphen-separated piece, because
    #    attackers hide misspellings inside longer names ("micros0ft-verify").
    core = registered_domain(host)
    tokens = {core} | set(core.split("-"))
    for brand in BRAND_NAMES:
        hit = next((t for t in tokens if t != brand and levenshtein(t, brand) <= 1), None)
        if hit:
            add(3, f"typosquatting: '{hit}' is one keystroke from brand '{brand}'")
            break

    # 8. Brand name in the URL but NOT the real domain?
    #    e.g. "paypal-login.xyz" uses the brand but isn't paypal.com.
    lowered = full_url.lower()
    for brand in BRAND_NAMES:
        if brand in lowered and not host.endswith(brand + ".com"):
            # Allow the real domain (paypal.com) — flag only lookalikes.
            add(2, f"imitates brand '{brand}' without being its real domain")
            break

    # 9. URL shortener hiding the destination?
    if host in URL_SHORTENERS:
        add(1, "URL shortener hides the real destination")

    # 10. Lure words in the URL (urgent, verify, prize...)? Attackers bait
    #     victims with language that triggers fear or greed.
    found_lures = sorted({w for w in LURE_WORDS if w in lowered})
    if found_lures:
        add(1, f"lure words present: {', '.join(found_lures)}")

    # 11. Lots of hyphens in the domain? Fake domains are often stuffed with
    #     hyphens: "secure-paypal-account-verify.xyz".
    if host.count("-") >= 3:
        add(1, f"many hyphens in domain ({host.count('-')}) — typical of fakes")

    # 12. Very long URL? Phishers pad links with junk to push the real host
    #     out of view on a small screen.
    if len(full_url) > 120:
        add(1, f"unusually long URL ({len(full_url)} chars)")

    # 13. Many subdomains? e.g. login.paypal.com.malicious.xyz
    #     More than 3 dots is a common deception pattern.
    if host.count(".") > 3:
        add(1, "excessive subdomains — read the REAL domain (last two parts)")

    # 14. Non-standard port? Legit sites live on 80/443; weird ports like
    #     :8080 or :4443 on a sketchy host are worth a second look.
    if parsed is not None and parsed.port and parsed.port not in (80, 443):
        add(1, f"non-standard port {parsed.port} in URL")

    score = sum(points for points, _ in findings)

    # --- Verdict ---
    if score >= 5:
        verdict = "HIGH RISK"
    elif score >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return score, findings, verdict


def read_file(path):
    """Read one URL per line, skipping blanks and '#' comments."""
    urls = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except FileNotFoundError:
        print(f"Error: could not find the file '{path}'.")
        print("Pass a file with one URL per line, or a URL directly.")
        sys.exit(1)
    except OSError as e:
        print(f"Error: could not read '{path}': {e}")
        sys.exit(1)
    return urls


def load_urls(args):
    """Get the URLs to check: from args, a file, or the sample list."""
    if not args.urls:
        # Default: check the sample file next to this script.
        return read_file("sample_urls.txt")

    if len(args.urls) == 1 and args.urls[0].endswith(".txt"):
        return read_file(args.urls[0])

    # Otherwise treat each argument as a URL.
    return args.urls


def print_report(results):
    """Human-friendly report: one verdict block per URL + batch summary."""
    print("=" * 60)
    print("PHISHING URL CHECKER — quick triage of suspicious links")
    print("=" * 60)

    verdict_counts = {"HIGH RISK": 0, "SUSPICIOUS": 0, "LOW RISK": 0, "INVALID": 0}
    flag_tally = {}  # how many times each red flag fired across the batch

    for url, (score, findings, verdict) in results:
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        print(f"\nURL:     {url}")
        print(f"Verdict: {verdict} (risk score {score})")
        if findings:
            print("Red flags:")
            for points, reason in findings:
                print(f"  - {reason}  (+{points})")
                flag_tally[reason] = flag_tally.get(reason, 0) + 1
        else:
            print("  (no red flags found)")

    print("\n" + "=" * 60)
    total = len(results)
    flagged = total - verdict_counts.get("LOW RISK", 0)
    print(f"Checked {total} URL(s): "
          f"{verdict_counts.get('HIGH RISK', 0)} high risk, "
          f"{verdict_counts.get('SUSPICIOUS', 0)} suspicious, "
          f"{verdict_counts.get('LOW RISK', 0)} low risk, "
          f"{verdict_counts.get('INVALID', 0)} invalid "
          f"({flagged} flagged for investigation).")

    if flag_tally:
        print("\nMost common red flags this run:")
        for reason, count in sorted(flag_tally.items(), key=lambda kv: -kv[1])[:5]:
            print(f"  {count}x — {reason}")

    print("\nTip: the real domain is the LAST two parts before the TLD.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Score URLs for phishing red flags (safe: never visits them).")
    parser.add_argument("urls", nargs="*",
                        help="URLs to check, or one .txt file with one URL per line")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of the text report")
    args = parser.parse_args()

    urls = load_urls(args)
    if not urls:
        print("No URLs to check.")
        return

    results = [(url, check_url(url)) for url in urls]

    if args.json:
        payload = [
            {
                "url": url,
                "verdict": verdict,
                "risk_score": score,
                "red_flags": [{"points": p, "reason": r} for p, r in findings],
            }
            for url, (score, findings, verdict) in results
        ]
        print(json.dumps(payload, indent=2))
    else:
        print_report(results)


if __name__ == "__main__":
    main()
