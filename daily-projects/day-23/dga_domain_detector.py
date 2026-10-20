#!/usr/bin/env python3
"""
Suspicious Domain Detector (DGA Spotter) — day-23
------------------------------------------------
A beginner-friendly SOC-style tool that scores domain names for how
"machine-generated" they look.

The big idea: real domain names are made for humans to remember
(google.com, github.com). Malware often does the opposite — it uses a
Domain Generation Algorithm (DGA) to invent thousands of random-looking
domains per day (like "xkqzptmwbvdr1234.top") and tries to phone home to
whichever one the attacker registered. Spotting those random-looking
names in DNS logs is a core SOC analyst skill.

This script is 100% offline and read-only: it only analyzes the text
of the domain names you feed it. It never queries DNS, never visits
any site, and never contacts the network.

Usage:
    python3 dga_domain_detector.py --demo            # built-in sample list
    python3 dga_domain_detector.py sample_domains.txt  # your own file (one domain per line)
    python3 dga_domain_detector.py google.com xkqzptmwbvdr1234.top  # direct arguments
"""

import math
import sys

# TLDs that show up disproportionately in malicious registrations.
# (Being on this list does NOT make a domain bad — it just adds a few points.)
RISKY_TLDS = {
    "xyz", "top", "info", "buzz", "click", "loan", "win", "bid",
    "gdn", "sbs", "quest", "rest", "date", "faith", "zip", "mov",
}

VOWELS = set("aeiou")


def shannon_entropy(text):
    """Measure how 'random' a string looks (bits per character).

    'aaaa' scores near 0 (totally predictable); a jumble of many
    different characters scores near 4-5. Human words usually land
    between 2 and 3.5; DGA names often push past 4.
    """
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def longest_consonant_run(text):
    """Longest streak of consonants in a row.

    Real words mix vowels and consonants ('google' has runs of 1-2).
    Random strings often stack 5+ consonants ('xkqzpt').
    """
    longest = 0
    current = 0
    for ch in text.lower():
        if ch.isalpha() and ch not in VOWELS:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def score_domain(domain):
    """Score one domain 0-100 and explain which checks fired.

    Returns (score, verdict, reasons). Higher = more suspicious.
    """
    domain = domain.strip().lower().rstrip(".")
    reasons = []
    score = 0

    # Split off the TLD ("top" in "evil.top") and work on the name itself.
    parts = domain.split(".")
    tld = parts[-1] if parts else ""
    name = ".".join(parts[:-1]) if len(parts) > 1 else domain
    bare = name.replace(".", "").replace("-", "")  # letters+digits only

    # 1. Length of the name — DGAs love long names to get enough randomness.
    if len(bare) > 18:
        score += 20
        reasons.append(f"very long name ({len(bare)} chars): +20")
    elif len(bare) > 12:
        score += 10
        reasons.append(f"long name ({len(bare)} chars): +10")

    # 2. Entropy — the core randomness test.
    entropy = shannon_entropy(bare)
    if entropy > 4.2:
        score += 25
        reasons.append(f"very high entropy ({entropy:.2f}): +25")
    elif entropy > 3.8:
        score += 12
        reasons.append(f"high entropy ({entropy:.2f}): +12")

    # 3. Digit ratio — humans rarely cram digits into names; DGAs do.
    digits = sum(ch.isdigit() for ch in bare)
    digit_ratio = digits / len(bare) if bare else 0
    if digit_ratio > 0.5:
        score += 15
        reasons.append(f"mostly digits ({digit_ratio:.0%}): +15")
    elif digit_ratio > 0.3:
        score += 8
        reasons.append(f"many digits ({digit_ratio:.0%}): +8")

    # 4. Hyphens — a couple are normal; a pile is a DGA/phishing habit.
    hyphens = name.count("-")
    if hyphens > 2:
        score += 10
        reasons.append(f"{hyphens} hyphens: +10")
    elif hyphens > 0:
        score += 5
        reasons.append(f"{hyphens} hyphen(s): +5")

    # 5. Subdomain depth — "a.b.c.d.evil.top" is weirder than "evil.top".
    depth = domain.count(".")
    if depth > 2:
        score += 10
        reasons.append(f"deep subdomains ({depth} dots): +10")

    # 6. Risky TLD — cheap, lightly-policed endings favored by abuse.
    if tld in RISKY_TLDS:
        score += 10
        reasons.append(f"abuse-prone TLD (.{tld}): +10")

    # 7. Consonant pile-ups — "xkqzpt" is not a human word.
    run = longest_consonant_run(bare)
    if run >= 6:
        score += 10
        reasons.append(f"{run}-consonant pile-up: +10")

    # Verdict bands (kept deliberately simple).
    if score >= 60:
        verdict = "LIKELY DGA"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return min(score, 100), verdict, reasons


def load_domains(args):
    """Figure out where the domains come from: --demo, a file, or args."""
    if "--demo" in args:
        return [
            "google.com",
            "github.com",
            "wikipedia.org",
            "xkqzptmwbvdr1234.top",
            "q7f2k9d4m1x8z3.xyz",
            "login-secure-verify-account-8891.info",
            "microsoft.com",
            "bvcrtdxplmnqswz19.buzz",
            "a.b.c.d.tracker-data.click",
            "example.com",
            "k7q9z2w4x6v8b1d3p5f0rtw19zx.xyz",
        ], "built-in demo list"
    if len(args) == 2 and not args[1].startswith("-"):
        path = args[1]
        try:
            with open(path, encoding="utf-8") as fh:
                domains = [line.strip() for line in fh
                           if line.strip() and not line.startswith("#")]
            return domains, f"file {path}"
        except FileNotFoundError:
            print(f"[!] File not found: {path}")
            sys.exit(1)
    # Otherwise treat every argument as a domain to check.
    domains = [a for a in args[1:] if not a.startswith("-")]
    return domains, "command-line arguments"


def main():
    domains, source = load_domains(sys.argv)
    if not domains:
        print("No domains to check. Try: python3 dga_domain_detector.py --demo")
        sys.exit(0)

    print(f"Suspicious Domain Detector — checking {len(domains)} domains ({source})\n")
    print(f"{'DOMAIN':<42}{'SCORE':<8}{'VERDICT'}")
    print("-" * 66)

    counts = {"CLEAN": 0, "SUSPICIOUS": 0, "LIKELY DGA": 0}
    for domain in domains:
        score, verdict, reasons = score_domain(domain)
        counts[verdict] += 1
        print(f"{domain:<42}{score:<8}{verdict}")
        for reason in reasons:
            print(f"    -> {reason}")

    print("\nSummary:", ", ".join(f"{v}: {counts[v]}" for v in counts))
    print("\nSOC next steps for anything SUSPICIOUS or LIKELY DGA:")
    print("  1. Check your DNS/firewall logs: which internal host asked for it, and when.")
    print("  2. If one host queries many flagged domains, isolate it and scan it.")
    print("  3. Confirm before blocking — high scores are leads, not proof.")
    print("  4. Track repeat offenders: DGA families generate new names daily.")


if __name__ == "__main__":
    main()
