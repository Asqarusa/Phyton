#!/usr/bin/env python3
"""
Suspicious Domain Detector (DGA Spotter) — day-23 (improved 2026-11-17)
------------------------------------------------------------------------
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

What's new in this version (2026-11-17):
  * Proper --help CLI (argparse): --demo, --file, --json, --min-score,
    --whitelist, --quiet, --top. A bare filename still works as before.
  * Two new checks: no-vowel names and punycode (xn--) lookalikes.
  * Input validation: junk input gets an INVALID verdict instead of a
    misleading score, with a plain-English explanation.
  * Whitelist support: known-good domains (--whitelist file) are
    reported CLEAN and never raise an alert.
  * Smarter summary: worst offenders, most-flagged TLD, and a
    "possible DGA family" hint when several flagged domains share a TLD.
  * Exit codes: 0 = all clean, 1 = something flagged, 2 = usage error.

Usage:
    python3 dga_domain_detector.py --demo
    python3 dga_domain_detector.py --file sample_domains.txt
    python3 dga_domain_detector.py sample_domains.txt   # bare file still works
    python3 dga_domain_detector.py google.com xkqzptmwbvdr1234.top
    python3 dga_domain_detector.py --demo --json
    python3 dga_domain_detector.py --file dns_log.txt --whitelist sample_whitelist.txt
"""

import argparse
import json
import math
import re
import sys

# TLDs that show up disproportionately in malicious registrations.
# (Being on this list does NOT make a domain bad — it just adds a few points.)
RISKY_TLDS = {
    "xyz", "top", "info", "buzz", "click", "loan", "win", "bid",
    "gdn", "sbs", "quest", "rest", "date", "faith", "zip", "mov",
}

VOWELS = set("aeiou")

# A domain label (the bit between two dots) may only contain letters,
# digits and hyphens, may not start or end with a hyphen, and is 1-63
# characters long. Anything else is not a domain at all.
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


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


def validate_domain(domain):
    """Check the shape of a domain; return an error string or None.

    Catches typos and junk before scoring so a bad input gets an
    honest INVALID verdict instead of a made-up score.
    """
    if not domain:
        return "empty input"
    if len(domain) > 253:
        return f"too long ({len(domain)} chars; max 253)"
    if " " in domain or "_" in domain:
        return "contains spaces or underscores (not allowed in domains)"
    if domain.startswith(".") or domain.endswith(".") and domain != domain.rstrip("."):
        return "starts or ends with a dot"
    if ".." in domain:
        return "contains an empty label (..)"
    if "." not in domain.rstrip("."):
        return "no dot — a domain needs at least a name and a TLD"
    labels = domain.rstrip(".").split(".")
    for label in labels:
        if not LABEL_RE.match(label):
            return f"bad label '{label}' (letters, digits and hyphens only)"
    if not labels[-1].isalpha():
        return f"TLD '.{labels[-1]}' is not letters-only"
    return None


def score_domain(domain):
    """Score one domain 0-100 and explain which checks fired.

    Returns (score, verdict, reasons). Higher = more suspicious.
    Verdicts: CLEAN / SUSPICIOUS / LIKELY DGA / INVALID.
    """
    domain = domain.strip().lower().rstrip(".")
    reasons = []

    problem = validate_domain(domain)
    if problem is not None:
        return 0, "INVALID", [f"not a valid domain: {problem}"]

    # Split off the TLD ("top" in "evil.top") and work on the name itself.
    parts = domain.split(".")
    tld = parts[-1] if parts else ""
    name = ".".join(parts[:-1]) if len(parts) > 1 else domain
    bare = name.replace(".", "").replace("-", "")  # letters+digits only

    score = 0

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

    # 8. NEW: almost no vowels — human words need vowels to be
    # pronounceable; a long name with (nearly) none is a DGA tell.
    letters = [ch for ch in bare if ch.isalpha()]
    if len(letters) >= 8:
        vowel_ratio = sum(ch in VOWELS for ch in letters) / len(letters)
        if vowel_ratio == 0:
            score += 10
            reasons.append(f"no vowels in {len(letters)} letters: +10")
        elif vowel_ratio < 0.1:
            score += 5
            reasons.append(f"almost no vowels ({vowel_ratio:.0%}): +5")

    # 9. NEW: punycode (xn--) labels — the trick behind lookalike
    # domains ("g00gle" with a Cyrillic 'o'). Real sites rarely need it.
    if any(label.startswith("xn--") for label in parts):
        score += 10
        reasons.append("punycode (xn--) label — possible lookalike: +10")

    # Verdict bands (kept deliberately simple).
    if score >= 60:
        verdict = "LIKELY DGA"
    elif score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return min(score, 100), verdict, reasons


def load_lines(path):
    """Read one-domain-per-line from a file, skipping blanks and # comments."""
    try:
        with open(path, encoding="utf-8") as fh:
            return [line.strip() for line in fh
                    if line.strip() and not line.lstrip().startswith("#")]
    except FileNotFoundError:
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"[!] Could not read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


DEMO_DOMAINS = [
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
    "qwrtypsdfghjk.xyz",          # NEW: no vowels at all
    "xn--g00gle-9ya.com",         # NEW: punycode lookalike
]


def parse_args(argv):
    """Command-line flags, with plain-English help text."""
    parser = argparse.ArgumentParser(
        description="Score domain names for how machine-generated (DGA) they look. "
                    "Offline, read-only — it only analyzes the text you give it.",
        epilog="Exit codes: 0 = all clean, 1 = something flagged, "
               "2 = usage or file error.",
    )
    parser.add_argument("domains", nargs="*", metavar="DOMAIN",
                        help="domain(s) to check, or a single file of domains "
                             "(one per line)")
    parser.add_argument("--demo", action="store_true",
                        help="check the built-in mixed sample list")
    parser.add_argument("--file", metavar="PATH",
                        help="read domains from a file (one per line)")
    parser.add_argument("--whitelist", metavar="PATH",
                        help="file of known-good domains (one per line); "
                             "they are reported CLEAN and never flagged")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON instead of a table")
    parser.add_argument("--min-score", type=int, default=0, metavar="N",
                        help="only show domains scoring N or higher (default: 0)")
    parser.add_argument("--top", type=int, default=0, metavar="N",
                        help="only show the N worst-scoring domains")
    parser.add_argument("--quiet", action="store_true",
                        help="only print flagged domains and the summary")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.min_score < 0 or args.min_score > 100:
        print("[!] --min-score must be between 0 and 100.", file=sys.stderr)
        return 2
    if args.top < 0:
        print("[!] --top must be 0 or more.", file=sys.stderr)
        return 2

    # Figure out where the domains come from.
    if args.demo:
        domains, source = list(DEMO_DOMAINS), "built-in demo list"
    elif args.file:
        domains, source = load_lines(args.file), f"file {args.file}"
    elif len(args.domains) == 1:
        # A single argument that is an existing file is read as a file,
        # so the original usage (script.py sample_domains.txt) keeps working.
        try:
            with open(args.domains[0], encoding="utf-8") as fh:
                domains = [line.strip() for line in fh
                           if line.strip() and not line.lstrip().startswith("#")]
            source = f"file {args.domains[0]}"
        except FileNotFoundError:
            domains, source = args.domains, "command-line arguments"
        except OSError as exc:
            print(f"[!] Could not read {args.domains[0]}: {exc}", file=sys.stderr)
            return 2
    elif args.domains:
        domains, source = args.domains, "command-line arguments"
    else:
        print("No domains to check. Try: python3 dga_domain_detector.py --demo",
              file=sys.stderr)
        return 2

    if not domains:
        print("[!] No domains found in the input.", file=sys.stderr)
        return 2

    whitelist = set()
    if args.whitelist:
        whitelist = {d.strip().lower().rstrip(".")
                     for d in load_lines(args.whitelist)}

    results = []
    for domain in domains:
        clean = domain.strip().lower().rstrip(".")
        if clean in whitelist:
            results.append({"domain": domain, "score": 0, "verdict": "CLEAN",
                            "reasons": ["on whitelist (known good): score 0"],
                            "whitelisted": True})
            continue
        score, verdict, reasons = score_domain(domain)
        results.append({"domain": domain, "score": score, "verdict": verdict,
                        "reasons": reasons, "whitelisted": False})

    # --min-score and --top filter what is shown, not what is counted.
    shown = [r for r in results if r["score"] >= args.min_score]
    if args.top:
        shown = sorted(shown, key=lambda r: r["score"], reverse=True)[:args.top]

    counts = {"CLEAN": 0, "SUSPICIOUS": 0, "LIKELY DGA": 0, "INVALID": 0}
    for r in results:
        counts[r["verdict"]] += 1

    if args.json:
        print(json.dumps({"source": source, "counts": counts,
                          "results": shown}, indent=2))
    else:
        if not args.quiet:
            print(f"Suspicious Domain Detector — checking {len(domains)} domains "
                  f"({source})\n")
            print(f"{'DOMAIN':<42}{'SCORE':<8}{'VERDICT'}")
            print("-" * 66)
        for r in shown:
            if args.quiet and r["verdict"] == "CLEAN":
                continue
            print(f"{r['domain']:<42}{r['score']:<8}{r['verdict']}")
            for reason in r["reasons"]:
                print(f"    -> {reason}")

        print("\nSummary:", ", ".join(f"{v}: {counts[v]}" for v in counts))

        flagged = [r for r in results if r["verdict"] in ("SUSPICIOUS", "LIKELY DGA")]
        if flagged:
            worst = sorted(flagged, key=lambda r: r["score"], reverse=True)[:3]
            print("\nWorst offenders:")
            for r in worst:
                print(f"  {r['score']:>3}  {r['domain']} ({r['verdict']})")
            # DGA families reuse one TLD for many names — if several flagged
            # domains share a TLD, say so: that is a lead worth chasing.
            tld_counts = {}
            for r in flagged:
                tld = r["domain"].rsplit(".", 1)[-1].lower()
                tld_counts[tld] = tld_counts.get(tld, 0) + 1
            top_tld, top_n = max(tld_counts.items(), key=lambda kv: kv[1])
            if top_n >= 3:
                print(f"\n[!] {top_n} flagged domains share .{top_tld} — "
                      "possible DGA family generating names on one TLD. "
                      "Check which host queried them and when.")

        if counts["INVALID"]:
            print(f"\nNote: {counts['INVALID']} input(s) were not valid domains "
                  "— fix the spelling before trusting any score for them.")

        print("\nSOC next steps for anything SUSPICIOUS or LIKELY DGA:")
        print("  1. Check your DNS/firewall logs: which internal host asked for it, and when.")
        print("  2. If one host queries many flagged domains, isolate it and scan it.")
        print("  3. Confirm before blocking — high scores are leads, not proof.")
        print("  4. Track repeat offenders: DGA families generate new names daily.")

    # Exit code: 1 if anything was flagged, 0 if all clean, 2 on errors.
    if counts["SUSPICIOUS"] or counts["LIKELY DGA"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
