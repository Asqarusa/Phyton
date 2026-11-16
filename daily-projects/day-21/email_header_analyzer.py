#!/usr/bin/env python3
"""
Email Header Analyzer — a SOC analyst's first look at a suspicious email (day-21).

Beginner-friendly, fully offline, standard-library-only.
Point it at a raw .eml file (File -> Save in most mail apps) and it reads the
"return address label" on the envelope — the headers — to spot common
phishing tells:

  1. From / Reply-To / Return-Path mismatches   ("who do replies really go to?")
  2. Display-name spoofing                     ("the nameplate lies")
  3. Received-chain anomalies                  ("which post offices handled it?")
  4. Authentication-Results                     ("the wax seal: SPF / DKIM / DMARC")
  5. Link-text vs link-target mismatch          ("the label says one door, opens another")
  6. Urgency language in the subject            ("ACT NOW!!!" pressure tactics)
  7. Message-ID domain mismatch                 ("the postmark disagrees with the letterhead")
  8. Attachments, especially risky file types   ("what's taped to the envelope?")

What's new in this version (2026-11-13):
  * Full argparse CLI: --demo runs all three samples with a summary table,
    --json prints a machine-readable report, --quiet prints just the verdict.
  * Two new checks: Message-ID domain vs From domain, and attachments
    (executable file types like .exe/.scr/.bat are flagged).
  * Per-mechanism SPF/DKIM/DMARC verdicts are shown for every message
    (pass/fail/missing), not only when something fails.
  * "No Received stamps at all" is now flagged — real mail always has stamps.
  * Exit codes mean something: 0 = CLEAN, 1 = SUSPICIOUS or LIKELY PHISHING,
    2 = usage error (missing file, unreadable file, bad flag).
  * Friendlier errors: a missing file, a directory, or an empty/garbled file
    now gets a plain-English message instead of a Python traceback.
  * A third sample, sample_bec.eml, shows a business-email-compromise style
    message: the envelope looks perfect, but replies are quietly hijacked.

Usage:
    python3 email_header_analyzer.py sample_phishing.eml
    python3 email_header_analyzer.py --demo
    python3 email_header_analyzer.py suspicious.eml --json
    python3 email_header_analyzer.py suspicious.eml --quiet

Everything here is read-only and safe: it only READS files you give it,
never sends mail, never touches the network.
"""

import argparse
import json
import os
import re
import sys
from email import policy
from email.parser import BytesParser

# ---------------------------------------------------------------------------
# The "smell test" lists: patterns attackers reuse, in plain regex.
# ---------------------------------------------------------------------------

# Words that pressure the reader to act without thinking.
URGENCY_WORDS = [
    "urgent", "immediately", "suspend", "suspended", "verify", "locked",
    "expire", "expired", "action required", "final notice", "unauthorized",
    "confirm now", "update now",
]

# Brands attackers love to impersonate, and the real domain each one owns.
# (Name in the display name -> domain the address should actually belong to.)
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "coinbase": "coinbase.com",
    "bank": None,          # any bank name: just needs a plausible bank domain
    "irs": None,
    "usps": "usps.com",
    "fedex": "fedex.com",
}

# File types that should never arrive unannounced in an email attachment.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".msi",
    ".com", ".pif", ".jar", ".hta",
}

# How "phishy" the whole message is: findings add weight, score decides verdict.
WEIGHTS = {
    "reply_to_mismatch": 25,     # Replies go somewhere OTHER than the sender
    "return_path_mismatch": 25,  # Envelope sender differs from From
    "display_name_spoof": 20,    # Nameplate doesn't match the address behind it
    "auth_failed": 20,           # SPF/DKIM/DMARC says "not really from them"
    "link_mismatch": 20,         # Clickable label points somewhere else
    "risky_attachment": 15,      # An executable-type file is attached
    "message_id_mismatch": 10,   # Message-ID domain disagrees with From domain
    "no_received": 10,           # No mail-server stamps at all — odd for real mail
    "external_first_hop": 10,    # First mail server is outside a mail provider
    "urgency": 10,               # Pressure language in the subject
}

SAMPLE_FILES = ["sample_phishing.eml", "sample_legit.eml", "sample_bec.eml"]


def addr_of(header_value):
    """Pull just the email address out of a header like 'Name <name@domain>'."""
    if not header_value:
        return ""
    match = re.search(r"[\w.+-]+@[\w.-]+\.[\w.-]+", str(header_value))
    return match.group(0).lower() if match else ""


def domain_of(address):
    """'billing@paypa1-verify.example' -> 'paypa1-verify.example'."""
    return address.split("@", 1)[1] if "@" in address else ""


def display_name_of(header_value):
    """The human name shown in the inbox: 'PayPal Support' <...>."""
    if not header_value:
        return ""
    text = str(header_value).strip()
    if text.startswith('"'):
        match = re.match(r'"([^"]+)"', text)
        return match.group(1) if match else ""
    if "<" in text:                       # Name <address>  -> the part before <
        return text.split("<", 1)[0].strip().strip('"')
    return ""


def analyze(path):
    """Read one .eml file and return (report dict, exit code).

    The report dict holds everything the text and --json outputs need:
    details (plain-English trace), findings (weight + text), auth verdicts,
    attachments, score and verdict. Raises ValueError with a friendly
    message when the file cannot be read or parsed at all.
    """
    if not os.path.exists(path):
        raise ValueError("No such file: %s — check the spelling and try again." % path)
    if os.path.isdir(path):
        raise ValueError("'%s' is a folder, not an email file — pass a .eml file." % path)
    if os.path.getsize(path) == 0:
        raise ValueError("'%s' is empty — nothing to analyze." % path)

    try:
        with open(path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except (OSError, ValueError) as exc:
        raise ValueError("Could not read '%s' (%s)." % (path, exc))

    if not msg["From"] and not msg["Subject"] and not msg.get_all("Received", []):
        raise ValueError("'%s' does not look like an email — no From, Subject "
                         "or Received headers found. Is it a .eml file?" % path)

    findings = []          # (weight, message) pairs
    details = []           # plain-English trace of what was checked
    auth_verdicts = {}     # "spf" -> "pass"/"fail"/"missing", etc.
    attachments = []       # (filename, content-type) pairs

    def check(weight, text):
        findings.append((WEIGHTS[weight], text))

    from_h, reply_h, return_h = msg["From"], msg["Reply-To"], msg["Return-Path"]
    from_addr, reply_addr, return_addr = addr_of(from_h), addr_of(reply_h), addr_of(return_h)

    details.append("From:        %s" % (from_h or "(missing)"))
    details.append("Reply-To:    %s" % (reply_h or "(none set)"))
    details.append("Return-Path: %s" % (return_h or "(missing)"))
    details.append("Subject:     %s" % (msg["Subject"] or "(missing)"))
    details.append("Date:        %s" % (msg["Date"] or "(missing)"))

    # --- Check 1 & 2: does the envelope agree with the letterhead? -----------
    # Legit mail: From, Reply-To and Return-Path usually agree (or Reply-To is
    # simply absent). Phishing: From says "PayPal", but replies quietly go to
    # an attacker-controlled inbox.
    if reply_addr and reply_addr != from_addr and domain_of(reply_addr) != domain_of(from_addr):
        check("reply_to_mismatch",
              "Reply-To (%s) differs from From (%s) — replies would go to a different party."
              % (reply_addr, from_addr))
    if return_addr and from_addr and return_addr != from_addr \
            and domain_of(return_addr) != domain_of(from_addr):
        check("return_path_mismatch",
              "Return-Path (%s) differs from From (%s) — the mail came from a different envelope sender."
              % (return_addr, from_addr))

    # --- Check 3: display-name spoofing -------------------------------------
    # The inbox shows the NAME in big letters and hides the address.
    # If the name claims a brand but the address has nothing to do with it, flag it.
    name = display_name_of(from_h)
    from_dom = domain_of(from_addr)
    if name and from_addr:
        claimed = [brand for brand in BRAND_DOMAINS if brand in name.lower()]
        if claimed:
            real = [BRAND_DOMAINS[b] for b in claimed if BRAND_DOMAINS[b]]
            if real and not any(from_dom == d or from_dom.endswith("." + d) for d in real):
                check("display_name_spoof",
                      "Display name '%s' claims a well-known brand, but the address is %s."
                      % (name, from_addr))
            elif not real and not re.search(r"(?i)bank|irs|gov", from_dom):
                # "Bank"/"IRS" in the name but the address has no bank/gov hint.
                check("display_name_spoof",
                      "Display name '%s' claims a bank or the IRS, but the address is %s."
                      % (name, from_addr))

    # --- Check 4: the Received chain — which post offices handled this? ------
    # Every mail server stamps the message as it passes it along, newest first.
    # Read bottom-up to follow the journey: sender -> ... -> you.
    received = msg.get_all("Received", [])
    details.append("\nReceived hops (%d):" % len(received))
    for i, hop in enumerate(reversed(received), 1):
        one_line = " ".join(str(hop).split())
        details.append("  hop %d: %s" % (i, one_line[:140]))
    if not received:
        check("no_received",
              "No Received stamps at all — real mail always carries at least one "
              "server stamp; this message may have been forged by hand.")
    else:
        first_hop = " ".join(str(received[-1]).split())   # oldest = closest to sender
        ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", first_hop)
        if ip_match and not ip_match.group(1).startswith(("10.", "192.168.", "172.16.")):
            details.append("  -> first hop originates from public IP %s" % ip_match.group(1))
            if "example" not in first_hop.lower() and "mail" not in first_hop.lower():
                check("external_first_hop",
                      "First mail server looks like an unfamiliar host, not a major mail provider.")

    # --- Check 5: authentication results — the wax seal -----------------------
    # SPF/DKIM/DMARC are DNS-published proofs. If a server checked them, it
    # writes the verdict in Authentication-Results. "fail" = the wax seal is broken.
    # New in this version: every mechanism's verdict is reported, pass or fail.
    auth = str(msg.get("Authentication-Results", "")).lower()
    if auth:
        details.append("\nAuthentication-Results present:")
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(mech + r"=(\w+)", auth)
            verdict = m.group(1) if m else "missing"
            auth_verdicts[mech] = verdict
            details.append("  %s: %s" % (mech.upper(), verdict))
            if verdict in ("fail", "softfail"):
                check("auth_failed", "%s check FAILED — the sender failed a legitimacy proof."
                      % mech.upper())
    else:
        auth_verdicts = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
        details.append("\nNo Authentication-Results header — no proof of sender legitimacy visible.")

    # --- Check 6: Message-ID domain vs From domain ---------------------------
    # The Message-ID is stamped by the sending server and usually ends in the
    # sender's domain. If it points somewhere else entirely, the letterhead
    # and the postmark disagree.
    msg_id = str(msg.get("Message-ID", "") or "")
    id_match = re.search(r"@([\w.-]+)>", msg_id)
    if id_match and from_dom:
        id_dom = id_match.group(1).lower()
        if id_dom != from_dom and not id_dom.endswith("." + from_dom) \
                and not from_dom.endswith("." + id_dom):
            check("message_id_mismatch",
                  "Message-ID domain (%s) disagrees with the From domain (%s)."
                  % (id_dom, from_dom))

    # --- Check 7: attachments -------------------------------------------------
    # List what is taped to the envelope. Executable file types (.exe, .scr,
    # .bat, ...) arriving unannounced are a classic malware-delivery tell.
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append((filename, part.get_content_type()))
    if attachments:
        details.append("\nAttachments (%d):" % len(attachments))
        for filename, ctype in attachments:
            ext = os.path.splitext(filename)[1].lower()
            details.append("  %s (%s)" % (filename, ctype))
            if ext in RISKY_EXTENSIONS:
                check("risky_attachment",
                      "Attachment '%s' is an executable file type (%s) — a common "
                      "malware-delivery trick; do not open it." % (filename, ext))

    # --- Check 8: do the clickable labels lie? --------------------------------
    # Classic trick: blue text says "paypal.com" but the link really goes to
    # an attacker's site. Compare what the eye sees with where the click goes.
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body += part.get_content() + "\n"
                except Exception:
                    pass
    else:
        try:
            body = str(msg.get_content())
        except Exception:
            body = ""
    for href, link_text in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', body, re.I | re.S):
        clean_text = re.sub(r"<[^>]+>", "", link_text).strip()
        text_dom = re.search(r"[\w.-]+\.[\w.-]+", clean_text)
        href_dom = re.search(r"https?://([\w.-]+)", href)
        if text_dom and href_dom and text_dom.group(0).lower() != href_dom.group(1).lower() \
                and re.search(r"\.", text_dom.group(0)):
            check("link_mismatch",
                  "Link text shows '%s' but the click goes to %s."
                  % (text_dom.group(0), href_dom.group(1)))

    # --- Check 9: pressure language ------------------------------------------
    subject = str(msg["Subject"] or "").lower()
    hits = sorted({w for w in URGENCY_WORDS if re.search(r"\b" + re.escape(w) + r"\b", subject)})
    if hits:
        check("urgency", "Subject uses pressure words: %s." % ", ".join(hits))

    # --- Verdict: add up the weights -----------------------------------------
    score = sum(w for w, _ in findings)
    if score >= 40:
        verdict, advice = "LIKELY PHISHING", \
            "Do NOT click, reply, or open attachments. Report it (phishing button / forward to your security team) and delete it."
    elif score >= 15:
        verdict, advice = "SUSPICIOUS", \
            "Treat with caution: verify through a separate channel (type the site address yourself, call the company) before acting."
    else:
        verdict, advice = "CLEAN (no common phishing tells found)", \
            "Still use common sense — this checks the envelope, not the letter's contents."

    report = {
        "file": path,
        "from": from_addr,
        "subject": str(msg["Subject"] or ""),
        "score": min(score, 100),
        "verdict": verdict,
        "advice": advice,
        "auth": auth_verdicts,
        "attachments": [{"filename": fn, "content_type": ct} for fn, ct in attachments],
        "findings": [{"weight": w, "text": t} for w, t in sorted(findings, reverse=True)],
        "details": details,
    }
    exit_code = 0 if score < 15 else 1
    return report, exit_code


def print_report(report, as_json=False, quiet=False):
    """Print one report as text (default), JSON, or verdict-only."""
    if quiet:
        print("%s (%d/100)" % (report["verdict"], report["score"]))
        return
    if as_json:
        report_out = {k: v for k, v in report.items() if k != "details"}
        print(json.dumps(report_out, indent=2))
        return

    print("=" * 64)
    print("EMAIL HEADER ANALYZER — report: %s" % report["file"])
    print("=" * 64)
    print("\n".join(report["details"]))

    print("\n--- Findings (%d) ---\n" % len(report["findings"]))
    for finding in report["findings"]:
        print("[+%d] %s" % (finding["weight"], finding["text"]))
    if not report["findings"]:
        print("(none — nothing phishy in the headers)")

    print("\n" + "-" * 64)
    print("Risk score: %d/100" % report["score"])
    print("Verdict:    %s" % report["verdict"])
    print("Next step:  %s" % report["advice"])


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyze an email's headers (.eml file) for phishing tells. "
                    "Fully offline — it only reads the file you give it.")
    parser.add_argument("file", nargs="?",
                        help="the .eml file to analyze (not needed with --demo)")
    parser.add_argument("--demo", action="store_true",
                        help="analyze the three bundled sample emails and print a summary table")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON instead of text")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the verdict and score")
    args = parser.parse_args(argv)

    if args.demo:
        rows = []
        worst = 0
        for name in SAMPLE_FILES:
            here = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
            if not os.path.exists(here):
                print("Demo sample missing: %s (run from the script's folder)" % name)
                return 2
            try:
                report, code = analyze(here)
            except ValueError as exc:
                print("Demo sample failed: %s" % exc)
                return 2
            rows.append((name, report["score"], report["verdict"]))
            worst = max(worst, code)
        print("%-22s %-8s %s" % ("FILE", "SCORE", "VERDICT"))
        print("-" * 64)
        for name, score, verdict in rows:
            print("%-22s %-8d %s" % (name, score, verdict))
        print("-" * 64)
        print("Worst sample verdict above. Run one file directly for the full report, e.g.:")
        print("  python3 email_header_analyzer.py sample_bec.eml")
        return worst

    if not args.file:
        parser.print_usage(sys.stderr)
        print("error: give me an .eml file to analyze, or use --demo to try the samples.",
              file=sys.stderr)
        return 2

    if not args.file.lower().endswith(".eml"):
        print("Note: '%s' does not end in .eml — analyzing it anyway." % args.file,
              file=sys.stderr)
    try:
        report, exit_code = analyze(args.file)
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2

    print_report(report, as_json=args.json, quiet=args.quiet)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
