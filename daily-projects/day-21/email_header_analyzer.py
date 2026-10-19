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

Usage:
    python3 email_header_analyzer.py sample_phishing.eml
    python3 email_header_analyzer.py my_suspicious_mail.eml

Everything here is read-only and safe: it only READS one file you give it,
never sends mail, never touches the network.
"""

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

# How "phishy" the whole message is: findings add weight, score decides verdict.
WEIGHTS = {
    "reply_to_mismatch": 25,     # Replies go somewhere OTHER than the sender
    "return_path_mismatch": 25,  # Envelope sender differs from From
    "display_name_spoof": 20,    # Nameplate doesn't match the address behind it
    "auth_failed": 20,           # SPF/DKIM/DMARC says "not really from them"
    "link_mismatch": 20,         # Clickable label points somewhere else
    "external_first_hop": 10,    # First mail server is outside a mail provider
    "urgency": 10,               # Pressure language in the subject
}

DOC_IP_RE = re.compile(r"\b(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.)\d{1,3}\b")


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
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    findings = []          # (weight, message) pairs
    details = []           # plain-English trace of what was checked

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
    if name and from_addr and re.search(r"(?i)paypal|apple|amazon|microsoft|google|bank|irs|netflix", name) \
            and not re.search(r"(?i)paypal\.com|apple\.com|amazon\.com|microsoft\.com|google\.com|netflix\.com",
                              from_dom):
        check("display_name_spoof",
              "Display name '%s' claims a well-known brand, but the address is %s."
              % (name, from_addr))

    # --- Check 4: the Received chain — which post offices handled this? ------
    # Every mail server stamps the message as it passes it along, newest first.
    # Read bottom-up to follow the journey: sender -> ... -> you.
    received = msg.get_all("Received", [])
    details.append("\nReceived hops (%d):" % len(received))
    for i, hop in enumerate(reversed(received), 1):
        one_line = " ".join(str(hop).split())
        details.append("  hop %d: %s" % (i, one_line[:140]))
    if received:
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
    auth = str(msg.get("Authentication-Results", "")).lower()
    if auth:
        details.append("\nAuthentication-Results present:")
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(mech + r"=(\w+)", auth)
            if m:
                details.append("  %s: %s" % (mech.upper(), m.group(1)))
                if m.group(1) in ("fail", "softfail"):
                    check("auth_failed", "%s check FAILED — the sender failed a legitimacy proof."
                          % mech.upper())
    else:
        details.append("\nNo Authentication-Results header — no proof of sender legitimacy visible.")

    # --- Check 6: do the clickable labels lie? --------------------------------
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

    # --- Check 7: pressure language ------------------------------------------
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
    return details, findings, score, verdict, advice


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 email_header_analyzer.py <message.eml>")
        print("Try:   python3 email_header_analyzer.py sample_phishing.eml")
        sys.exit(1)

    details, findings, score, verdict, advice = analyze(sys.argv[1])

    print("=" * 64)
    print("EMAIL HEADER ANALYZER — report")
    print("=" * 64)
    print("\n".join(details))

    print("\n--- Findings (%d) ---\n" % len(findings))
    for weight, text in sorted(findings, reverse=True):
        print("[+%d] %s" % (weight, text))
    if not findings:
        print("(none — nothing phishy in the headers)")

    print("\n" + "-" * 64)
    print("Risk score: %d/100" % min(score, 100))
    print("Verdict:    %s" % verdict)
    print("Next step:  %s" % advice)


if __name__ == "__main__":
    main()
