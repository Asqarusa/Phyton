# Email Header Analyzer — reading the return address on the envelope

**Day 21 · SOC analysis series · by Askarbek Akhrorov**
Code: `email_header_analyzer.py` (+ `sample_phishing.eml`, `sample_legit.eml`)

## The big idea (analogy first)

Think of every email as a physical letter. The **message body** is the letter itself — what you read. The **headers** are the envelope: the return address, the postmarks stamped by every post office along the way, and the wax seal.

Here's the catch: anyone can *write* anything on an envelope. A letter that says "From: Your Bank" in big letters might have been mailed from a basement. SOC analysts know this, so when someone reports a suspicious email, they don't start by reading the letter — they start by inspecting the **envelope**: who really sent it, which post offices touched it, whether the wax seal is genuine, and whether the return address agrees with the letterhead.

This script does exactly that first look, automatically. It runs 6 checks and scores the email like an analyst's gut feeling, quantified.

## What the script does

Point it at a saved email file (`.eml` — any mail app can save one) and it:

1. **Reads the three "who is this?" headers** — `From`, `Reply-To`, `Return-Path` — and flags it when they disagree. Legit mail agrees with itself; phishing mail has the letterhead say "PayPal" while replies quietly go to an attacker's inbox.
2. **Spots display-name spoofing** — your inbox shows the big friendly *name* ("PayPal Support") and hides the address. The script checks whether that name is borrowing a famous brand the address has nothing to do with.
3. **Walks the Received chain** — every mail server stamps the message, newest stamp first. The script lists the journey (sender → … → you) and flags a suspicious first hop.
4. **Reads the Authentication-Results "wax seal"** — SPF, DKIM, and DMARC are DNS-published proofs of legitimacy. If a server checked them and they *failed*, that's the seal broken.
5. **Compares link text vs link target** — classic trick: blue text says `paypal.com/signin` but the click really goes somewhere else. The script catches the mismatch.
6. **Sniffs for pressure language** — "URGENT", "suspended", "verify now". Attackers manufacture panic so you click before you think.

Each finding adds points (25 / 20 / 10 by severity); the total becomes a **risk score** and a verdict: **CLEAN**, **SUSPICIOUS**, or **LIKELY PHISHING**, plus the right next step for each.

## How the code works (line by line, simple terms)

- **`addr_of()`** — pulls just the address out of a header like `"PayPal Support" <support@...>` using a pattern. The inbox shows you the name; this function reads the fine print.
- **`display_name_of()`** — the opposite: pulls just the *name* people see. Headers come in two shapes (`Name <addr>` and `"Name" <addr>`), so it handles both.
- **`analyze()`** — the main brain. It opens the `.eml` file with Python's built-in `email` parser (the same library that understands how real mail apps read messages), then runs each check and records findings.
- **`WEIGHTS`** — the scoring table. Not all clues are equal: a mismatched Reply-To (replies hijacked) is worth 25 points; a panicky subject line only 10. This mirrors how analysts think: some tells are decisive, others are just seasoning.
- **`Received` handling** — `msg.get_all("Received")` returns every stamp, newest first, so the script prints them bottom-up to follow the journey from sender to you. The **oldest** stamp (last in the list) is closest to the true sender — that's the one it inspects for the originating IP.
- **Authentication-Results parsing** — tiny regexes like `spf=(\w+)` pull `pass`/`fail` out of the verdict line. `fail` = broken wax seal, flagged immediately.
- **Link check** — a regex finds every `<a href="...">text</a>`, extracts the domain from the *visible text* and the *real destination*, and compares them. Different domains = the label lies.
- **Verdict thresholds** — 40+ points: LIKELY PHISHING (report and delete). 15–39: SUSPICIOUS (verify through a separate channel — type the site address yourself). Below 15: CLEAN, with the honest caveat that this checks the *envelope*, not the letter.

## Key terms, translated

| Term | Plain English |
|---|---|
| Email header | The envelope: metadata stamped around the message (sender, route, date) |
| From / Reply-To / Return-Path | Letterhead / where replies go / where bounces go — three "senders" that should usually agree |
| Display-name spoofing | Big friendly name says "PayPal Support", hidden address says otherwise |
| Received chain | Postmark stamps from every mail server the message passed through |
| SPF / DKIM / DMARC | Three proofs a sender can publish in DNS: "this server may send for me" / "this message is cryptographically signed" / "reject fakes, here's the policy" |
| Authentication-Results | The receiving server's note: "I checked the proofs, here's what I found" |
| Link-text mismatch | The clickable label says one address, the click goes to another |

## How to run it

```bash
cd daily-projects/day-21
python3 email_header_analyzer.py sample_phishing.eml   # the spoofed one → LIKELY PHISHING
python3 email_header_analyzer.py sample_legit.eml      # a normal message → CLEAN
```

To check your own suspicious email: in your mail app use *File → Save / Download* to get a `.eml` file, then run the script on it. Fully offline — nothing ever leaves your laptop.

You'll need Python 3 (no extra libraries — standard-library-only code).

## What to learn next

- **Full email forensics**: open a real phish in a sandbox and correlate the headers with the body — do the URLs, attachments, and sending infrastructure tell one story?
- **DMARC policies**: look up a domain's real `_dmarc` DNS record and see what `p=reject` vs `p=none` means for spoofing that brand.
- **BEC (business email compromise)**: the same header skills, applied to the trickiest phish of all — one that comes from a *real* compromised account, where the envelope is perfect and only the story is wrong.

---

*Sample data uses RFC 5737 documentation IPs and `.example` domains — no real addresses anywhere. Built as a defensive learning exercise: read-only, offline, educational.*
