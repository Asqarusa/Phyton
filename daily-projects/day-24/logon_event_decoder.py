#!/usr/bin/env python3
"""
Day 24 — Windows Logon Event Decoder (SOC analysis, read-only, fully offline)

What this does
-------------
Takes Windows Security event log entries about logons and explains them in
plain English: WHO logged on, HOW (which "door" they used), and whether a
SOC analyst should care.

The key idea: Windows doesn't just say "someone logged in". It says WHICH
KIND of logon it was — sitting at the keyboard? connecting over the network?
a Remote Desktop session? a background service? That number is called the
Logon Type, and reading it is a bread-and-butter SOC analyst skill.

Think of it like a building with different doors:
  Type 2  = the front door with a badge reader (someone physically at the keyboard)
  Type 3  = the loading dock (network connection, e.g. opening a shared folder)
  Type 10 = the video intercom — someone "entered" from across town via Remote Desktop
  Type 5  = the robot vacuum with its own key (a background service)

A Type 10 logon on a server at 3 AM is a very different story from a Type 2
logon on a laptop at 9 AM — same "success" word, completely different risk.

WHAT'S NEW in this version (2026-11-19)
----------------------------------------
* Success-after-failures detection: if a user logs on successfully right
  after several failed attempts, the summary now raises a CRITICAL flag —
  that pattern is how a guessed password turns into a break-in.
* Lateral-movement watch: if one source address makes 5+ Type 3 (network)
  logons, the summary flags it — that's the footprint of someone hopping
  from machine to machine inside your network.
* Four more event IDs: 4740 (account locked out), 4768 / 4769 / 4771
  (Kerberos ticket events, including Kerberos password-guessing failures).
* --json: machine-readable output for piping into other tools.
* --quiet: show only the flagged events, plus the summary.
* --user / --ip: filter the batch to one user or one source address.
* --explain <event ID> [--type N]: look up one event code (and logon
  type) without needing a log line — a quick reference card.
* Exit codes: 0 = clean, 1 = something flagged, 2 = usage error.
* Friendlier errors: missing files, bad event IDs and timestamp-only
  lines now get a clear message instead of a crash or a confusing
  "Event None".

SAFETY: this tool is 100% offline and read-only. It parses text lines you
hand it (or the built-in sample file) and explains them. It touches no live
systems, no real logs, no network.

Run it
------
    python3 logon_event_decoder.py --demo        # walk through built-in samples
    python3 logon_event_decoder.py --file sample_events.txt
    python3 logon_event_decoder.py "2026-10-19 03:14:22 | 4624 | jdoe | 10 | 203.0.113.45"
    python3 logon_event_decoder.py --file sample_events.txt --json
    python3 logon_event_decoder.py --file sample_lateral.txt --quiet
    python3 logon_event_decoder.py --explain 4720
    python3 logon_event_decoder.py --explain 4624 --type 10
"""

import argparse
import json
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# The event IDs that matter for logon analysis.
# Format: id -> (short label, plain-English meaning, risk level for SOC)
# ---------------------------------------------------------------------------
EVENTS = {
    4624: ("Successful logon",
            "Someone (or something) logged on successfully.",
            "info"),
    4625: ("Failed logon",
            "A logon attempt failed — wrong password or bad account name. "
            "One is normal; a burst of them is password guessing.",
            "low"),
    4634: ("Logoff",
            "A logon session ended normally.",
            "info"),
    4647: ("User-initiated logoff",
            "The user logged off on purpose (as opposed to a session just ending).",
            "info"),
    4648: ("Explicit credentials used",
            "Someone logged on with credentials DIFFERENT from the account "
            "already signed in — e.g. 'run as administrator' or connecting to "
            "another machine's share. Normal for admins, interesting in bulk.",
            "medium"),
    4672: ("Special privileges assigned",
            "A logon was granted administrator-level rights. Every admin logon "
            "creates one of these — attackers LOVE admin sessions, so SOC "
            "analysts watch these closely.",
            "medium"),
    4720: ("User account created",
            "A brand-new account was made. Attackers create backdoor accounts "
            "to come back later — a new account you didn't expect is a red flag.",
            "high"),
    4732: ("Added to privileged group",
            "Someone was added to a powerful group (like Administrators). "
            "This is how attackers escalate: get in quietly, then make "
            "themselves admin.",
            "high"),
    4740: ("Account locked out",
            "Too many failed logons locked this account. The lockout itself "
            "is a safety feature doing its job — but it also proves someone "
            "was guessing passwords at this account.",
            "medium"),
    4768: ("Kerberos ticket-granting ticket requested",
            "A user asked the domain controller for a ticket-granting ticket "
            "— the Kerberos version of showing your badge at the front desk "
            "so you can move around the building afterwards.",
            "info"),
    4769: ("Kerberos service ticket requested",
            "A user asked for a ticket to one specific service (a file "
            "server, a database...). A flood of these to many services from "
            "one user can mean someone mapping out what's available.",
            "info"),
    4771: ("Kerberos pre-authentication failed",
            "A Kerberos logon failed before any ticket was issued — usually "
            "a wrong password at the domain controller. One is a typo; a "
            "burst is password guessing against the domain itself.",
            "low"),
    4776: ("Credential validation",
            "Windows checked a username/password against its database. The "
            "companion of 4624/4625 — failures here + successes elsewhere "
            "tell a story.",
            "low"),
}

# Event IDs that count as "a logon attempt failed" for burst and
# success-after-failures tracking.
FAILED_EVENT_IDS = (4625, 4771)

# ---------------------------------------------------------------------------
# Logon types: the "which door" number. Applies to 4624/4625/4634/4647.
# Format: type -> (short label, plain-English meaning, SOC note)
# ---------------------------------------------------------------------------
LOGON_TYPES = {
    0:  ("System use only",
         "Reserved for the system itself — you should basically never see this "
         "on a real logon.",
         "Odd to see on a real logon line; note it."),
    2:  ("Interactive",
         "Someone sat at the actual keyboard (or the console) and signed in. "
         "The classic 'front door' logon.",
         "Normal on workstations during work hours."),
    3:  ("Network",
         "A remote connection over the network — opening a shared folder, "
         "connecting to a printer, mapping a drive. The 'loading dock' door: "
         "no one is 'sitting' anywhere, the machine just served files.",
         "Very common and usually fine — but a FLOOD of Type 3 logons from "
         "one machine to many others can mean lateral movement (an attacker "
         "hopping machine to machine)."),
    4:  ("Batch",
         "A scheduled task ran as this account. The 'janitor's scheduled "
         "rounds' — automatic, expected, repetitive.",
         "Should match known scheduled tasks; an unknown one is suspicious."),
    5:  ("Service",
         "A background service started as this account — the 'robot vacuum "
         "with its own key'. Services need accounts to run.",
         "Normal for known services; a NEW service account is worth checking."),
    7:  ("Unlock",
         "Someone unlocked a locked workstation (Win+L, then password). "
         "Proves a human came back to a machine they were already on.",
         "Routine on workstations."),
    8:  ("NetworkCleartext",
         "A network logon where the password traveled in CLEARTEXT — "
         "readable by anyone listening on the wire. Mostly legacy protocols "
         "(old IIS logons).",
         "Cleartext passwords are always bad news — flag and fix."),
    9:  ("NewCredentials",
         "Logon with cloned credentials, e.g. 'RunAs' with /netonly. The "
         "account runs locally but uses different credentials on the network.",
         "Legit admin tool; also abused — context decides."),
    10: ("RemoteInteractive (RDP)",
         "A Remote Desktop session — someone controlled this machine's screen "
         "from across the network. The 'video intercom' door: they weren't "
         "in the building, but they were driving the computer.",
         "THE big one to watch. RDP from an unusual IP, at an unusual hour, "
         "or on a server that shouldn't get RDP = investigate immediately."),
    11: ("CachedInteractive",
         "Interactive logon using cached credentials — the machine couldn't "
         "reach the domain controller (laptop on a plane) so it trusted the "
         "last-known-good password.",
         "Normal for roaming laptops."),
    12: ("CachedRemoteInteractive",
         "RemoteInteractive logon with cached credentials (RDP while the "
         "domain controller was unreachable).",
         "Same as Type 10, plus offline — check the source."),
    13: ("CachedUnlock",
         "Workstation unlock with cached credentials.",
         "Routine on roaming laptops."),
}

# Keywords that suggest a service/system account rather than a human.
SYSTEM_ACCOUNTS = ("system", "network service", "local service", "$")

# How many failures before a success counts as "success after failures",
# and how many Type 3 logons from one source counts as lateral movement.
SUCCESS_AFTER_FAILURES_MIN = 3
LATERAL_MOVEMENT_MIN = 5
BURST_MIN = 5


def parse_line(line):
    """Parse one event line into a dict. Accepts a flexible pipe format:

        <timestamp> | <event_id> | <user> | <logon_type> | <source_ip>

    Timestamp is optional; logon_type and source_ip default to unknown.
    Returns None for blank lines, lines starting with #, lines with no
    event ID (e.g. a bare timestamp), and lines whose event ID is not a
    number.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = [p.strip() for p in line.split("|")]
    event = {"raw": line, "time": "?", "event_id": None,
             "user": "?", "logon_type": None, "src": "?"}
    # First field may be a timestamp ("2026-10-19 03:14:22") or the event ID.
    first = parts[0]
    rest = parts[1:]
    try:
        datetime.strptime(first, "%Y-%m-%d %H:%M:%S")
        event["time"] = first
    except ValueError:
        rest = parts  # no timestamp; first field is the event ID
    if len(rest) >= 1:
        try:
            event["event_id"] = int(rest[0])
        except ValueError:
            return None  # not a parseable event line
    if event["event_id"] is None:
        return None  # e.g. a line that was only a timestamp
    if len(rest) >= 2:
        event["user"] = rest[1] or "?"
    if len(rest) >= 3 and rest[2] not in ("", "?", "-"):
        try:
            event["logon_type"] = int(rest[2])
        except ValueError:
            pass
    if len(rest) >= 4:
        event["src"] = rest[3] or "?"
    return event


def is_night_hour(timestr):
    """Rough check: is the timestamp between 22:00 and 06:00?"""
    try:
        hour = datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S").hour
        return hour >= 22 or hour < 6
    except ValueError:
        return False


def analyze(event):
    """Work out the plain-English breakdown of one parsed event.

    Returns a dict with the event info, the logon-type ("door") info, and
    a list of flags. Each flag is (level, text) where level is one of
    "warning" or "critical". Keeping the analysis separate from printing
    is what makes --json possible.
    """
    eid = event["event_id"]
    label, meaning, risk = EVENTS.get(
        eid, ("Unknown event ID",
              "Not one of the common logon events — look it up before "
              "trusting it.", "unknown"))
    result = {
        "time": event["time"],
        "event_id": eid,
        "event": label,
        "meaning": meaning,
        "risk": risk,
        "user": event["user"],
        "source": event["src"],
        "logon_type": event["logon_type"],
        "door": None,
        "flags": [],
    }

    # The logon-type "door" explanation, when the event carries one.
    ltype = event["logon_type"]
    if ltype is not None and eid in (4624, 4625, 4634, 4647):
        tlabel, tmeaning, tnote = LOGON_TYPES.get(
            ltype, ("Unknown logon type",
                    "Not a documented type — treat with suspicion.",
                    "Unknown types are worth a lookup."))
        result["door"] = {"type": ltype, "label": tlabel,
                          "meaning": tmeaning, "soc_note": tnote}

    # Simple, honest risk flags — pattern-based, no magic.
    flags = []
    user_lower = event["user"].lower()
    if eid in FAILED_EVENT_IDS:
        flags.append(("warning",
                      "Failed logon — one is human error; many in a row is "
                      "password guessing (see the burst check below)."))
    if eid == 4624 and ltype == 10 and is_night_hour(event["time"]):
        flags.append(("warning",
                      "RDP logon at night — unusual hour for remote access. "
                      "Verify this was expected."))
    if eid == 4624 and ltype == 10 and not user_lower.endswith(SYSTEM_ACCOUNTS):
        flags.append(("warning",
                      "Remote session by a named user — confirm the source IP "
                      "is one you recognize."))
    if eid == 4624 and ltype == 8:
        flags.append(("critical",
                      "Cleartext network logon — credentials traveled "
                      "readable on the wire. Fix the protocol, don't just "
                      "watch the alert."))
    if eid == 4740:
        flags.append(("warning",
                      "Account locked out — the lockout stopped the guessing, "
                      "but confirm the account owner knows and the source "
                      "isn't still hammering it."))
    if eid in (4672, 4720, 4732):
        flags.append(("warning",
                      f"Privilege/account event ({label}) — confirm it was "
                      "an authorized admin action."))
    result["flags"] = flags
    return result


def explain(analysis):
    """Print a plain-English breakdown of one analyzed event."""
    print(f"  [{analysis['time']}] Event {analysis['event_id']} — {analysis['event']}")
    print(f"  User: {analysis['user']}"
          + (f"   Source: {analysis['source']}" if analysis['source'] != "?" else ""))
    print(f"  What it means: {analysis['meaning']}")

    door = analysis["door"]
    if door is not None:
        print(f"  Door used: Type {door['type']} — {door['label']}")
        print(f"             {door['meaning']}")
        print(f"  SOC note: {door['soc_note']}")

    for level, text in analysis["flags"]:
        tag = "CRITICAL" if level == "critical" else "FLAG"
        print(f"  >> {tag}: {text}")
    if not analysis["flags"] and analysis["risk"] == "info":
        print("  >> No flags — routine entry.")
    print()


def summarize(events, analyses):
    """Print a SOC-style triage summary across all parsed events.

    Returns (exit_code, summary_dict): exit code 1 when something worth
    investigating was found, else 0. The summary dict feeds --json output.
    """
    counts = {}
    failed_users = {}
    rdp_night = 0
    # Success-after-failures: walk the events in order, counting failed
    # attempts per user; a success that follows 3+ failures is the
    # textbook sign a guessed password worked.
    fails_since_success = {}
    compromised = []
    # Lateral movement: Type 3 (network) logons per source address.
    type3_by_source = {}
    for e in events:
        counts[e["event_id"]] = counts.get(e["event_id"], 0) + 1
        if e["event_id"] in FAILED_EVENT_IDS:
            failed_users[e["user"]] = failed_users.get(e["user"], 0) + 1
            fails_since_success[e["user"]] = \
                fails_since_success.get(e["user"], 0) + 1
        elif e["event_id"] == 4624:
            prior_fails = fails_since_success.get(e["user"], 0)
            if prior_fails >= SUCCESS_AFTER_FAILURES_MIN:
                compromised.append({"user": e["user"],
                                    "failed_before": prior_fails,
                                    "time": e["time"],
                                    "source": e["src"]})
            fails_since_success[e["user"]] = 0
            if e["logon_type"] == 10 and is_night_hour(e["time"]):
                rdp_night += 1
            if e["logon_type"] == 3 and e["src"] not in ("?", "-", ""):
                type3_by_source[e["src"]] = \
                    type3_by_source.get(e["src"], 0) + 1

    lateral = [{"source": src, "type3_logons": n}
               for src, n in sorted(type3_by_source.items())
               if n >= LATERAL_MOVEMENT_MIN]

    summary = {
        "event_counts": {str(eid): counts[eid] for eid in sorted(counts)},
        "failed_logons_by_user": failed_users,
        "night_rdp_logons": rdp_night,
        "success_after_failures": compromised,
        "lateral_movement": lateral,
    }

    print("=" * 64)
    print("TRIAGE SUMMARY")
    print("=" * 64)
    for eid in sorted(counts):
        label = EVENTS.get(eid, ("Unknown", "", ""))[0]
        print(f"  Event {eid} ({label}): {counts[eid]}")
    print()
    exit_code = 0
    if failed_users:
        top_user, top_n = max(failed_users.items(), key=lambda kv: kv[1])
        print(f"  Failed logons by user: {failed_users}")
        if top_n >= BURST_MIN:
            print(f"  >> BURST: {top_n} failed logons for '{top_user}' — "
                  "this smells like password guessing. Next steps: check the "
                  "source IPs, see if the attempts came from one place, and "
                  "confirm the account isn't locked or compromised.")
            exit_code = 1
        else:
            print("  Failed-logon volume looks like normal human typos.")
    else:
        print("  No failed logons in this batch.")
    if compromised:
        for c in compromised:
            print(f"  >> CRITICAL: '{c['user']}' logged on successfully at "
                  f"{c['time']} after {c['failed_before']} failed attempts "
                  f"(source {c['source']}) — a guessed password may have "
                  "worked. Treat this session as potentially compromised: "
                  "check what the account did next and force a password reset.")
        exit_code = 1
    if lateral:
        for entry in lateral:
            print(f"  >> LATERAL MOVEMENT?: {entry['type3_logons']} Type 3 "
                  f"(network) logons from {entry['source']} — one address "
                  "touching many machines in a short window. Check whether "
                  "that host should be reaching out like that.")
        exit_code = 1
    if rdp_night:
        print(f"  >> {rdp_night} RDP logon(s) during night hours (22:00–06:00) "
              "— verify each was expected.")
        exit_code = 1
    if any(level == "critical" for a in analyses for level, _ in a["flags"]):
        exit_code = 1
    if any(a["flags"] for a in analyses):
        exit_code = 1
    print("  Reminder: an alert is a lead, not a verdict — confirm before "
          "escalating.")
    return exit_code, summary


def explain_code(event_id, logon_type=None):
    """Print the reference-card explanation for one event ID, optionally
    with one logon type. Used by --explain; needs no log line at all."""
    label, meaning, risk = EVENTS.get(
        event_id, ("Unknown event ID",
                   "Not one of the common logon events — look it up before "
                   "trusting it.", "unknown"))
    print(f"Event {event_id} — {label}  (risk: {risk})")
    print(f"  {meaning}")
    if logon_type is not None:
        tlabel, tmeaning, tnote = LOGON_TYPES.get(
            logon_type, ("Unknown logon type",
                         "Not a documented type — treat with suspicion.",
                         "Unknown types are worth a lookup."))
        print(f"Logon Type {logon_type} — {tlabel}")
        print(f"  {tmeaning}")
        print(f"  SOC note: {tnote}")


def read_lines(path):
    """Read event lines from a file, with a friendly error if it is missing."""
    try:
        with open(path) as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        print("Tip: check the path, or start with  python3 "
              "logon_event_decoder.py --demo", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"Error: could not read {path}: {exc}", file=sys.stderr)
        sys.exit(2)


def run(lines, as_json=False, quiet=False, user_filter=None,
        ip_filter=None):
    """Parse, explain, and summarize a batch of event lines.

    Returns an exit code: 0 = clean, 1 = something flagged, 2 = usage
    error (no parseable lines, or a filter that matched nothing).
    """
    events = [e for e in (parse_line(l) for l in lines) if e]
    if not events:
        print("No parseable event lines found. Expected format:")
        print("  2026-10-19 03:14:22 | 4624 | jdoe | 10 | 203.0.113.45")
        return 2
    if user_filter:
        events = [e for e in events
                  if e["user"].lower() == user_filter.lower()]
    if ip_filter:
        events = [e for e in events if e["src"] == ip_filter]
    if not events:
        print("No events matched the filter. Try --demo to see the "
              "built-in examples, or drop the filter.", file=sys.stderr)
        return 2

    analyses = [analyze(e) for e in events]
    shown = [a for a in analyses if not quiet or a["flags"]]

    if as_json:
        exit_code, summary = summarize_json(events, analyses)
        print(json.dumps({"events": shown, "summary": summary}, indent=2))
        return exit_code

    print("=" * 64)
    print(f"Decoding {len(events)} event(s)...")
    print("=" * 64 + "\n")
    for a in shown:
        explain(a)
    if quiet and len(shown) < len(analyses):
        print(f"  ({len(analyses) - len(shown)} routine event(s) hidden "
              "by --quiet)\n")
    exit_code, _summary = summarize(events, analyses)
    return exit_code


def summarize_json(events, analyses):
    """Same triage numbers as summarize(), but without printing — the
    caller prints them as JSON. Returns (exit_code, summary_dict)."""
    counts = {}
    failed_users = {}
    rdp_night = 0
    fails_since_success = {}
    compromised = []
    type3_by_source = {}
    for e in events:
        counts[e["event_id"]] = counts.get(e["event_id"], 0) + 1
        if e["event_id"] in FAILED_EVENT_IDS:
            failed_users[e["user"]] = failed_users.get(e["user"], 0) + 1
            fails_since_success[e["user"]] = \
                fails_since_success.get(e["user"], 0) + 1
        elif e["event_id"] == 4624:
            prior_fails = fails_since_success.get(e["user"], 0)
            if prior_fails >= SUCCESS_AFTER_FAILURES_MIN:
                compromised.append({"user": e["user"],
                                    "failed_before": prior_fails,
                                    "time": e["time"],
                                    "source": e["src"]})
            fails_since_success[e["user"]] = 0
            if e["logon_type"] == 10 and is_night_hour(e["time"]):
                rdp_night += 1
            if e["logon_type"] == 3 and e["src"] not in ("?", "-", ""):
                type3_by_source[e["src"]] = \
                    type3_by_source.get(e["src"], 0) + 1

    lateral = [{"source": src, "type3_logons": n}
               for src, n in sorted(type3_by_source.items())
               if n >= LATERAL_MOVEMENT_MIN]

    exit_code = 0
    if failed_users and max(failed_users.values()) >= BURST_MIN:
        exit_code = 1
    if compromised or lateral or rdp_night:
        exit_code = 1
    if any(level == "critical" for a in analyses for level, _ in a["flags"]):
        exit_code = 1
    if any(a["flags"] for a in analyses):
        exit_code = 1

    summary = {
        "event_counts": {str(eid): counts[eid] for eid in sorted(counts)},
        "failed_logons_by_user": failed_users,
        "night_rdp_logons": rdp_night,
        "success_after_failures": compromised,
        "lateral_movement": lateral,
    }
    return exit_code, summary


def main():
    parser = argparse.ArgumentParser(
        description="Explain Windows logon events in plain English "
                    "(offline, read-only).")
    parser.add_argument("--demo", action="store_true",
                        help="decode the built-in sample events")
    parser.add_argument("--file", metavar="PATH",
                        help="read event lines from a file")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON instead of text")
    parser.add_argument("--quiet", action="store_true",
                        help="show only flagged events, plus the summary")
    parser.add_argument("--user", metavar="NAME",
                        help="only show events for this user")
    parser.add_argument("--ip", metavar="ADDRESS",
                        help="only show events from this source IP")
    parser.add_argument("--explain", metavar="EVENT_ID", type=int,
                        help="explain one event ID, e.g. --explain 4720")
    parser.add_argument("--type", metavar="N", type=int, default=None,
                        help="with --explain, also explain logon type N")
    parser.add_argument("event", nargs="?",
                        help='one event line, e.g. "4624 | jdoe | 10"')
    args = parser.parse_args()

    if args.explain is not None:
        explain_code(args.explain, args.type)
        sys.exit(0)
    if args.demo:
        sys.exit(run(DEMO_LINES, as_json=args.json, quiet=args.quiet,
                     user_filter=args.user, ip_filter=args.ip))
    if args.file:
        sys.exit(run(read_lines(args.file), as_json=args.json,
                     quiet=args.quiet, user_filter=args.user,
                     ip_filter=args.ip))
    if args.event:
        sys.exit(run([args.event], as_json=args.json, quiet=args.quiet,
                     user_filter=args.user, ip_filter=args.ip))
    parser.print_help()
    print("\nTip: start with  python3 logon_event_decoder.py --demo")
    sys.exit(1)


# Built-in demo: a small, realistic day-shift batch plus two suspicious
# entries. All IPs are RFC 5737 documentation ranges — never real.
DEMO_LINES = [
    "# Morning shift: normal interactive logons",
    "2026-10-19 08:58:11 | 4624 | jdoe | 2 | -",
    "2026-10-19 09:01:44 | 4624 | asmith | 11 | -",
    "2026-10-19 09:05:02 | 4648 | jdoe | 3 | 198.51.100.23",
    "2026-10-19 09:12:37 | 4624 | jdoe | 3 | 198.51.100.23",
    "# A typo or two — human, not hostile",
    "2026-10-19 09:14:05 | 4625 | jdoe | 2 | -",
    "2026-10-19 09:14:31 | 4624 | jdoe | 2 | -",
    "# Night: the interesting part",
    "2026-10-19 03:14:22 | 4625 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:14:40 | 4625 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:15:03 | 4625 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:15:29 | 4625 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:15:55 | 4625 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:16:12 | 4625 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:16:30 | 4624 | administrator | 10 | 203.0.113.45",
    "2026-10-19 03:16:31 | 4672 | administrator | - | -",
    "2026-10-19 03:18:02 | 4720 | svc-backup | - | -",
]

if __name__ == "__main__":
    main()
