#!/usr/bin/env python3
"""
Day 23 — Windows Logon Event Decoder (SOC analysis, read-only, fully offline)

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

SAFETY: this tool is 100% offline and read-only. It parses text lines you
hand it (or the built-in sample file) and explains them. It touches no live
systems, no real logs, no network.

Run it
------
    python3 logon_event_decoder.py --demo        # walk through built-in samples
    python3 logon_event_decoder.py --file sample_events.txt
    python3 logon_event_decoder.py "2026-10-19 03:14:22 | 4624 | jdoe | 10 | 203.0.113.45"
"""

import argparse
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
    4776: ("Credential validation",
            "Windows checked a username/password against its database. The "
            "companion of 4624/4625 — failures here + successes elsewhere "
            "tell a story.",
            "low"),
}

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


def parse_line(line):
    """Parse one event line into a dict. Accepts a flexible pipe format:

        <timestamp> | <event_id> | <user> | <logon_type> | <source_ip>

    Timestamp is optional; logon_type and source_ip default to unknown.
    Returns None for blank lines and lines starting with #.
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


def explain(event):
    """Print a plain-English breakdown of one parsed event."""
    eid = event["event_id"]
    label, meaning, risk = EVENTS.get(
        eid, ("Unknown event ID",
              "Not one of the common logon events — look it up before "
              "trusting it.", "unknown"))
    print(f"  [{event['time']}] Event {eid} — {label}")
    print(f"  User: {event['user']}"
          + (f"   Source: {event['src']}" if event["src"] != "?" else ""))
    print(f"  What it means: {meaning}")

    # The logon-type "door" explanation, when the event carries one.
    ltype = event["logon_type"]
    if ltype is not None and eid in (4624, 4625, 4634, 4647):
        tlabel, tmeaning, tnote = LOGON_TYPES.get(
            ltype, ("Unknown logon type",
                    "Not a documented type — treat with suspicion.",
                    "Unknown types are worth a lookup."))
        print(f"  Door used: Type {ltype} — {tlabel}")
        print(f"             {tmeaning}")
        print(f"  SOC note: {tnote}")

    # Simple, honest risk flags — pattern-based, no magic.
    flags = []
    user_lower = event["user"].lower()
    if eid == 4625:
        flags.append("Failed logon — one is human error; many in a row is "
                     "password guessing (see the burst check below).")
    if eid == 4624 and ltype == 10 and is_night_hour(event["time"]):
        flags.append("RDP logon at night — unusual hour for remote access. "
                     "Verify this was expected.")
    if eid == 4624 and ltype == 10 and not user_lower.endswith(SYSTEM_ACCOUNTS):
        flags.append("Remote session by a named user — confirm the source IP "
                     "is one you recognize.")
    if eid == 4624 and ltype == 8:
        flags.append("Cleartext network logon — credentials traveled "
                     "readable on the wire. Fix the protocol, don't just "
                     "watch the alert.")
    if eid in (4672, 4720, 4732):
        flags.append(f"Privilege/account event ({label}) — confirm it was "
                     "an authorized admin action.")
    for f in flags:
        print(f"  >> FLAG: {f}")
    if not flags and risk in ("info",):
        print("  >> No flags — routine entry.")
    print()


def summarize(events):
    """Print a SOC-style triage summary across all parsed events."""
    counts = {}
    failed_users = {}
    rdp_night = 0
    for e in events:
        counts[e["event_id"]] = counts.get(e["event_id"], 0) + 1
        if e["event_id"] == 4625:
            failed_users[e["user"]] = failed_users.get(e["user"], 0) + 1
        if (e["event_id"] == 4624 and e["logon_type"] == 10
                and is_night_hour(e["time"])):
            rdp_night += 1

    print("=" * 64)
    print("TRIAGE SUMMARY")
    print("=" * 64)
    for eid in sorted(counts):
        label = EVENTS.get(eid, ("Unknown", "", ""))[0]
        print(f"  Event {eid} ({label}): {counts[eid]}")
    print()
    if failed_users:
        top_user, top_n = max(failed_users.items(), key=lambda kv: kv[1])
        print(f"  Failed logons by user: {failed_users}")
        if top_n >= 5:
            print(f"  >> BURST: {top_n} failed logons for '{top_user}' — "
                  "this smells like password guessing. Next steps: check the "
                  "source IPs, see if the attempts came from one place, and "
                  "confirm the account isn't locked or compromised.")
        else:
            print("  Failed-logon volume looks like normal human typos.")
    else:
        print("  No failed logons in this batch.")
    if rdp_night:
        print(f"  >> {rdp_night} RDP logon(s) during night hours (22:00–06:00) "
              "— verify each was expected.")
    print("  Reminder: an alert is a lead, not a verdict — confirm before "
          "escalating.")


def run(lines):
    """Parse, explain, and summarize a batch of event lines."""
    events = [e for e in (parse_line(l) for l in lines) if e]
    if not events:
        print("No parseable event lines found. Expected format:")
        print("  2026-10-19 03:14:22 | 4624 | jdoe | 10 | 203.0.113.45")
        sys.exit(1)
    print("=" * 64)
    print(f"Decoding {len(events)} event(s)...")
    print("=" * 64 + "\n")
    for e in events:
        explain(e)
    summarize(events)


def main():
    parser = argparse.ArgumentParser(
        description="Explain Windows logon events in plain English "
                    "(offline, read-only).")
    parser.add_argument("--demo", action="store_true",
                        help="decode the built-in sample events")
    parser.add_argument("--file", metavar="PATH",
                        help="read event lines from a file")
    parser.add_argument("event", nargs="?",
                        help='one event line, e.g. "4624 | jdoe | 10"')
    args = parser.parse_args()

    if args.demo:
        run(DEMO_LINES)
    elif args.file:
        with open(args.file) as f:
            run(f.readlines())
    elif args.event:
        run([args.event])
    else:
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
