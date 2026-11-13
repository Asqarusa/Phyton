#!/usr/bin/env python3
"""
Day 20 — Banner Grabber (read-only, defensive service identification)

What this does
--------------
Yesterday's port scanner told us which doors are open. This tool knocks
on each open door and reads the *nameplate*: the "banner" a service sends
when you connect. A banner often says exactly what software is running
and which version -- e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu".

For a SOC analyst that matters twice:
  1. Blue team: knowing your own services means knowing what to patch.
  2. Attackers love banners: an exact version number tells them which
     known exploit to try. That is why hiding or removing banners is a
     basic hardening step ("version disclosure").

What's new in this version
--------------------------
  * Risk grading: every banner gets a grade -- LOW (generic greeting),
    MEDIUM (software named, no version) or HIGH (exact version disclosed)
    -- plus a plain-English hardening tip.
  * Known-bad version watch: a small table of famous risky versions
    (e.g. vsftpd 2.3.4, which had a backdoor) gets flagged by name.
  * --file mode: analyse banners saved in a text file (one
    "PORT | BANNER" line each) -- handy for banners captured elsewhere.
  * --json mode: machine-readable output for scripts and SIEM ingestion.
  * --save / --compare: snapshot your banners and later spot what
    changed (NEW / CHANGED / GONE) -- a service quietly changing its
    banner is worth a look.
  * Friendlier errors: bad ports, bad timeouts and missing files now
    explain the problem and exit with code 2 instead of crashing.
  * Exit codes: 0 = no HIGH-risk banner found, 1 = at least one HIGH
    risk banner (needs attention), 2 = usage/input error.

SAFETY: this tool only ever connects to 127.0.0.1 (your own machine).
Pointing it at any other address is refused on purpose.

Run it
------
    python3 banner_grabber.py               # grab common ports on localhost
    python3 banner_grabber.py --ports 22,80,443
    python3 banner_grabber.py --demo        # no network at all, sample banners
    python3 banner_grabber.py --demo --json # same, as JSON
    python3 banner_grabber.py --file sample_banners.txt
    python3 banner_grabber.py --save baseline.json
    python3 banner_grabber.py --compare baseline.json
"""

import argparse
import json
import re
import socket
import sys

# Version-looking pattern: digit(s).digit(s), e.g. 8.9p1, 4.96, 1.0
VERSION_RE = re.compile(r"\d+\.\d+")

# Common ports we bother to knock on. (Knocking is just a short
# TCP connect -- the same thing any client does before talking.)
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]

# Localhost only. This is the entire safety story of this script:
# it cannot be pointed at anyone else's machine.
ALLOWED_TARGET = "127.0.0.1"

# Guesses: a few banner fragments and the service they usually mean.
KNOWN_SIGNATURES = [
    ("SSH-", "SSH server"),
    ("OpenSSH", "OpenSSH"),
    ("220", "mail / FTP style greeting (SMTP, FTP, POP3...)"),
    ("+OK", "mail server (POP3 style)"),
    ("* OK", "mail server (IMAP style)"),
    ("HTTP/", "web server speaking HTTP"),
    ("Server:", "web server (Server header)"),
    ("vsftpd", "vsftpd FTP server"),
    ("ProFTPD", "ProFTPD FTP server"),
    ("Microsoft FTP", "Microsoft FTP Service"),
    ("Exim", "Exim mail server"),
    ("Postfix", "Postfix mail server"),
    ("Dovecot", "Dovecot mail server"),
    ("Courier", "Courier mail server"),
    ("MySQL", "MySQL database"),
    ("nginx", "nginx web server"),
    ("Apache", "Apache web server"),
    ("RDP", "Remote Desktop"),
]

# A tiny watchlist of versions with a famous bad reputation. These are
# not "every old version" -- just the ones a beginner should recognise
# on sight. (vsftpd 2.3.4 shipped with a backdoor; OpenSSH before 7.4
# is missing years of security fixes.)
RISKY_VERSIONS = [
    ("vsftpd 2.3.4", "famous backdoored version -- replace immediately"),
    ("OpenSSH_7.4", "very old OpenSSH (pre-2017) -- patch it"),
    ("OpenSSH_7.2", "very old OpenSSH (pre-2016) -- patch it"),
    ("Apache/2.2", "Apache 2.2 is end-of-life -- upgrade to 2.4"),
    ("Microsoft FTP Service 6.0", "old IIS FTP -- upgrade / harden"),
]

# Risk grades, in plain English.
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"


def guess_service(banner: str) -> str:
    """Return a best-guess service name for a banner (or 'unknown')."""
    for fragment, service in KNOWN_SIGNATURES:
        if fragment.lower() in banner.lower():
            return service
    return "unknown service"


def find_risky_version(banner: str) -> str | None:
    """Return the warning for a known-bad version in the banner, or None."""
    for version, warning in RISKY_VERSIONS:
        if version.lower() in banner.lower():
            return f"{version}: {warning}"
    return None


def grade_banner(banner: str) -> tuple[str, str]:
    """
    Grade one banner and explain why, in plain English.
    Returns (grade, reason).
    """
    risky = find_risky_version(banner)
    if risky:
        return RISK_HIGH, f"known risky version -- {risky}"
    # "HTTP/1.1" is the *protocol* version, not the software's version --
    # ignore it so a plain "HTTP/1.1 400 Bad Request" is not misread
    # as version disclosure.
    without_protocol = re.sub(r"HTTP/\d+\.\d+", "", banner)
    if VERSION_RE.search(without_protocol):
        return RISK_HIGH, (
            "exact version disclosed -- attackers can look up exploits "
            "for this version"
        )
    if guess_service(banner) != "unknown service":
        return RISK_MEDIUM, (
            "software named but no version shown -- better, still tells "
            "an attacker what to probe"
        )
    return RISK_LOW, "generic greeting -- reveals little about the service"


def hardening_tip(grade: str) -> str:
    """One concrete next step for a banner grade."""
    if grade == RISK_HIGH:
        return (
            "hide the version in the service config (e.g. ServerTokens Prod "
            "for Apache, or the equivalent banner setting)"
        )
    if grade == RISK_MEDIUM:
        return "consider a generic greeting that names no software at all"
    return "good -- keep it this vague"


def analyse_banner(port: int, banner: str) -> dict:
    """Turn one (port, banner) pair into a result record."""
    service = guess_service(banner)
    grade, reason = grade_banner(banner)
    return {
        "port": port,
        "banner": banner,
        "service": service,
        "risk": grade,
        "reason": reason,
        "tip": hardening_tip(grade),
    }


def grab_banner(port: int, timeout: float) -> str | None:
    """
    Connect to 127.0.0.1:port, read whatever it says first, then hang up.
    Returns the banner text, or None when nothing answers.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ALLOWED_TARGET, port))
            # Most services volunteer a banner on connect; HTTP servers
            # don't, so we say something neutral to coax a reply.
            if port in (80, 8080, 8000, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            raw = sock.recv(1024)  # 1024 bytes is plenty for a nameplate.
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None  # closed/filtered/silent -- normal, not an error
    if not raw:
        return None
    # Banners are supposed to be text; strip junk bytes just in case.
    return raw.decode("utf-8", errors="replace").strip().replace("\r", "")


def read_banner_file(path: str) -> list[tuple[int, str]]:
    """
    Read a "PORT | BANNER" file (same format as sample_banners.txt).
    Skips blank lines and '#' comments; warns and skips bad lines.
    """
    entries: list[tuple[int, str]] = []
    skipped = 0
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"Error: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            print(f"Warning: line {lineno} skipped (needs 'PORT | BANNER')",
                  file=sys.stderr)
            skipped += 1
            continue
        port_text, banner = (part.strip() for part in line.split("|", 1))
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            print(f"Warning: line {lineno} skipped (bad port '{port_text}')",
                  file=sys.stderr)
            skipped += 1
            continue
        entries.append((int(port_text), banner))
    if skipped:
        print(f"({skipped} line(s) skipped -- see warnings above)\n",
              file=sys.stderr)
    return entries


def load_baseline(path: str) -> dict:
    """Load a --save snapshot file (port -> banner). Exits 2 on problems."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: baseline file not found: {path}", file=sys.stderr)
        sys.exit(2)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Error: cannot read baseline {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"Error: baseline {path} is not a port->banner map",
              file=sys.stderr)
        sys.exit(2)
    return {int(port): banner for port, banner in data.items()}


def report_changes(current: dict, baseline: dict, as_json: bool = False) -> None:
    """Print NEW / CHANGED / GONE lines comparing two banner snapshots."""
    out = sys.stderr if as_json else sys.stdout
    print("\n=== banner changes vs baseline ===", file=out)
    changes = 0
    for port in sorted(set(current) | set(baseline)):
        if port not in baseline:
            print(f"  NEW     port {port}: {current[port]}", file=out)
            changes += 1
        elif port not in current:
            print(f"  GONE    port {port}: was '{baseline[port]}'", file=out)
            changes += 1
        elif current[port] != baseline[port]:
            print(f"  CHANGED port {port}:", file=out)
            print(f"    was: {baseline[port]}", file=out)
            print(f"    now: {current[port]}", file=out)
            changes += 1
    if changes == 0:
        print("  No changes -- every banner matches the baseline.", file=out)
    else:
        print(f"  {changes} change(s) -- check whether each one was planned.", file=out)


def parse_ports(text: str) -> list[int]:
    """Validate a comma-separated port list. Exits 2 with a friendly error."""
    ports: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or not 1 <= int(part) <= 65535:
            print(f"Error: '{part}' is not a valid port (use 1-65535).",
                  file=sys.stderr)
            print("Example: --ports 22,80,443", file=sys.stderr)
            sys.exit(2)
        ports.append(int(part))
    if not ports:
        print("Error: no ports given. Example: --ports 22,80,443",
              file=sys.stderr)
        sys.exit(2)
    return ports


def print_results(results: list[dict], as_json: bool) -> None:
    """Print the analysed banners, as a table or as JSON."""
    if as_json:
        print(json.dumps(results, indent=2))
        return
    high = sum(1 for r in results if r["risk"] == RISK_HIGH)
    medium = sum(1 for r in results if r["risk"] == RISK_MEDIUM)
    for r in results:
        print(f"port {r['port']}: {r['banner']}")
        print(f"  -> best guess: {r['service']}")
        print(f"  -> risk: {r['risk']} -- {r['reason']}")
        print(f"  -> hardening tip: {r['tip']}")
        print()
    print(f"Summary: {len(results)} banner(s) read -- "
          f"{high} HIGH risk, {medium} MEDIUM risk, "
          f"{len(results) - high - medium} LOW risk.")
    if high:
        print("HIGH risk means an exact version is on show -- "
              "hide it in the service config.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read service banners from your own machine (localhost only)."
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="comma-separated ports to try, e.g. 22,80,443",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.5,
        help="seconds to wait per port (must be over 0)",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="use sample banners, no network",
    )
    parser.add_argument(
        "--file", metavar="FILE",
        help="analyse banners from a 'PORT | BANNER' file instead of the network",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="print results as JSON instead of a human-readable report",
    )
    parser.add_argument(
        "--save", metavar="FILE",
        help="save the banners found to FILE (a baseline snapshot)",
    )
    parser.add_argument(
        "--compare", metavar="FILE",
        help="compare the banners found against a baseline FILE",
    )
    args = parser.parse_args()

    if args.timeout <= 0:
        print("Error: --timeout must be over 0 (e.g. --timeout 1.5).",
              file=sys.stderr)
        sys.exit(2)
    if args.demo and args.file:
        print("Error: pick one input -- --demo or --file, not both.",
              file=sys.stderr)
        sys.exit(2)

    # --- gather (port, banner) pairs from the chosen source ---
    entries: list[tuple[int, str]] = []
    if args.demo:
        if not args.json:
            print("=== --demo: sample banners (no network used) ===\n")
        entries = read_banner_file("sample_banners.txt")
    elif args.file:
        entries = read_banner_file(args.file)
    else:
        ports = parse_ports(args.ports)
        if not args.json:
            print(f"Grabbing banners on {ALLOWED_TARGET} (localhost only)...\n")
        for port in ports:
            banner = grab_banner(port, args.timeout)
            if banner is None:
                if not args.json:
                    print(f"port {port}: (no answer)")
                continue
            entries.append((port, banner))

    if not entries:
        print("No banners found. Try --demo to see what real banners look like.")
        sys.exit(0)

    results = [analyse_banner(port, banner) for port, banner in entries]
    print_results(results, args.json)

    # --- optional baseline snapshot / comparison ---
    snapshot = {str(r["port"]): r["banner"] for r in results}
    if args.save:
        try:
            with open(args.save, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            msg = (f"\nBaseline saved to {args.save} "
                   f"({len(snapshot)} banner(s)).")
            print(msg, file=sys.stderr if args.json else sys.stdout)
        except OSError as exc:
            print(f"Error: cannot write {args.save}: {exc}", file=sys.stderr)
            sys.exit(2)
    if args.compare:
        baseline = load_baseline(args.compare)
        current = {int(p): b for p, b in snapshot.items()}
        report_changes(current, baseline, args.json)

    # Exit 1 when any banner leaks an exact (or known-bad) version:
    # that is the "needs attention" signal for scripts.
    if any(r["risk"] == RISK_HIGH for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
