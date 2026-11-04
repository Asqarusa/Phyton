#!/usr/bin/env python3
"""
arp_neighbor_viewer.py — Who is on my local network? (read-only)

A beginner-friendly tool that shows which devices your computer currently
knows about on your own local network. It reads your machine's ARP table —
the little address book your operating system keeps that maps IP addresses
to hardware (MAC) addresses.

This script is 100% READ-ONLY:
  - It only reads information your own computer already has.
  - It sends NO packets, touches NO other device, and makes NO network calls.
  - It never leaves your own machine.

What's new in this version (2026-11-03):
  - Real command-line flags: --demo, --json, --save, --compare,
    --unknown-only, --quiet (run --help to see them all).
  - Spoofing checks: flags an IP claimed by two different MACs, and one
    MAC claiming several IPs — the two classic signs of ARP spoofing.
  - Baseline snapshots: --save stores today's device list; --compare
    against a saved list flags NEW, GONE, and CHANGED devices.
  - Bigger vendor table (more makers guessed offline) and numeric IP
    sorting, so 192.168.1.2 now correctly comes before 192.168.1.10.
  - Friendlier errors with exit code 2 for bad input or unreadable files.

Run it with:
    python3 arp_neighbor_viewer.py

See sample data (handy on machines with an empty ARP table):
    python3 arp_neighbor_viewer.py --demo

Save a baseline, then compare later to spot new or missing devices:
    python3 arp_neighbor_viewer.py --save baseline.json
    python3 arp_neighbor_viewer.py --compare baseline.json

Machine-readable output:
    python3 arp_neighbor_viewer.py --json
"""

import argparse
import json
import re
import shutil
import subprocess
import sys


# --- A built-in vendor prefix (OUI) table ------------------------------------
# The first 3 bytes of every MAC address identify the device manufacturer.
# This table lets us take a guess at the vendor fully offline.
# (Real OUI lists are huge; this is a demo subset.)
OUI_VENDORS = {
    # Virtual machines / hypervisors
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "52:54:00": "QEMU/KVM virtual machine",
    "08:00:27": "VirtualBox",
    # Single-board computers
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # Randomized / private MACs (common on phones)
    "AC:DE:48": "Private/randomized (common on phones)",
    "2C:54:91": "Private/randomized (common on phones)",
    "DA:A1:19": "Private/randomized (common on phones)",
    # Apple
    "3C:22:FB": "Apple",
    "F0:18:98": "Apple",
    "AC:87:A3": "Apple",
    "A4:5E:60": "Apple",
    "F4:5C:89": "Apple",
    "D8:9E:3F": "Apple",
    # Samsung
    "30:65:EC": "Samsung",
    "8C:F5:A3": "Samsung",
    "84:25:19": "Samsung",
    # Google / Nest
    "40:4E:36": "Nest/Google",
    "18:B4:30": "Nest/Google",
    "F4:F5:D8": "Google",
    # Other consumer electronics
    "D8:A0:1D": "LG",
    "F8:0D:AC": "Sony",
    "70:48:0F": "Amazon (Echo/Ring)",
    "74:C2:46": "Amazon (Echo/Ring)",
    "50:F5:DA": "Amazon (Echo/Ring)",
    "FC:A1:83": "Amazon (Echo/Ring)",
    # Network gear
    "00:14:BF": "Cisco/Linksys",
    "00:1A:8A": "Cisco",
    "68:7F:74": "Cisco",
    "00:23:69": "Cisco",
    "E8:DE:27": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A8:9C:ED": "Netgear",
    "00:1F:33": "Netgear",
    "C0:3F:0E": "Netgear",
    "04:18:D6": "Netgear",
    "00:0F:B5": "Netgear",
    # PC makers
    "00:1E:37": "Dell",
    "F8:BC:12": "Dell",
    "00:26:B9": "Dell",
    "00:25:64": "Dell",
    "3C:97:0E": "Hewlett Packard",
    "D8:D3:85": "Hewlett Packard",
    "A0:D3:C1": "Hewlett Packard",
    "B0:5A:DA": "Hewlett Packard",
    "00:15:5D": "Microsoft (Hyper-V)",
    # Other common makers
    "00:1A:11": "Google (Chromecast)",
    "48:5D:60": "Intel",
    "A4:34:D9": "Intel",
    "34:02:86": "Intel",
    "E0:2A:82": "Huawei",
    "48:46:FB": "Huawei",
    "64:09:80": "Xiaomi",
    "F0:B4:29": "Xiaomi",
    "7C:2F:80": "Xiaomi",
    "C8:3D:D4": "Sonos",
    "B8:E9:37": "Sonos",
}

MAC_RE = re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def fail(message):
    """Print a friendly error and exit with code 2 (bad input)."""
    print(f"Error: {message}", file=sys.stderr)
    print("Run with --help to see the options.", file=sys.stderr)
    sys.exit(2)


def is_private_ip(ip):
    """True for RFC-1918 private addresses and loopback (10/8, 172.16/12, 192.168/16, 127/8)."""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    nums = [int(p) for p in parts]
    if any(n > 255 for n in nums):
        return False
    a, b = nums[0], nums[1]
    return (a == 10 or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168))


def is_valid_ip(ip):
    """True only for a well-formed dotted-quad address (0-255 per octet)."""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    return all(0 <= int(p) <= 255 for p in parts)


def read_proc_net_arp():
    """Read the Linux ARP table from /proc/net/arp. Returns list of (ip, mac) tuples."""
    entries = []
    try:
        with open("/proc/net/arp") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        print(f"Warning: could not read /proc/net/arp ({exc}); trying `arp -a`.",
              file=sys.stderr)
        return []
    for line in lines[1:]:                      # skip the header row
        cols = line.split()
        if len(cols) < 4:
            continue
        ip, mac = cols[0], cols[3]
        if MAC_RE.fullmatch(mac) and not mac.lower().startswith("00:00:00"):
            entries.append((ip, mac.upper()))
    return entries


def read_arp_command():
    """Fallback: parse `arp -a` output (works on macOS and many Linuxes)."""
    entries = []
    arp = shutil.which("arp")
    if not arp:
        return []
    try:
        out = subprocess.run([arp, "-a"], capture_output=True, text=True,
                             timeout=10).stdout
    except subprocess.TimeoutExpired:
        print("Warning: `arp -a` timed out after 10 seconds.", file=sys.stderr)
        return []
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"Warning: could not run `arp -a` ({exc}).", file=sys.stderr)
        return []
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
                      r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
        if m and is_valid_ip(m.group(1)) \
                and not m.group(2).lower().startswith("00:00:00"):
            entries.append((m.group(1), m.group(2).upper()))
    return entries


def guess_vendor(mac):
    """Look up the first 3 bytes of the MAC in our vendor table."""
    return OUI_VENDORS.get(mac[:8], "Unknown vendor")


def ip_sort_key(ip):
    """Sort IPs numerically (so 192.168.1.2 sorts before 192.168.1.10)."""
    return tuple(int(p) for p in ip.split("."))


def detect_spoofing(entries):
    """Spot the two classic ARP-spoofing red flags.

    Returns a list of warning strings (empty when the table looks clean):
      - one IP claimed by two or more different MACs
      - one MAC claiming two or more different IPs
    """
    warnings = []
    ip_to_macs = {}
    mac_to_ips = {}
    for ip, mac in entries:
        ip_to_macs.setdefault(ip, set()).add(mac)
        mac_to_ips.setdefault(mac, set()).add(ip)
    for ip in sorted(ip_to_macs, key=ip_sort_key):
        macs = sorted(ip_to_macs[ip])
        if len(macs) > 1:
            warnings.append(
                f"POSSIBLE SPOOFING: {ip} is claimed by {len(macs)} different "
                f"MACs ({', '.join(macs)}) — two devices are pretending to "
                f"be the same address.")
    for mac in sorted(mac_to_ips):
        ips = sorted(mac_to_ips[mac], key=ip_sort_key)
        if len(ips) > 1:
            warnings.append(
                f"SUSPICIOUS: MAC {mac} claims {len(ips)} different IPs "
                f"({', '.join(ips)}) — one device is pretending to be "
                f"several addresses.")
    return warnings


def sample_entries():
    """Made-up home-network entries so --demo works anywhere.

    Includes one spoofing example on purpose: 192.168.1.1 is claimed by
    two different MACs, so the demo shows what a warning looks like.
    """
    return [
        ("192.168.1.1", "40:4E:36:A1:B2:C3"),   # Nest/Google (router)
        ("192.168.1.1", "3C:22:FB:AA:BB:CC"),   # same IP, different MAC: spoof!
        ("192.168.1.10", "3C:22:FB:D4:E5:F6"),  # Apple
        ("192.168.1.22", "DA:A1:19:07:08:09"),  # randomized phone MAC
        ("192.168.1.40", "08:00:27:0A:0B:0C"),  # VirtualBox
        ("192.168.1.50", "B8:27:EB:0D:0E:0F"),  # Raspberry Pi
        ("192.168.1.60", "E8:DE:27:11:22:33"),  # TP-Link
        ("192.168.1.2", "A8:9C:ED:44:55:66"),   # Netgear (sorts before .10)
    ]


def load_baseline(path):
    """Load a baseline saved earlier with --save. Returns {ip: mac}."""
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        fail(f"baseline file not found: {path}")
    except json.JSONDecodeError:
        fail(f"baseline file is not valid JSON: {path}")
    except OSError as exc:
        fail(f"could not read baseline file {path}: {exc}")
    if not isinstance(data, dict) or "entries" not in data \
            or not isinstance(data["entries"], dict):
        fail(f"baseline file has an unexpected format: {path} "
             f"(expected a --save file with an 'entries' object)")
    bad = [ip for ip, mac in data["entries"].items()
           if not is_valid_ip(ip) or not MAC_RE.fullmatch(str(mac))]
    if bad:
        fail(f"baseline file {path} has invalid entries: {', '.join(bad[:3])}")
    return {ip: mac.upper() for ip, mac in data["entries"].items()}


def save_baseline(path, entries):
    """Save the current device list as JSON for later --compare runs."""
    data = {"tool": "arp_neighbor_viewer", "entries": dict(entries)}
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
    except OSError as exc:
        fail(f"could not write baseline file {path}: {exc}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Show the devices your computer knows about on your "
                    "local network (read-only ARP table viewer).")
    parser.add_argument("--demo", action="store_true",
                        help="show built-in sample data instead of the real "
                             "ARP table (includes a spoofing example)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of a table")
    parser.add_argument("--save", metavar="FILE",
                        help="save the current device list to FILE for later "
                             "comparison with --compare")
    parser.add_argument("--compare", metavar="FILE",
                        help="compare the current device list with a baseline "
                             "saved earlier with --save; flags NEW, GONE and "
                             "CHANGED devices")
    parser.add_argument("--unknown-only", action="store_true",
                        help="show only devices whose vendor we could not guess")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the table (skip the explanations)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.save and args.compare and args.save == args.compare:
        fail("--save and --compare cannot use the same file")

    if args.demo:
        entries = sample_entries()
        demo_note = "(Showing built-in sample data — your real ARP table was skipped.)"
    else:
        entries = read_proc_net_arp() or read_arp_command()
        demo_note = ""

    # Keep every sighting (duplicates matter for spoofing detection), but
    # dedupe for the table: one row per IP, first MAC wins.
    table = {}
    for ip, mac in entries:
        table.setdefault(ip, mac)

    if args.unknown_only:
        table = {ip: mac for ip, mac in table.items()
                 if guess_vendor(mac) == "Unknown vendor"}

    warnings = detect_spoofing(entries)
    baseline = load_baseline(args.compare) if args.compare else None

    if args.save:
        save_baseline(args.save, table)

    if args.json:
        result = {
            "entries": [
                {"ip": ip, "mac": mac, "vendor": guess_vendor(mac),
                 "scope": "private" if is_private_ip(ip) else "public"}
                for ip, mac in sorted(table.items(), key=lambda kv: ip_sort_key(kv[0]))
            ],
            "warnings": warnings,
        }
        if baseline is not None:
            current = table
            result["comparison"] = {
                "new": sorted(set(current) - set(baseline), key=ip_sort_key),
                "gone": sorted(set(baseline) - set(current), key=ip_sort_key),
                "changed": sorted(
                    [ip for ip in set(current) & set(baseline)
                     if current[ip] != baseline[ip]], key=ip_sort_key),
            }
        print(json.dumps(result, indent=2))
        return 1 if warnings else 0

    if not args.quiet:
        print("=" * 64)
        print("  ARP NEIGHBOR VIEWER — devices your computer knows about")
        print("=" * 64)
        print()
        print("Your machine keeps an ARP table: an address book that maps each")
        print("device's network address (IP) to its hardware address (MAC).")
        print("This is read-only — nothing is sent to anyone.")
        print()
        if demo_note:
            print(demo_note)
            print()

    if not table:
        if args.unknown_only and entries:
            print("No devices with an unknown vendor in this run.")
        else:
            print("No ARP entries found (or the ARP table could not be read).")
        if not args.quiet:
            print("Try again after your machine has talked to the local network")
            print("(e.g., open a website), then re-run this script.")
        return 0

    private = [ip for ip in table if is_private_ip(ip)]
    known = sum(1 for mac in table.values()
                if guess_vendor(mac) != "Unknown vendor")
    print(f"Found {len(table)} device(s) in your ARP table "
          f"({len(private)} on private addresses, "
          f"{known} with a known vendor).")
    print()

    header = f"{'IP ADDRESS':<17}{'MAC ADDRESS':<20}{'VENDOR GUESS':<40}{'SCOPE'}"
    print(header)
    print("-" * len(header))
    for ip, mac in sorted(table.items(), key=lambda kv: ip_sort_key(kv[0])):
        vendor = guess_vendor(mac)
        scope = "private" if is_private_ip(ip) else "NOT PRIVATE!"
        print(f"{ip:<17}{mac:<20}{vendor:<40}{scope}")

    print()
    for warning in warnings:
        print(f"! {warning}")
    if warnings:
        print()

    if baseline is not None:
        current = table
        new = sorted(set(current) - set(baseline), key=ip_sort_key)
        gone = sorted(set(baseline) - set(current), key=ip_sort_key)
        changed = sorted([ip for ip in set(current) & set(baseline)
                          if current[ip] != baseline[ip]], key=ip_sort_key)
        print("Compared with baseline:")
        if not new and not gone and not changed:
            print("  No changes — the same devices are here as before.")
        for ip in new:
            print(f"  NEW:     {ip} ({current[ip]}, {guess_vendor(current[ip])})")
        for ip in gone:
            print(f"  GONE:    {ip} ({baseline[ip]}, {guess_vendor(baseline[ip])})")
        for ip in changed:
            print(f"  CHANGED: {ip} was {baseline[ip]}, now {current[ip]}")
        print()

    if args.save:
        print(f"Baseline saved to {args.save} "
              f"({len(table)} device(s)).")
        print()

    if not args.quiet:
        print("What this means:")
        print("  * Each row is a device your computer recently communicated with")
        print("    on your local network — your router, your phone, maybe a TV.")
        print("  * A MAC address is the device's permanent hardware name tag; the")
        print("    IP address is its temporary seat number on the network.")
        print("  * 'Unknown vendor' is normal: phones randomize their MACs for")
        print("    privacy, and our mini vendor table only knows a few makers.")
        print()
        print("Why SOC analysts care: an unknown device suddenly appearing in")
        print("the ARP table — especially on a wired office network — is a classic")
        print("sign of a rogue device or an attacker spoofing addresses (ARP")
        print("spoofing). This read-only view is the first step of that check.")
        print()
        print("Try next: save a baseline (--save), run this again in an hour,")
        print("and compare (--compare) to spot what changed.")
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
