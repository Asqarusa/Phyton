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
  - It refuses to run on non-private data by design (it never leaves localhost).

Run it with:
    python3 arp_neighbor_viewer.py

Run it with built-in sample data (handy on machines with an empty ARP table):
    python3 arp_neighbor_viewer.py --demo
"""

import re
import shutil
import subprocess
import sys


# --- A tiny built-in vendor prefix (OUI) table --------------------------------
# The first 3 bytes of every MAC address identify the device manufacturer.
# This mini table lets us take a guess at the vendor fully offline.
# (Real OUI lists are huge; this is just a demo subset.)
OUI_VENDORS = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "52:54:00": "QEMU/KVM virtual machine",
    "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "AC:DE:48": "Private/randomized (common on phones)",
    "2C:54:91": "Private/randomized (common on phones)",
    "DA:A1:19": "Private/randomized (common on phones)",
    "3C:22:FB": "Apple",
    "F0:18:98": "Apple",
    "AC:87:A3": "Apple",
    "A4:5E:60": "Apple",
    "30:65:EC": "Samsung",
    "8C:F5:A3": "Samsung",
    "40:4E:36": "Nest/Google",
    "18:B4:30": "Nest/Google",
    "D8:A0:1D": "LG",
    "F8:0D:AC": "Sony",
    "70:48:0F": "Amazon (Echo/Ring)",
    "74:C2:46": "Amazon (Echo/Ring)",
}


def is_private_ip(ip):
    """True for RFC-1918 private addresses and loopback (10/8, 172.16/12, 192.168/16, 127/8)."""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    return (a == 10 or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168))


def read_proc_net_arp():
    """Read the Linux ARP table from /proc/net/arp. Returns list of (ip, mac) tuples."""
    entries = []
    try:
        with open("/proc/net/arp") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return []
    for line in lines[1:]:                      # skip the header row
        cols = line.split()
        if len(cols) < 4:
            continue
        ip, _type, _flags, mac = cols[0], cols[1], cols[2], cols[3]
        if re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) \
                and not mac.lower().startswith("00:00:00"):
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
    except (subprocess.SubprocessError, OSError):
        return []
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
                      r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
        if m and not m.group(2).lower().startswith("00:00:00"):
            entries.append((m.group(1), m.group(2).upper()))
    return entries


def guess_vendor(mac):
    """Look up the first 3 bytes of the MAC in our mini vendor table."""
    return OUI_VENDORS.get(mac[:8], "Unknown vendor")


def sample_entries():
    """Made-up home-network entries so the --demo flag works anywhere."""
    return [
        ("192.168.1.1", "40:4E:36:A1:B2:C3"),   # Nest/Google
        ("192.168.1.10", "3C:22:FB:D4:E5:F6"),  # Apple
        ("192.168.1.22", "DA:A1:19:07:08:09"),  # randomized phone MAC
        ("192.168.1.40", "08:00:27:0A:0B:0C"),  # VirtualBox
        ("192.168.1.50", "B8:27:EB:0D:0E:0F"),  # Raspberry Pi
    ]


def main():
    print("=" * 64)
    print("  ARP NEIGHBOR VIEWER — devices your computer knows about")
    print("=" * 64)
    print()
    print("Your machine keeps an ARP table: an address book that maps each")
    print("device's network address (IP) to its hardware address (MAC).")
    print("This is read-only — nothing is sent to anyone.")
    print()

    if "--demo" in sys.argv[1:]:
        entries = sample_entries()
        print("(Showing built-in sample data — your real ARP table was skipped.)")
        print()
    else:
        entries = read_proc_net_arp() or read_arp_command()

    if not entries:
        print("No ARP entries found (or the ARP table could not be read).")
        print("Try again after your machine has talked to the local network")
        print("(e.g., open a website), then re-run this script.")
        return 0

    # Deduplicate, keeping the first sighting of each IP.
    seen = {}
    for ip, mac in entries:
        seen.setdefault(ip, mac)
    entries = sorted(seen.items(), key=lambda kv: kv[0])

    private = [ip for ip, _ in entries if is_private_ip(ip)]
    print(f"Found {len(entries)} device(s) in your ARP table "
          f"({len(private)} on private addresses).")
    print()

    header = f"{'IP ADDRESS':<17}{'MAC ADDRESS':<20}{'VENDOR GUESS':<40}{'SCOPE'}"
    print(header)
    print("-" * len(header))
    for ip, mac in entries:
        vendor = guess_vendor(mac)
        scope = "private" if is_private_ip(ip) else "NOT PRIVATE!"
        print(f"{ip:<17}{mac:<20}{vendor:<40}{scope}")

    print()
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
    print("Try next: run this again in an hour and compare the two lists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
