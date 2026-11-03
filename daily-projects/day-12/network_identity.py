#!/usr/bin/env python3
"""
network_identity.py — "Your laptop's network ID card" (improved)

WHAT IT DOES:
    Prints the network identity of the machine it runs on:
      * hostname        — the name your computer calls itself
      * local IP (v4)   — the address your home/office router gave you
      * local IP (v6)   — the longer IPv6 address, if your network has one
      * all local IPs   — every address on this machine (Wi-Fi, Ethernet,
                          loopback) so you can spot your own traffic anywhere
      * MAC address     — the permanent hardware ID of your network card
      * public IP       — the address the internet sees (your router's face)
    Then it explains private vs. public addresses in plain English, and
    classifies every address it shows (private, public, loopback...).

NEW IN THIS VERSION (2026-11-02):
    * IPv6 local address detection (the original only knew IPv4)
    * Lists ALL local addresses, not just the one used for the internet
    * --check <ip> classifies any IP you paste in (private/public/loopback/
      link-local/CGNAT/documentation) with a one-line SOC hint
    * --json prints the whole ID card as machine-readable JSON
    * --demo runs fully offline with sample addresses (great for practice)
    * --no-public skips the public-IP lookup; --timeout sets how long to wait
    * Friendlier errors: bad IPs and bad flags exit with code 2 and a
      plain-English message instead of a traceback

THE ANALOGY:
    Your local IP is like your apartment number inside a building — it only
    makes sense inside that building. Your public IP is the building's street
    address — that's what the outside world sees. The MAC address is like the
    serial number engraved on your phone: it never changes, wherever you go.

WHY IT MATTERS (SOC angle):
    When a SOC analyst reads a firewall or proxy log, the first question is
    always: "Is this traffic MINE, or is it the attacker?" If you don't know
    your own machine's IPs, you can't tell your own shadow from an intruder.
    Listing every local address — including IPv6 and loopback — means your
    own traffic can never hide from you in a log.

SAFETY:
    100% read-only. We ask the operating system for information about our own
    machine and make ONE tiny web request (api.ipify.org) to learn our public
    IP — the same thing every "what is my IP" website does. No scanning,
    no credentials, nothing leaves the machine except that one IP lookup.
    --demo and --check never touch the network at all.

USAGE:
    python3 network_identity.py               # the ID card
    python3 network_identity.py --demo        # sample data, fully offline
    python3 network_identity.py --json        # same card, as JSON
    python3 network_identity.py --no-public   # skip the public-IP lookup
    python3 network_identity.py --check 8.8.8.8   # classify any IP
    python3 network_identity.py --help        # all options
"""

import argparse
import ipaddress
import json
import socket
import sys
import uuid
import urllib.error
import urllib.request

# A tiny public service that simply echoes back your public IP as text.
# Used with a timeout; if it fails, we report that gracefully.
PUBLIC_IP_URL = "https://api.ipify.org"

# Sample addresses for --demo mode. These use documentation ranges
# (192.0.2.x, 2001:db8::/32) that can never belong to a real machine,
# so the demo is safe to screenshot, share, or paste anywhere.
DEMO_DATA = {
    "hostname": "demo-laptop",
    "local_ipv4": "192.168.1.42",
    "local_ipv6": "2001:db8:85a3::8a2e:370:7334",
    "all_local_ips": ["192.168.1.42", "127.0.0.1", "2001:db8:85a3::8a2e:370:7334", "::1"],
    "mac": "02:42:ac:11:00:02",
    "public_ip": "203.0.113.77",
}


def get_hostname():
    """Ask the OS for this computer's name (like 'laptop-7')."""
    return socket.gethostname()


def get_local_ip(version=4):
    """Find the local IP we'd use to reach the internet.

    Trick: open a UDP "connection" to a public address. No packet is ever
    sent (UDP connect just picks a route), but the OS then tells us which
    local address it would use — that IS our local IP.
    version=4 uses Google DNS (8.8.8.8); version=6 uses Google's IPv6 DNS.
    Returns None when that address family isn't available on this machine.
    """
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    target = ("8.8.8.8", 80) if version == 4 else ("2001:4860:4860::8888", 80)
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.connect(target)                 # nothing is sent, route only
        return sock.getsockname()[0]         # our end of the would-be route
    except OSError:
        return None                          # e.g. no IPv6 on this network
    finally:
        sock.close()


def get_all_local_ips():
    """List every IP address assigned to this machine.

    socket.getaddrinfo(hostname) asks the OS for all addresses tied to our
    own name: Wi-Fi, Ethernet, loopback (127.0.0.1 / ::1), and any extras.
    Duplicates are removed, order kept stable for readable output.
    """
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in found:
                found.append(ip)
    except socket.gaierror:
        pass                                 # hostname didn't resolve; fine
    return found


def get_mac():
    """Return the MAC address of the primary network interface, pretty-printed.

    uuid.getnode() asks the OS for the hardware address of the network card.
    It comes back as one big number, so we slice it into 6 pairs of hex
    digits, e.g. 02:42:ac:11:00:02.
    If the OS has no real card to report, it invents a random address — we
    spot that (first byte's lowest bit set = "locally administered") and say so.
    """
    node = uuid.getnode()
    mac = ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))
    if node & 0x020000000000:
        # The "locally administered" bit is set: this is a made-up address,
        # not one burned into a real network card.
        return mac + "  (random — no hardware address found)"
    return mac


def get_public_ip(timeout=10):
    """Ask the internet what our public IP is.

    Everything on your home network shares ONE public IP (your router's).
    This request leaves your machine but reveals nothing private — the
    service only sees the same public address any website would see.
    The reply is checked to make sure it really looks like an IP address,
    so a captive portal or error page can't sneak in as a fake answer.
    Returns None when offline, blocked, or the answer isn't an IP.
    """
    try:
        request = urllib.request.Request(
            PUBLIC_IP_URL, headers={"User-Agent": "network-identity-tool"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            candidate = response.read().decode().strip()
        ipaddress.ip_address(candidate)      # raises ValueError if not an IP
        return candidate
    except (ValueError, urllib.error.URLError, OSError, UnicodeDecodeError):
        return None


def _in_network(ip, network):
    """True if ip belongs to network; safe across IPv4/IPv6 (no TypeError)."""
    net = ipaddress.ip_network(network)
    return ip.version == net.version and ip in net


def classify(ip_text):
    """Classify an IP address in plain English.

    Returns (label, soc_hint) — e.g. ("private", "safe to ignore in most
    logs: it's inside your own network"). Uses Python's ipaddress module,
    which knows every special range, so no hand-rolled octet math.
    Raises ValueError for text that isn't an IP address at all.
    """
    ip = ipaddress.ip_address(ip_text)       # raises ValueError on junk
    if ip.is_loopback:
        return ("loopback",
                "this machine talking to itself — normal, ignore in logs")
    if ip.is_link_local:
        return ("link-local",
                "self-assigned address (no router/DHCP) — worth a look if unexpected")
    if _in_network(ip, "100.64.0.0/10"):
        return ("CGNAT (carrier-grade NAT)",
                "your ISP's shared address pool — not your LAN, not the internet")
    if _in_network(ip, "198.18.0.0/15"):
        return ("benchmarking range",
                "reserved for network testing — should never appear in real traffic")
    if (_in_network(ip, "192.0.2.0/24") or _in_network(ip, "198.51.100.0/24")
            or _in_network(ip, "203.0.113.0/24") or _in_network(ip, "2001:db8::/32")):
        return ("documentation / reserved",
                "example-only address — should never appear in real traffic")
    if ip.is_private:
        return ("private",
                "inside your own network — your baseline, usually safe to ignore")
    if ip.is_multicast:
        return ("multicast",
                "one-to-many group traffic — check it's a service you expect")
    if ip.is_global:
        return ("public",
                "visible on the whole internet — verify you expect this one")
    return ("special-purpose",
            "unusual address — look it up before trusting it")


def is_private(ip):
    """True if the IP is a private (inside-the-building) address.

    Kept for backwards compatibility with the original script; new code
    should use classify() instead.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def collect_identity(args):
    """Gather every field of the ID card into one dictionary."""
    if args.demo:
        return dict(DEMO_DATA)

    local_v4 = get_local_ip(4)
    local_v6 = get_local_ip(6)
    all_ips = get_all_local_ips()
    # Make sure the headline addresses are listed even if getaddrinfo missed them.
    for ip in (local_v4, local_v6):
        if ip and ip not in all_ips:
            all_ips.insert(0, ip)

    public = None if args.no_public else get_public_ip(timeout=args.timeout)

    return {
        "hostname": get_hostname(),
        "local_ipv4": local_v4 or "unavailable (no IPv4 route)",
        "local_ipv6": local_v6 or "unavailable (no IPv6 on this network)",
        "all_local_ips": all_ips,
        "mac": get_mac(),
        "public_ip": public or "unavailable (offline or blocked)",
    }


def print_card(card):
    """Print the ID card in the friendly human-readable layout."""
    print("=" * 58)
    print("  YOUR LAPTOP'S NETWORK ID CARD")
    print("=" * 58)
    print(f"  Hostname : {card['hostname']}")
    print(f"  Local IP : {card['local_ipv4']}   <-- your 'apartment number'")
    print(f"  Local v6 : {card['local_ipv6']}")
    print(f"  MAC      : {card['mac']}   <-- engraved hardware serial")
    print(f"  Public IP: {card['public_ip']}   <-- the building's 'street address'")
    print("=" * 58)

    print("\nAll addresses on this machine:")
    if card["all_local_ips"]:
        for ip in card["all_local_ips"]:
            label, _hint = classify(ip)
            print(f"  * {ip:<42} {label}")
    else:
        print("  (none found)")

    # --- The SOC takeaway, computed live ---
    print("\nWhat this means:")
    try:
        label, _hint = classify(card["local_ipv4"])
        if label == "private":
            print(f"  * {card['local_ipv4']} is PRIVATE: it only works inside")
            print("    your own network. Millions of homes reuse the same private")
            print("    ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x).")
        else:
            print(f"  * {card['local_ipv4']} is {label.upper()} — not a normal")
            print("    home private address. Worth a second look if you expected")
            print("    a 192.168.x.x or 10.x.x.x address here.")
    except ValueError:
        print("  * No local IPv4 address was found — check your network cable/Wi-Fi.")
    print(f"  * {card['public_ip']} is what the whole internet sees. Every device")
    print("    in your home shares it — your router translates between the two.")
    print("  * SOC rule of thumb: when you read a log, first check whether an")
    print("    IP is one of YOURS. Your own traffic is the baseline;")
    print("    everything else deserves a second look.")


def check_ip(ip_text):
    """Handle --check: classify one IP and print the verdict. Exit code 2 on junk."""
    try:
        label, hint = classify(ip_text)
    except ValueError:
        print(f"error: '{ip_text}' is not a valid IP address.", file=sys.stderr)
        print("Try something like 192.168.1.1, 8.8.8.8, or ::1.", file=sys.stderr)
        return 2
    print(f"{ip_text}  ->  {label}")
    print(f"  SOC hint: {hint}")
    return 0


def parse_args(argv=None):
    """Define the command-line flags (argparse prints --help for free)."""
    parser = argparse.ArgumentParser(
        description="Print your machine's network ID card (hostname, IPs, MAC, public IP)."
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="show the ID card with sample data (fully offline, safe to share)")
    parser.add_argument(
        "--json", action="store_true",
        help="print the ID card as JSON instead of the human-readable layout")
    parser.add_argument(
        "--no-public", action="store_true",
        help="skip the public-IP lookup (stays fully local)")
    parser.add_argument(
        "--timeout", type=int, default=10, metavar="SECONDS",
        help="how long to wait for the public-IP lookup (default: 10)")
    parser.add_argument(
        "--check", metavar="IP",
        help="classify one IP address (private/public/loopback/...) and exit")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")
    return args


def main(argv=None):
    args = parse_args(argv)

    if args.check:
        return check_ip(args.check)

    card = collect_identity(args)

    if args.json:
        print(json.dumps(card, indent=2))
    else:
        print_card(card)
    return 0


if __name__ == "__main__":
    sys.exit(main())
