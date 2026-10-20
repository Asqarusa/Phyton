#!/usr/bin/env python3
"""
network_identity.py — "Your laptop's network ID card"

WHAT IT DOES:
    Prints the network identity of the machine it runs on:
      * hostname        — the name your computer calls itself
      * local IP        — the address your home/office router gave you
      * MAC address     — the permanent hardware ID of your network card
      * public IP       — the address the internet sees (your router's face)
    Then it explains private vs. public addresses in plain English.

THE ANALOGY:
    Your local IP is like your apartment number inside a building — it only
    makes sense inside that building. Your public IP is the building's street
    address — that's what the outside world sees. The MAC address is like the
    serial number engraved on your phone: it never changes, wherever you go.

WHY IT MATTERS (SOC angle):
    When a SOC analyst reads a firewall or proxy log, the first question is
    always: "Is this traffic MINE, or is it the attacker?" If you don't know
    your own machine's IPs, you can't tell your own shadow from an intruder.

SAFETY:
    100% read-only. We ask the operating system for information about our own
    machine and make ONE tiny web request (api.ipify.org) to learn our public
    IP — the same thing every "what is my IP" website does. No scanning,
    no credentials, nothing leaves the machine except that one IP lookup.

USAGE:
    python3 network_identity.py
"""

import socket
import uuid
import urllib.request

# A tiny public service that simply echoes back your public IP as text.
# Used with a timeout; if it fails, we report that gracefully.
PUBLIC_IP_URL = "https://api.ipify.org"


def get_hostname():
    """Ask the OS for this computer's name (like 'laptop-7')."""
    return socket.gethostname()


def get_local_ip():
    """Find the local IP we'd use to reach the internet.

    Trick: open a UDP "connection" to a public address. No packet is ever
    sent (UDP connect just picks a route), but the OS then tells us which
    local address it would use — that IS our local IP.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))          # Google DNS; nothing is sent
        return sock.getsockname()[0]           # our end of the would-be route
    except OSError:
        return "unavailable (no network route)"
    finally:
        sock.close()


def get_mac():
    """Return the MAC address of the primary network interface, pretty-printed.

    uuid.getnode() asks the OS for the hardware address of the network card.
    It comes back as one big number, so we slice it into 6 pairs of hex
    digits, e.g. 02:42:ac:11:00:02.
    """
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def get_public_ip():
    """Ask the internet what our public IP is.

    Everything on your home network shares ONE public IP (your router's).
    This request leaves your machine but reveals nothing private — the
    service only sees the same public address any website would see.
    """
    try:
        request = urllib.request.Request(
            PUBLIC_IP_URL, headers={"User-Agent": "network-identity-tool"}
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode().strip()
    except Exception:
        return "unavailable (offline or blocked)"


def is_private(ip):
    """True if the IP is a private (inside-the-building) address."""
    try:
        first, second = (int(part) for part in ip.split(".")[:2])
    except ValueError:
        return False
    return (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
    )


def main():
    hostname = get_hostname()
    local_ip = get_local_ip()
    mac = get_mac()
    public_ip = get_public_ip()

    print("=" * 58)
    print("  YOUR LAPTOP'S NETWORK ID CARD")
    print("=" * 58)
    print(f"  Hostname : {hostname}")
    print(f"  Local IP : {local_ip}   <-- your 'apartment number'")
    print(f"  MAC      : {mac}   <-- engraved hardware serial")
    print(f"  Public IP: {public_ip}   <-- the building's 'street address'")
    print("=" * 58)

    # --- The SOC takeaway, computed live ---
    print("\nWhat this means:")
    if is_private(local_ip):
        print(f"  * {local_ip} is a PRIVATE address: it only works inside your")
        print("    own network. Millions of homes reuse the same private")
        print("    ranges (10.x.x.x, 172.16–31.x.x, 192.168.x.x).")
    print(f"  * {public_ip} is what the whole internet sees. Every device in")
    print("    your home shares it — your router translates between the two.")
    print("  * SOC rule of thumb: when you read a log, first check whether an")
    print("    IP is one of YOURS. Your own traffic is the baseline;")
    print("    everything else deserves a second look.")


if __name__ == "__main__":
    main()
