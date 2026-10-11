#!/usr/bin/env python3
"""
Subnet Calculator — Day 07 (Networking)

Given an IP address in CIDR notation (like 192.168.1.10/24), this script
breaks it into every piece a network engineer would want to see:
network address, broadcast address, subnet mask, usable host range,
and how many devices can live on that subnet.

USAGE:
    python3 subnet_calculator.py 192.168.1.10/24
    python3 subnet_calculator.py              # uses a default example

Everything here is read-only math on an address YOU type in.
No network scanning, no traffic, no packets — totally safe to run.
"""

import ipaddress  # Python's built-in library for working with IP addresses
import sys        # lets us read command-line arguments


def bits_of(address_int):
    """Turn a 32-bit integer into a dotted-binary string like '11000000.10101000...'"""
    # format(..., '032b') = 32 characters of 0s and 1s, padded with leading zeros
    bits = format(address_int, '032b')
    # split into 8-bit chunks and join with dots for readability
    return '.'.join(bits[i:i + 8] for i in range(0, 32, 8))


def ip_class(first_octet):
    """The old 'class' system (A/B/C) is still useful shorthand for subnet sizes."""
    if 1 <= first_octet <= 126:
        return "A (default /8 — huge, ~16 million addresses)"
    if 128 <= first_octet <= 191:
        return "B (default /16 — medium, ~65 thousand addresses)"
    if 192 <= first_octet <= 223:
        return "C (default /24 — small, 254 usable addresses)"
    return "D/E (special use — multicast or experimental)"


def describe(cidr_text):
    """Do all the subnet math and print a beginner-friendly breakdown."""
    # strict=False lets the user pass a host address like 192.168.1.10/24,
    # not only the network address 192.168.1.0/24.
    network = ipaddress.ip_network(cidr_text, strict=False)
    prefix = network.prefixlen          # the "/24" part
    mask = network.netmask              # the subnet mask as an IP object
    wildcard = network.hostmask         # inverse of the mask (used in ACLs)

    total = network.num_addresses       # ALL addresses, including reserved ones
    # The first address (network) and last address (broadcast) are reserved,
    # except for tiny /31 and /32 subnets which have special rules.
    if prefix <= 30:
        usable = total - 2
        first = network.network_address + 1
        last = network.broadcast_address - 1
    elif prefix == 31:
        usable = 2      # point-to-point link: both addresses are usable
        first = network.network_address
        last = network.broadcast_address
    else:  # /32 — a single host address
        usable = 1
        first = network.network_address
        last = network.network_address

    first_octet = int(str(network.network_address).split('.')[0])
    private = network.network_address.is_private

    print(f"\n{'=' * 58}")
    print(f"  SUBNET BREAKDOWN: {cidr_text}")
    print(f"{'=' * 58}\n")

    print("--- Addresses ---")
    print(f"  Your IP:          {cidr_text.split('/')[0]}")
    print(f"  Network address:  {network.network_address}   (identifies the subnet itself)")
    print(f"  Broadcast:        {network.broadcast_address}   (talks to EVERYONE on the subnet)")
    if prefix <= 30:
        print(f"  First usable:     {first}")
        print(f"  Last usable:      {last}")

    print("\n--- Masks ---")
    print(f"  CIDR notation:    /{prefix}")
    print(f"  Subnet mask:      {mask}")
    print(f"  Wildcard mask:    {wildcard}   (inverse mask, used in firewall rules)")

    print("\n--- Size ---")
    print(f"  Total addresses:  {total}")
    print(f"  Usable for hosts: {usable}")

    print("\n--- Classification ---")
    print(f"  Class:            {ip_class(first_octet)}")
    print(f"  Private (RFC1918): {'YES — internal use only' if private else 'NO — public, routable on the internet'}")

    print("\n--- Binary view (how the computer sees it) ---")
    print(f"  IP:       {bits_of(int(network.network_address) + (0 if prefix > 30 else 1))}")
    print(f"  Mask:     {bits_of(int(mask))}")
    print(f"  Network:  {bits_of(int(network.network_address))}")
    print("\n  The mask's 1-bits mark the NETWORK part; 0-bits mark the HOST part.")
    print(f"{'=' * 58}\n")


def main():
    # Take the address from the command line, or fall back to a home-network example.
    if len(sys.argv) > 1:
        cidr_text = sys.argv[1]
    else:
        cidr_text = "192.168.1.10/24"
        print(f"(No address given — using a typical home-network example: {cidr_text})")

    # Basic sanity check before doing any math.
    if '/' not in cidr_text:
        print(f"ERROR: '{cidr_text}' needs CIDR notation, e.g. 192.168.1.10/24")
        print("       (the /24 says the first 24 bits are the network part)")
        sys.exit(1)

    try:
        describe(cidr_text)
    except ValueError as e:
        # ipaddress raises ValueError for things like 999.1.1.1/24 or /33
        print(f"ERROR: could not parse '{cidr_text}': {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
