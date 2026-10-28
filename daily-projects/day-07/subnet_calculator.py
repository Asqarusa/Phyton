#!/usr/bin/env python3
"""
Subnet Calculator — Day 07 (Networking) — IMPROVED version

Given an IP address in CIDR notation (like 192.168.1.10/24), this script
breaks it into every piece a network engineer would want to see:
network address, broadcast address, subnet mask, usable host range,
and how many devices can live on that subnet.

NEW in this version:
  * Works with IPv6 as well as IPv4 (the original only handled IPv4).
  * Command-line flags: --demo, --json, --split N, --hosts N.
  * --split N carves a network into N smaller subnets (VLSM in one step).
  * --hosts N answers "what is the smallest subnet that fits N devices?"
  * Friendlier error messages: a missing "/24" or a typo now gets a
    plain-English hint instead of a bare traceback.

USAGE:
    python3 subnet_calculator.py 192.168.1.10/24
    python3 subnet_calculator.py 2001:db8::1/64     # IPv6 works too
    python3 subnet_calculator.py --demo            # four worked examples
    python3 subnet_calculator.py 192.168.1.0/24 --split 4
    python3 subnet_calculator.py 10.0.0.0/24 --hosts 50
    python3 subnet_calculator.py 192.168.1.10/24 --json

Everything here is read-only math on an address YOU type in.
No network scanning, no traffic, no packets — totally safe to run.
"""

import argparse  # friendly command-line flags with built-in --help text
import ipaddress  # Python's built-in library for working with IP addresses
import json       # for the --json machine-readable output
import math       # ceil/log2 for the --split and --hosts sizing math
import sys        # lets us exit with a clear error code


def bits_of(address_int, total_bits):
    """Turn an address integer into a readable binary string.

    IPv4 uses 32 bits (shown as four 8-bit groups); IPv6 uses 128 bits
    (shown as sixteen 8-bit groups, wrapped for readability).
    """
    bits = format(address_int, f"0{total_bits}b")
    groups = [bits[i:i + 8] for i in range(0, total_bits, 8)]
    if total_bits <= 32:
        return ".".join(groups)
    # IPv6: break the long string into lines of 4 groups so it stays readable.
    lines = [" ".join(groups[i:i + 4]) for i in range(0, len(groups), 4)]
    return "\n           ".join(lines)


def ip_class(first_octet):
    """The old 'class' system (A/B/C) is still useful shorthand for IPv4."""
    if 1 <= first_octet <= 126:
        return "A (default /8 — huge, ~16 million addresses)"
    if 128 <= first_octet <= 191:
        return "B (default /16 — medium, ~65 thousand addresses)"
    if 192 <= first_octet <= 223:
        return "C (default /24 — small, 254 usable addresses)"
    return "D/E (special use — multicast or experimental)"


def classify(network):
    """Plain-English labels for what kind of address this is.

    Uses ipaddress's own flags so we never have to hand-code the
    private/public ranges — and so IPv6 gets correct labels too.
    """
    addr = network.network_address
    labels = []
    is_doc_v6 = network.version == 6 and str(addr).startswith("2001:db8")
    if addr.is_loopback:
        labels.append("loopback (this machine only, like 127.0.0.1)")
    if addr.is_link_local:
        labels.append("link-local (works on this cable/Wi-Fi only, no router needed)")
    if addr.is_multicast:
        labels.append("multicast (one packet to a whole group at once)")
    if addr.is_private and not addr.is_loopback and not addr.is_link_local and not is_doc_v6:
        labels.append("private (RFC 1918 / unique-local — internal use only)")
    if addr.is_global:
        labels.append("public / global (routable on the internet)")
    if addr.is_reserved and not labels:
        labels.append("reserved / special use")
    if not labels:
        labels.append("special use")
    # IPv6 neighbourhood names, the same idea as the day-22 explorer.
    if network.version == 6:
        if addr.is_loopback:
            labels.append("IPv6 loopback ::1")
        elif str(addr).startswith("fe80"):
            labels.append("IPv6 link-local fe80::/10")
        elif str(addr).startswith("fc") or str(addr).startswith("fd"):
            labels.append("IPv6 unique-local (private)")
        elif str(addr).startswith("2001:db8"):
            labels.append("IPv6 documentation range (safe for examples)")
    return "; ".join(labels)


def describe(cidr_text):
    """Do all the subnet math. Returns a dict; printing is separate.

    Splitting the math from the printing is what makes --json possible:
    the same numbers feed the human-readable table and the JSON output.
    """
    network = ipaddress.ip_network(cidr_text, strict=False)
    prefix = network.prefixlen
    total = network.num_addresses
    version = network.version

    if version == 4:
        if prefix <= 30:
            usable = total - 2
            first = network.network_address + 1
            last = network.broadcast_address - 1
        elif prefix == 31:
            usable = 2  # point-to-point link: both addresses are usable
            first = network.network_address
            last = network.broadcast_address
        else:  # /32 — a single host address
            usable = 1
            first = network.network_address
            last = network.network_address
        broadcast = str(network.broadcast_address)
        first_octet = int(str(network.network_address).split(".")[0])
        extra = {"class": ip_class(first_octet)}
    else:
        # IPv6 has no broadcast address and no reserved network/broadcast
        # pair in the IPv4 sense: every address in the prefix is usable.
        usable = total
        first = network.network_address
        last = network.broadcast_address  # last address of the range
        broadcast = "(none — IPv6 has no broadcast; it uses multicast instead)"
        extra = {"class": "n/a for IPv6 (classes are an IPv4-only idea)"}

    result = {
        "input": cidr_text,
        "version": version,
        "network": str(network.network_address),
        "broadcast": broadcast,
        "first_usable": str(first),
        "last_usable": str(last),
        "prefix": prefix,
        "netmask": str(network.netmask),
        "wildcard": str(network.hostmask),
        "total_addresses": total,
        "usable_hosts": usable,
        "classification": classify(network),
        **extra,
    }
    return result


def print_breakdown(info):
    """Print the human-readable table from a describe() dict."""
    print(f"\n{'=' * 58}")
    print(f"  SUBNET BREAKDOWN: {info['input']}")
    print(f"{'=' * 58}\n")

    print("--- Addresses ---")
    print(f"  Your IP:          {info['input'].split('/')[0]}")
    print(f"  Network address:  {info['network']}   (identifies the subnet itself)")
    print(f"  Broadcast:        {info['broadcast']}")
    print(f"  First usable:     {info['first_usable']}")
    print(f"  Last usable:      {info['last_usable']}")

    print("\n--- Masks ---")
    print(f"  CIDR notation:    /{info['prefix']}")
    print(f"  Subnet mask:      {info['netmask']}")
    print(f"  Wildcard mask:    {info['wildcard']}   (inverse mask, used in firewall rules)")

    print("\n--- Size ---")
    print(f"  Total addresses:  {info['total_addresses']}")
    print(f"  Usable for hosts: {info['usable_hosts']}")

    print("\n--- Classification ---")
    print(f"  Class:            {info['class']}")
    print(f"  Type:             {info['classification']}")

    # Binary view: recompute from the network address itself.
    network = ipaddress.ip_network(info["input"], strict=False)
    total_bits = 32 if network.version == 4 else 128
    print("\n--- Binary view (how the computer sees it) ---")
    print(f"  Network:  {bits_of(int(network.network_address), total_bits)}")
    print(f"  Mask:     {bits_of(int(network.netmask), total_bits)}")
    print("\n  The mask's 1-bits mark the NETWORK part; 0-bits mark the HOST part.")
    print(f"{'=' * 58}\n")


def split_network(cidr_text, count):
    """Carve a network into `count` equal smaller subnets.

    Example: 192.168.1.0/24 --split 4 gives four /26 subnets of 62 hosts.
    The new prefix is old prefix + ceil(log2(count)); any leftover
    subnets beyond `count` are simply not shown.
    """
    if count < 2:
        print("ERROR: --split needs at least 2 (splitting into 1 is no split).")
        sys.exit(2)
    network = ipaddress.ip_network(cidr_text, strict=False)
    extra_bits = math.ceil(math.log2(count))
    new_prefix = network.prefixlen + extra_bits
    if new_prefix > network.max_prefixlen:
        print(f"ERROR: cannot split {cidr_text} into {count} subnets — "
              f"that would need a /{new_prefix} prefix, past the "
              f"/{network.max_prefixlen} limit.")
        sys.exit(2)
    subnets = list(network.subnets(new_prefix=new_prefix))[:count]
    print(f"\n{cidr_text} split into {count} subnets (each /{new_prefix}):\n")
    for i, sub in enumerate(subnets, 1):
        hosts = sub.num_addresses - 2 if sub.version == 4 and new_prefix <= 30 else sub.num_addresses
        print(f"  {i}. {sub}  ({hosts} usable hosts)")
    print("\nTip: each step down (/24 -> /25 -> /26) halves the subnet size.")
    return subnets


def smallest_for_hosts(cidr_text, wanted):
    """Find the smallest subnet (inside the given network) fitting N hosts.

    IPv4 reserves network + broadcast, so we need wanted + 2 addresses;
    we round up to the next power of two, then work out the prefix.
    """
    if wanted < 1:
        print("ERROR: --hosts needs at least 1.")
        sys.exit(2)
    network = ipaddress.ip_network(cidr_text, strict=False)
    if network.version == 4:
        needed = wanted + 2  # network address + broadcast address
    else:
        needed = wanted
    host_bits = math.ceil(math.log2(needed)) if needed > 1 else 0
    new_prefix = network.max_prefixlen - host_bits
    if new_prefix < network.prefixlen:
        print(f"ERROR: {wanted} hosts do not fit inside {cidr_text} "
              f"(it only holds {network.num_addresses} addresses).")
        sys.exit(2)
    capacity = 2 ** host_bits - (2 if network.version == 4 else 0)
    print(f"\nTo fit {wanted} host(s) inside {cidr_text}:")
    print(f"  Smallest subnet: /{new_prefix}  (holds {capacity} usable hosts)")
    print(f"  Example:         {network.network_address}/{new_prefix}")
    return new_prefix


def friendly_error(cidr_text, error):
    """Turn ipaddress's terse errors into plain-English hints."""
    print(f"ERROR: could not parse '{cidr_text}': {error}")
    if "/" not in cidr_text:
        print("  Hint: add CIDR notation, e.g. 192.168.1.10/24")
        print("        (the /24 says the first 24 bits are the network part).")
    elif "prefix" in str(error).lower() or "/" in str(error):
        print("  Hint: the number after / must be 0-32 for IPv4 or 0-128 for IPv6.")
    elif "octet" in str(error).lower() or "digit" in str(error).lower():
        print("  Hint: each IPv4 number must be 0-255, e.g. 192.168.1.10/24.")
    print("  Try: python3 subnet_calculator.py --demo  for worked examples.")
    sys.exit(2)


DEMO_CASES = [
    ("192.168.1.10/24", "typical home network"),
    ("10.0.5.23/16", "bigger corporate-style network"),
    ("172.16.0.1/30", "tiny 2-device link (router-to-router cable)"),
    ("2001:db8::1/64", "IPv6 example (documentation range, safe to share)"),
]


def main():
    parser = argparse.ArgumentParser(
        description="Break an IP address in CIDR notation into a full subnet breakdown.")
    parser.add_argument("cidr", nargs="?",
                        help="address in CIDR notation, e.g. 192.168.1.10/24")
    parser.add_argument("--demo", action="store_true",
                        help="run four worked examples instead of one address")
    parser.add_argument("--json", action="store_true",
                        help="print the breakdown as JSON instead of a table")
    parser.add_argument("--split", type=int, metavar="N",
                        help="carve the network into N equal smaller subnets")
    parser.add_argument("--hosts", type=int, metavar="N",
                        help="show the smallest subnet (inside this network) fitting N hosts")
    args = parser.parse_args()

    if args.demo:
        for cidr_text, note in DEMO_CASES:
            print(f"--- Example: {note} ---")
            try:
                print_breakdown(describe(cidr_text))
            except ValueError as e:
                friendly_error(cidr_text, e)
        return

    cidr_text = args.cidr
    if not cidr_text:
        cidr_text = "192.168.1.10/24"
        print(f"(No address given — using a typical home-network example: {cidr_text})")

    if "/" not in cidr_text:
        # ipaddress would silently treat a bare IP as /32; the old script
        # errored here, and a silent /32 would confuse a beginner, so
        # keep the explicit hint instead.
        friendly_error(cidr_text, "missing CIDR prefix (no '/' in the input)")

    try:
        info = describe(cidr_text)
    except ValueError as e:
        friendly_error(cidr_text, e)

    if args.split is not None:
        # --split works on the network itself; validate it first.
        try:
            split_network(cidr_text, args.split)
        except ValueError as e:
            friendly_error(cidr_text, e)
        return
    if args.hosts is not None:
        try:
            smallest_for_hosts(cidr_text, args.hosts)
        except ValueError as e:
            friendly_error(cidr_text, e)
        return

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print_breakdown(info)


if __name__ == "__main__":
    main()
