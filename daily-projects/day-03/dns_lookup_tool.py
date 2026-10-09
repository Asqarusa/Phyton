#!/usr/bin/env python3
"""
dns_lookup_tool.py — A beginner-friendly DNS lookup tool.

The big idea: DNS (the Domain Name System) is the internet's phone book.
You type "google.com" and DNS answers with the phone number (the IP address)
your computer actually dials. This script asks those questions and shows
the answers, like flipping through a phone book for a website.

What this script does:
  1. Takes one or more domain names (like "example.com").
  2. Looks up their IP addresses (the "phone numbers").
  3. Shows which kind of record it found (A = IPv4, AAAA = IPv6).
  4. Does a reverse lookup: given an IP, asks "what name is registered here?"
  5. Times each lookup, so you can feel how fast (or slow) DNS is.

Run it like this:
    python3 dns_lookup_tool.py example.com google.com
or with the built-in examples:
    python3 dns_lookup_tool.py --examples
"""

import socket
import sys
import time


def lookup_ipv4(domain):
    """Ask DNS for this domain's IPv4 addresses (A records).

    socket.gethostbyname_ex is the standard library's way of saying
    "hey DNS, what IPv4 addresses do you have for this name?"
    It returns (official_name, [aliases], [ip_addresses]).
    """
    try:
        hostname, aliases, ip_addresses = socket.gethostbyname_ex(domain)
        return {
            "record_type": "A (IPv4)",
            "official_name": hostname,
            "aliases": aliases,
            "addresses": ip_addresses,
            "error": None,
        }
    except socket.gaierror:
        # gaierror = "get address info error": DNS said "never heard of it."
        return {"record_type": "A (IPv4)", "addresses": [], "error": f"Could not resolve '{domain}' (no such name?)"}


def lookup_ipv6(domain):
    """Ask DNS for this domain's IPv6 addresses (AAAA records).

    socket.getaddrinfo returns full address details; we filter for the
    IPv6 family (AF_INET6) and pull out the raw address strings.
    """
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        # Each result is a 5-tuple; the address lives at index 4, position 0.
        ipv6_addresses = sorted({result[4][0] for result in results})
        return {
            "record_type": "AAAA (IPv6)",
            "addresses": ipv6_addresses,
            "error": None,
        }
    except socket.gaierror:
        return {"record_type": "AAAA (IPv6)", "addresses": [], "error": f"No IPv6 addresses found for '{domain}'"}


def reverse_lookup(ip_address):
    """Reverse lookup: given an IP, ask "what hostname is registered here?"

    This uses PTR records — the reverse pages of the phone book.
    Not every IP has one, and that's normal (many servers share IPs
    or simply don't register a reverse name).
    """
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return None  # No reverse name registered — common and fine.


def analyze_domain(domain):
    """Run every lookup for one domain and bundle the results."""
    print(f"\n{'=' * 60}")
    print(f"  {domain}")
    print(f"{'=' * 60}")

    start = time.perf_counter()

    # Step 1: IPv4 lookup.
    v4 = lookup_ipv4(domain)
    if v4["error"]:
        print(f"\n  [A / IPv4]     {v4['error']}")
    else:
        print(f"\n  [A / IPv4]     {v4['official_name']}")
        for ip in v4["addresses"]:
            print(f"    -> {ip}")

    # Step 2: IPv6 lookup (may legitimately find nothing).
    v6 = lookup_ipv6(domain)
    if v6["error"]:
        print(f"\n  [AAAA / IPv6]  {v6['error']}")
    else:
        print(f"\n  [AAAA / IPv6]")
        for ip in v6["addresses"]:
            print(f"    -> {ip}")

    # Step 3: reverse lookups for the IPv4 addresses we found.
    if not v4["error"] and v4["addresses"]:
        print(f"\n  [Reverse / PTR]")
        for ip in v4["addresses"]:
            name = reverse_lookup(ip)
            if name:
                print(f"    -> {ip} resolves back to: {name}")
            else:
                print(f"    -> {ip} has no reverse (PTR) record")

    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"\n  Lookups finished in {elapsed_ms:.1f} ms")


def main():
    args = sys.argv[1:]

    if not args or "--help" in args:
        print(__doc__)
        print("Example: python3 dns_lookup_tool.py example.com github.com")
        return

    if "--examples" in args:
        domains = ["example.com", "python.org", "github.com"]
        print("Running with built-in example domains:", ", ".join(domains))
    else:
        domains = args

    print("DNS Lookup Tool — asking the internet's phone book for answers...")

    for domain in domains:
        # A tiny sanity check: strip accidental http:// or trailing slashes.
        cleaned = domain.replace("http://", "").replace("https://", "").rstrip("/").split("/")[0]
        analyze_domain(cleaned)

    print(f"\n{'=' * 60}")
    print("  Done! Every answer above came from your configured DNS server,")
    print("  usually your router or ISP. No accounts, no API keys needed.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
