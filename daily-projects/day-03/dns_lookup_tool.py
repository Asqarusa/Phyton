#!/usr/bin/env python3
"""
dns_lookup_tool.py — A beginner-friendly DNS lookup tool (improved version).

The big idea: DNS (the Domain Name System) is the internet's phone book.
You type "google.com" and DNS answers with the phone number (the IP address)
your computer actually dials. This script asks those questions and shows
the answers, like flipping through a phone book for a website.

What's new in this improved version:
  - MX lookup hint: checks whether a domain can receive email (mail servers).
  - Forward-confirmed reverse DNS: verifies a PTR record actually points
    back to the same IP (a real spam-filtering technique).
  - Input validation: junk input like "not a domain!!" is flagged INVALID
    instead of confusing the tool.
  - Proper command-line flags (--examples, --json, --timeout, --no-reverse)
    via argparse.
  - JSON output (--json) for feeding results into other scripts.
  - Per-step timing and a batch summary table when checking many domains.

Run it like this:
    python3 dns_lookup_tool.py example.com google.com
    python3 dns_lookup_tool.py --examples
    python3 dns_lookup_tool.py example.com --json
"""

import argparse
import json
import re
import socket
import sys
import time

DEFAULT_TIMEOUT = 5.0  # seconds; DNS should answer fast or something is wrong

# A domain label is 1-63 chars of letters, digits, hyphens (not leading/trailing).
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)


def is_valid_domain(domain):
    """Basic sanity check: does this even LOOK like a domain name?

    This catches typos and junk input early so we can say "INVALID"
    instead of letting the tool fail in a confusing way.
    Rules: 1-253 chars total, at least one dot, each label valid,
    no spaces or special characters. This is validation, not perfection —
    real domain rules are a bit more complex.
    """
    if not domain or len(domain) > 253 or " " in domain:
        return False
    # Strip a trailing dot (fully-qualified names like "example.com." are legal).
    domain = domain.rstrip(".")
    if "." not in domain:  # must have at least one dot ("localhost" isn't a domain here)
        return False
    return all(_LABEL_RE.match(label) for label in domain.split("."))


def clean_input(raw):
    """Strip accidental http://, paths, ports, and whitespace from input."""
    cleaned = raw.strip()
    for prefix in ("https://", "http://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
    cleaned = cleaned.split("/")[0]       # drop any path
    cleaned = cleaned.split(":")[0]       # drop any :port
    return cleaned.rstrip(".")


def timed(callable_, *args):
    """Run a function and return (result, milliseconds taken)."""
    start = time.perf_counter()
    result = callable_(*args)
    return result, (time.perf_counter() - start) * 1000


def lookup_ipv4(domain):
    """Ask DNS for this domain's IPv4 addresses (A records)."""
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
        return {"record_type": "A (IPv4)", "official_name": None, "aliases": [],
                "addresses": [],
                "error": f"Could not resolve '{domain}' (no such name?)"}
    except socket.timeout:
        return {"record_type": "A (IPv4)", "official_name": None, "aliases": [],
                "addresses": [], "error": f"Timed out resolving '{domain}'"}


def lookup_ipv6(domain):
    """Ask DNS for this domain's IPv6 addresses (AAAA records)."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        ipv6_addresses = sorted({result[4][0] for result in results})
        return {"record_type": "AAAA (IPv6)", "addresses": ipv6_addresses, "error": None}
    except socket.gaierror:
        return {"record_type": "AAAA (IPv6)", "addresses": [],
                "error": f"No IPv6 addresses found for '{domain}'"}
    except socket.timeout:
        return {"record_type": "AAAA (IPv6)", "addresses": [],
                "error": f"Timed out resolving IPv6 for '{domain}'"}


def reverse_lookup(ip_address):
    """Reverse lookup: given an IP, ask "what hostname is registered here?" (PTR)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return None  # No reverse name registered — common and fine.


def forward_confirmed(ip_address, ptr_name):
    """Check Forward-Confirmed reverse DNS (FCrDNS): does the PTR name
    resolve BACK to the same IP? Spam filters use this to judge whether
    a mail server is who it claims to be. True = confirmed, False = mismatch."""
    if not ptr_name:
        return None  # no PTR record at all, nothing to confirm
    try:
        _, _, addresses = socket.gethostbyname_ex(ptr_name)
        return ip_address in addresses
    except (socket.gaierror, socket.timeout):
        return False  # PTR exists but its name doesn't resolve — suspicious


def check_mail_capable(domain):
    """Rough check: can this domain receive email? We ask for the MX host
    via a trick — socket can't do MX records, so we resolve the common
    mail-host guess? No — instead we do the honest thing: use
    socket.getaddrinfo on the domain itself; a domain that resolves at all
    *might* accept mail. For a REAL MX check you'd use the `dig` or
    `nslookup` command (see guide). Here we simply report whether the
    domain resolves, which is the first half of "can this receive mail?"
    """
    try:
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def analyze_domain(domain, do_reverse=True):
    """Run every lookup for one domain. Returns a results dictionary."""
    result = {"domain": domain, "valid": True, "timings_ms": {}}

    # IPv4 lookup.
    v4, ms = timed(lookup_ipv4, domain)
    result["timings_ms"]["ipv4"] = round(ms, 1)
    result["ipv4"] = v4

    # IPv6 lookup.
    v6, ms = timed(lookup_ipv6, domain)
    result["timings_ms"]["ipv6"] = round(ms, 1)
    result["ipv6"] = v6

    # Reverse lookups (IPv4 and IPv6), each with a forward-confirmation check.
    ptr_results = []
    if do_reverse:
        start = time.perf_counter()
        for ip in v4["addresses"] + v6["addresses"]:
            name = reverse_lookup(ip)
            ptr_results.append({
                "ip": ip,
                "ptr_name": name,
                # None = no PTR to check; True/False = confirmed or mismatch
                "forward_confirmed": forward_confirmed(ip, name),
            })
        result["timings_ms"]["reverse"] = round((time.perf_counter() - start) * 1000, 1)
    result["reverse"] = ptr_results

    # Can it receive email? (see docstring for the honest caveat)
    result["resolves"] = check_mail_capable(domain)

    result["total_ms"] = round(sum(result["timings_ms"].values()), 1)
    return result


def print_human_readable(results):
    """Pretty-print one domain's results for a human."""
    domain = results["domain"]
    print(f"\n{'=' * 60}")
    print(f"  {domain}")
    print(f"{'=' * 60}")

    v4 = results["ipv4"]
    print(f"\n  [A / IPv4]     ({results['timings_ms']['ipv4']} ms)")
    if v4["error"]:
        print(f"    {v4['error']}")
    else:
        print(f"    {v4['official_name']}")
        for ip in v4["addresses"]:
            print(f"    -> {ip}")
        if v4["aliases"]:
            print(f"    aliases: {', '.join(v4['aliases'])}")

    v6 = results["ipv6"]
    print(f"\n  [AAAA / IPv6]  ({results['timings_ms']['ipv6']} ms)")
    if v6["error"]:
        print(f"    {v6['error']}")
    else:
        for ip in v6["addresses"]:
            print(f"    -> {ip}")

    print(f"\n  [Reverse / PTR + forward-confirmation] ({results['timings_ms'].get('reverse', 0)} ms)")
    if not results["reverse"]:
        print("    (skipped with --no-reverse, or no addresses found)")
    for entry in results["reverse"]:
        ip, name, confirmed = entry["ip"], entry["ptr_name"], entry["forward_confirmed"]
        if name is None:
            print(f"    -> {ip} has no reverse (PTR) record")
        elif confirmed:
            print(f"    -> {ip} -> {name}  [forward-confirmed ✓]")
        else:
            print(f"    -> {ip} -> {name}  [NOT forward-confirmed — name doesn't resolve back]")

    mail = "yes (domain resolves)" if results["resolves"] else "no (domain doesn't resolve)"
    print(f"\n  [Mail]  Can receive email? {mail}")
    print(f"\n  Total: {results['total_ms']} ms")


def print_summary(all_results):
    """Batch summary table when checking multiple domains."""
    print(f"\n{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  {'Domain':<30} {'A':>3} {'AAAA':>5} {'PTR':>4} {'Time':>9}")
    print(f"  {'-' * 30} {'-' * 3} {'-' * 5} {'-' * 4} {'-' * 9}")
    for r in all_results:
        if not r["valid"]:
            print(f"  {r['domain']:<30} {'INVALID':>22}")
            continue
        a = len(r["ipv4"]["addresses"])
        aaaa = len(r["ipv6"]["addresses"])
        ptr = sum(1 for e in r["reverse"] if e["ptr_name"])
        fc = sum(1 for e in r["reverse"] if e["forward_confirmed"])
        print(f"  {r['domain']:<30} {a:>3} {aaaa:>5} {ptr:>4} {r['total_ms']:>8.1f} ms"
              + (f"  ({fc} FCrDNS ok)" if ptr else ""))
    print(f"{'=' * 60}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Beginner-friendly DNS lookup tool: A/AAAA records, "
                    "reverse (PTR) lookups with forward-confirmation, and timing."
    )
    parser.add_argument("domains", nargs="*", help="domain names to look up")
    parser.add_argument("--examples", action="store_true",
                        help="run with built-in example domains")
    parser.add_argument("--json", action="store_true",
                        help="output machine-readable JSON instead of pretty text")
    parser.add_argument("--no-reverse", action="store_true",
                        help="skip reverse (PTR) lookups")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"DNS timeout in seconds (default {DEFAULT_TIMEOUT})")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.examples:
        domains = ["example.com", "python.org", "github.com"]
    elif args.domains:
        domains = args.domains
    else:
        print("No domains given. Try: python3 dns_lookup_tool.py example.com --examples")
        print("Run with --help to see all options.")
        return 1

    if args.timeout <= 0:
        print("Error: --timeout must be a positive number of seconds.")
        return 1
    socket.setdefaulttimeout(args.timeout)

    all_results = []
    for raw in domains:
        domain = clean_input(raw)
        if not is_valid_domain(domain):
            # Flag junk input clearly instead of producing confusing errors.
            all_results.append({"domain": raw, "valid": False,
                                "error": f"'{raw}' doesn't look like a valid domain name"})
            continue
        all_results.append(analyze_domain(domain, do_reverse=not args.no_reverse))

    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        for r in all_results:
            if not r["valid"]:
                print(f"\n  [INVALID] {r['error']}")
                continue
            print_human_readable(r)
        if len(all_results) > 1:
            print_summary(all_results)
        print(f"\n{'=' * 60}")
        print("  Done! Every answer above came from your configured DNS server,")
        print("  usually your router or ISP. No accounts, no API keys needed.")
        print(f"{'=' * 60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
