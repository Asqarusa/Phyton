#!/usr/bin/env python3
"""
Day 22 — IPv6 Address Explorer (networking, read-only, fully offline)

What this does
-------------
Hands you one IPv6 address and explains it in plain English:
the short form and the full form, which "neighborhood" it lives in
(link-local, private, global, multicast, special), and why IPv6
exists at all (IPv4 ran out of room).

Why an SOC analyst cares: logs, alerts, and firewall rules are full
of IPv6 addresses now. If you can read one at a glance — "oh, that's
just my own machine talking to itself" vs "that's routable on the
internet" — you triage faster and chase fewer ghosts.

SAFETY: this tool never touches the network. It only *reads* an
address you give it and does math on the bits. Nothing to scan,
nothing to probe.

Run it
------
    python3 ipv6_explorer.py --demo            # walk through built-in examples
    python3 ipv6_explorer.py 2001:db8::1       # explain one address
    python3 ipv6_explorer.py fe80::1 --why      # plus the "why IPv6" explainer
"""

import argparse
import ipaddress
import sys

# ---------------------------------------------------------------------------
# The "neighborhoods" of IPv6: well-known address blocks and what they mean.
# Each entry: (network, short label, plain-English explanation).
# Order matters: more specific blocks are checked first.
# ---------------------------------------------------------------------------
NEIGHBORHOODS = [
    (ipaddress.ip_network("::1/128"),
     "Loopback",
     "This is your own machine talking to itself — like thinking out loud. "
     "Same job as 127.0.0.1 in IPv4."),
    (ipaddress.ip_network("::/128"),
     "Unspecified",
     "Means 'no address yet'. Software uses it as a placeholder before it "
     "gets a real address — like writing 'TBD' on a form."),
    (ipaddress.ip_network("::ffff:0:0/96"),
     "IPv4-mapped",
     "An IPv4 address wearing an IPv6 costume, e.g. ::ffff:192.0.2.1. "
     "Lets new IPv6 software talk to old IPv4 addresses during the transition."),
    (ipaddress.ip_network("2001:db8::/32"),
     "Documentation",
     "Reserved for textbooks and examples — never real traffic. "
     "Like the 555 phone numbers in movies."),
    (ipaddress.ip_network("fe80::/10"),
     "Link-local",
     "Only works on your own wire/Wi-Fi — routers never forward it. "
     "Like shouting across the room: everyone nearby hears, nobody outside does. "
     "Every IPv6 device gets one automatically."),
    (ipaddress.ip_network("fc00::/7"),
     "Unique local (private)",
     "The IPv6 version of 192.168.x.x — private addresses for inside a "
     "company or home. Routable inside your network, never on the internet."),
    (ipaddress.ip_network("ff00::/8"),
     "Multicast",
     "One address that reaches a whole *group* at once — like a radio "
     "station: one broadcast, many listeners. Used for neighbor discovery "
     "and streaming."),
    (ipaddress.ip_network("2000::/3"),
     "Global unicast",
     "A real, routable address on the public internet — the IPv6 equivalent "
     "of a public IPv4 address. This is the 'postal address' of the internet."),
]

# A few interesting addresses for --demo mode (documentation ranges only).
DEMO_ADDRESSES = [
    "::1",
    "fe80::a299:9bff:fe18:6c5a",
    "fd00:1234:5678::9",
    "2001:db8:abcd::42",
    "ff02::1",
    "::ffff:203.0.113.7",
]

WHY_IPV6 = """
Why IPv6 exists — the 30-second version
----------------------------------------
IPv4 addresses are 32 bits long: about 4.3 billion possible addresses.
That sounded infinite in 1981. Then phones, laptops, TVs, fridges, and
doorbells all wanted one, and we ran out (the free pool emptied in 2011).

IPv6 addresses are 128 bits long: about 340 undecillion addresses —
340 followed by 36 zeros. That's roughly 4.8 x 10^28 addresses *per person*
on Earth. The phone-number analogy: IPv4 is a town that ran out of
7-digit numbers; IPv6 gave every grain of sand its own area code.

As a learner, you don't need to memorize the math. Just remember:
  * IPv4 (dotted, like 192.168.1.10)  = the old, crowded neighborhood
  * IPv6 (colons, like 2001:db8::1)    = the new, roomy neighborhood
  * Both appear in logs and alerts — being able to read both is a
    basic SOC literacy skill.
"""


def classify(addr):
    """Return (label, explanation) for the neighborhood this address is in."""
    for network, label, explanation in NEIGHBORHOODS:
        if addr in network:
            return label, explanation
    # Anything left over is some other special-purpose block; say so honestly.
    return ("Special / reserved",
            "Not one of the common neighborhoods above. It may belong to a "
            "special-purpose block (transition mechanisms, benchmarking, "
            "etc.). Worth a lookup before trusting it in an alert.")


def explain(address_text):
    """Print a plain-English breakdown of one IPv6 address."""
    try:
        # ipaddress does the hard parsing work: it accepts compressed,
        # exploded, and mixed forms and normalizes them.
        addr = ipaddress.IPv6Address(address_text)
    except ipaddress.AddressValueError:
        print(f"  '{address_text}' is not a valid IPv6 address. "
              "Example of a valid one: 2001:db8::1")
        return

    label, explanation = classify(addr)

    print(f"  You gave me : {address_text}")
    # compressed = the short everyday form (:: squashes runs of zeros)
    print(f"  Short form  : {addr.compressed}")
    # exploded = all 8 groups written out, nothing hidden
    print(f"  Full form   : {addr.exploded}")
    # The raw number behind the address — every address is just a big integer
    print(f"  As a number : {int(addr):,}")
    print(f"  Neighborhood: {label}")
    print(f"  What that means: {explanation}")

    # One-line SOC triage hint based on the neighborhood.
    if label in ("Loopback", "Link-local"):
        print("  SOC hint    : Local-only traffic — normal background noise, "
              "not internet activity.")
    elif label == "Multicast":
        print("  SOC hint    : Group traffic, usually automatic chatter "
              "(device discovery). Note it, don't panic.")
    elif label == "Global unicast":
        print("  SOC hint    : Internet-routable. If this shows up unexpectedly "
              "in a log, it's worth a closer look.")
    elif label == "IPv4-mapped":
        print("  SOC hint    : Really an IPv4 address in disguise — check the "
              "embedded IPv4 part.")


def main():
    parser = argparse.ArgumentParser(
        description="Explain IPv6 addresses in plain English (offline, read-only).")
    parser.add_argument("address", nargs="?",
                        help="an IPv6 address to explain, e.g. 2001:db8::1")
    parser.add_argument("--demo", action="store_true",
                        help="walk through built-in example addresses")
    parser.add_argument("--why", action="store_true",
                        help="also print the 'why does IPv6 exist' explainer")
    args = parser.parse_args()

    print("=" * 64)
    print("IPv6 ADDRESS EXPLORER")
    print("=" * 64)

    if args.demo:
        # No arguments needed: just learn from the built-in examples.
        for demo in DEMO_ADDRESSES:
            print()
            explain(demo)
    elif args.address:
        print()
        explain(args.address)
    else:
        parser.print_help()
        print("\nTip: start with  python3 ipv6_explorer.py --demo")
        sys.exit(1)

    if args.why or args.demo:
        print(WHY_IPV6)


if __name__ == "__main__":
    main()
