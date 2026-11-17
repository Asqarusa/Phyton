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

What's new in this version
--------------------------
  * More neighborhoods: Teredo, 6to4, benchmarking, discard-only and
    ORCHIDv2 blocks are now recognized instead of "special / reserved".
  * Hidden IPv4 addresses are pulled out and shown: IPv4-mapped
    (::ffff:192.0.2.1) and 6to4 (2002:xxxx::) both carry a real IPv4
    address inside them — the tool prints it.
  * --file mode: explain a whole list of addresses from a text file
    (one per line, # comments and blank lines skipped) with a summary
    table at the end. Exit code 1 if any global-unicast address was
    found, so you can use it in a script.
  * --network mode: explain a prefix like 2001:db8::/32 — first and
    last address, how many addresses it holds, and how many /64
    subnets fit inside it.
  * --json mode: machine-readable output for one address, a file, a
    network, or the demo set.
  * Friendlier errors with exit code 2: bad address, bad prefix,
    missing file, or an empty file all say what went wrong and how
    to fix it instead of crashing.

SAFETY: this tool never touches the network. It only *reads* an
address you give it and does math on the bits. Nothing to scan,
nothing to probe.

Run it
------
    python3 ipv6_explorer.py --demo            # walk through built-in examples
    python3 ipv6_explorer.py 2001:db8::1       # explain one address
    python3 ipv6_explorer.py fe80::1 --why     # plus the "why IPv6" explainer
    python3 ipv6_explorer.py --file sample_addresses.txt
    python3 ipv6_explorer.py --network 2001:db8::/32
    python3 ipv6_explorer.py 2001:db8::1 --json

Exit codes: 0 = OK (or no global-unicast address in --file mode),
1 = --file mode found at least one global-unicast address,
2 = usage/input error (bad address, bad prefix, missing file).
"""

import argparse
import ipaddress
import json
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
    (ipaddress.ip_network("2001:2::/48"),
     "Benchmarking",
     "Reserved for measuring network performance (like a test track). "
     "You should never see it in real user traffic."),
    (ipaddress.ip_network("2001:20::/28"),
     "ORCHIDv2",
     "Experimental addresses for research crypto identifiers — not "
     "routable on the internet. If it shows up in a log, it is a lab "
     "experiment, not a real host."),
    (ipaddress.ip_network("2001::/32"),
     "Teredo",
     "An old IPv4-to-IPv6 tunnel: the real IPv4 address is hidden inside, "
     "scrambled (XORed). Teredo traffic in a modern log is unusual and "
     "worth a second look — tunnels can hide where traffic really came from."),
    (ipaddress.ip_network("2002::/16"),
     "6to4",
     "Another IPv4-to-IPv6 tunnel: the IPv4 address is baked right into "
     "the address (the 2nd and 3rd groups spell it out in hex). Mostly "
     "legacy now — modern networks rarely use it."),
    (ipaddress.ip_network("100::/64"),
     "Discard-only",
     "A block reserved for packets that should be thrown away — like a "
     "mail slot marked 'do not deliver'. Real traffic should never use it."),
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
    "2002:c000:0201::1",   # 6to4: hides IPv4 192.0.2.1
    "2001:0000:4136:e378:8000:63bf:3fff:fdd2",  # Teredo example
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

# One-line SOC triage hints, keyed by neighborhood label.
SOC_HINTS = {
    "Loopback": "Local-only traffic — normal background noise, not internet activity.",
    "Link-local": "Local-only traffic — normal background noise, not internet activity.",
    "Unspecified": "A placeholder address, not real traffic — usually a program that has not started yet.",
    "Documentation": "Example-only address — safe to ignore in real logs; it is never real traffic.",
    "Benchmarking": "Test traffic only — if it appears in a real alert, something is misconfigured.",
    "ORCHIDv2": "Research traffic only — not a real host on the internet.",
    "Discard-only": "Should never appear in real traffic — treat it as a misconfiguration or a spoof attempt.",
    "Multicast": "Group traffic, usually automatic chatter (device discovery). Note it, don't panic.",
    "Global unicast": "Internet-routable. If this shows up unexpectedly in a log, it's worth a closer look.",
    "IPv4-mapped": "Really an IPv4 address in disguise — check the embedded IPv4 part.",
    "6to4": "A tunnel address — check the embedded IPv4 address; legacy tunnels are rare in modern logs.",
    "Teredo": "A tunnel address — the real IPv4 source is scrambled inside; tunnels deserve a second look.",
    "Unique local (private)": "Private, inside-network only — normal if it is your own network, odd if it is not.",
    "Special / reserved": "Not a common neighborhood — look it up before trusting it in an alert.",
}


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


def embedded_ipv4(addr):
    """Return the IPv4 address hidden inside this IPv6 address, or None.

    IPv4-mapped addresses carry it in the last 32 bits (::ffff:192.0.2.1).
    6to4 addresses carry it in bits 16-47 (2002:<hex-of-IPv4>::).
    Teredo scrambles it (XOR with all-ones), so we report that honestly
    instead of guessing.
    """
    if addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    if addr in ipaddress.ip_network("2002::/16"):
        # Groups 2 and 3 of the address are the IPv4 address in hex.
        raw = (int(addr) >> 80) & 0xFFFFFFFF
        return str(ipaddress.IPv4Address(raw))
    return None


def describe(address_text):
    """Parse one address and return a dict of facts, or an error dict.

    Returns a dict with keys: input, valid, and (when valid) compressed,
    exploded, number, neighborhood, explanation, soc_hint, embedded_ipv4.
    """
    try:
        addr = ipaddress.IPv6Address(address_text)
    except ipaddress.AddressValueError:
        return {"input": address_text, "valid": False,
                "error": "not a valid IPv6 address (example of a valid one: 2001:db8::1)"}
    label, explanation = classify(addr)
    hidden = embedded_ipv4(addr)
    result = {
        "input": address_text,
        "valid": True,
        "compressed": addr.compressed,
        "exploded": addr.exploded,
        "number": int(addr),
        "neighborhood": label,
        "explanation": explanation,
        "soc_hint": SOC_HINTS.get(label, ""),
    }
    if hidden is not None:
        result["embedded_ipv4"] = hidden
    if label == "Teredo":
        result["note"] = ("Teredo hides its IPv4 address scrambled (XORed) — "
                          "the tool does not unscramble it here.")
    return result


def print_explanation(info):
    """Print a plain-English breakdown of one address from describe()."""
    if not info["valid"]:
        print(f"  '{info['input']}' is not a valid IPv6 address. "
              "Example of a valid one: 2001:db8::1")
        return
    print(f"  You gave me : {info['input']}")
    # compressed = the short everyday form (:: squashes runs of zeros)
    print(f"  Short form  : {info['compressed']}")
    # exploded = all 8 groups written out, nothing hidden
    print(f"  Full form   : {info['exploded']}")
    # The raw number behind the address — every address is just a big integer
    print(f"  As a number : {info['number']:,}")
    if "embedded_ipv4" in info:
        print(f"  Hidden IPv4 : {info['embedded_ipv4']} (inside this IPv6 address)")
    if "note" in info:
        print(f"  Note        : {info['note']}")
    print(f"  Neighborhood: {info['neighborhood']}")
    print(f"  What that means: {info['explanation']}")
    print(f"  SOC hint    : {info['soc_hint']}")


def explain(address_text):
    """Print a plain-English breakdown of one IPv6 address. Returns its info dict."""
    info = describe(address_text)
    print_explanation(info)
    return info


def explain_network(prefix_text):
    """Print a plain-English breakdown of an IPv6 prefix. Returns an info dict."""
    try:
        network = ipaddress.IPv6Network(prefix_text, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return {"input": prefix_text, "valid": False,
                "error": "not a valid IPv6 prefix (example: 2001:db8::/32)"}
    size = network.num_addresses
    # How many /64 subnets fit inside this prefix (a /64 is the usual
    # smallest subnet handed to one network segment).
    subnets_64 = size // (2 ** 64) if network.prefixlen <= 64 else 0
    return {
        "input": prefix_text,
        "valid": True,
        "network": network.compressed,
        "prefix_length": network.prefixlen,
        "first_address": network.network_address.compressed,
        "last_address": network.broadcast_address.compressed,
        "total_addresses": size,
        "subnets_64": subnets_64,
    }


def print_network(info):
    """Print a plain-English breakdown of a prefix from explain_network()."""
    if not info["valid"]:
        print(f"  '{info['input']}' is not a valid IPv6 prefix. "
              "Example of a valid one: 2001:db8::/32")
        return
    print(f"  Prefix      : {info['network']} (/{info['prefix_length']})")
    print(f"  First address: {info['first_address']}")
    print(f"  Last address : {info['last_address']}")
    print(f"  Total addresses: {info['total_addresses']:,}")
    if info["subnets_64"]:
        print(f"  Fits {info['subnets_64']:,} subnets of /64 "
              "(the usual size for one network segment)")
    else:
        print("  This prefix is smaller than a /64 — it is a slice of one subnet, "
              "not a whole network.")


def read_address_file(path):
    """Read addresses from a text file: one per line, # comments and blanks skipped.

    Returns (addresses, error_message). error_message is None on success.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return [], f"file not found: {path} — check the path and try again"
    except OSError as exc:
        return [], f"could not read {path}: {exc}"
    addresses = []
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        addresses.append(text)
    if not addresses:
        return [], (f"{path} has no addresses in it — add one address per line, "
                    "or use --demo to see examples")
    return addresses, None


def summarize(results):
    """Print a summary table for --file results. Returns True if any global unicast found."""
    counts = {}
    invalid = []
    for info in results:
        if not info["valid"]:
            invalid.append(info["input"])
            continue
        counts[info["neighborhood"]] = counts.get(info["neighborhood"], 0) + 1
    print()
    print("Summary")
    print("-" * 64)
    for label in sorted(counts):
        print(f"  {label:<24} {counts[label]}")
    print(f"  {'Total valid':<24} {sum(counts.values())}")
    if invalid:
        print(f"  {'Invalid lines':<24} {len(invalid)}: {', '.join(invalid)}")
    found_global = counts.get("Global unicast", 0) > 0
    if found_global:
        print("  -> At least one internet-routable (global unicast) address "
              "was found — worth a closer look.")
    return found_global


def main():
    parser = argparse.ArgumentParser(
        description="Explain IPv6 addresses in plain English (offline, read-only).")
    parser.add_argument("address", nargs="?",
                        help="an IPv6 address to explain, e.g. 2001:db8::1")
    parser.add_argument("--demo", action="store_true",
                        help="walk through built-in example addresses")
    parser.add_argument("--why", action="store_true",
                        help="also print the 'why does IPv6 exist' explainer")
    parser.add_argument("--file", metavar="PATH",
                        help="explain every address in a text file (one per line)")
    parser.add_argument("--network", metavar="PREFIX",
                        help="explain a prefix, e.g. 2001:db8::/32")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON instead of plain English")
    args = parser.parse_args()

    # One input at a time — mixing them would be ambiguous.
    modes = sum(bool(x) for x in (args.address, args.demo, args.file, args.network))
    if modes > 1:
        print("Please pick just one: an address, --demo, --file, or --network.")
        sys.exit(2)

    exit_code = 0
    json_out = None

    if not args.json:
        print("=" * 64)
        print("IPv6 ADDRESS EXPLORER")
        print("=" * 64)

    if args.demo:
        results = []
        for demo in DEMO_ADDRESSES:
            info = describe(demo)
            results.append(info)
            if not args.json:
                print()
                print_explanation(info)
        if args.json:
            json_out = {"mode": "demo", "results": results}
    elif args.address:
        info = describe(args.address)
        if args.json:
            json_out = info
        else:
            print()
            print_explanation(info)
        if not info["valid"]:
            sys.exit(2)
    elif args.file:
        addresses, error = read_address_file(args.file)
        if error:
            print(f"Error: {error}")
            sys.exit(2)
        results = [describe(text) for text in addresses]
        found_global = any(
            r["valid"] and r["neighborhood"] == "Global unicast"
            for r in results)
        if found_global:
            exit_code = 1
        if args.json:
            json_out = {"mode": "file", "file": args.file, "results": results,
                        "global_unicast_found": found_global}
        else:
            for info in results:
                print()
                print_explanation(info)
            summarize(results)
    elif args.network:
        info = explain_network(args.network)
        if args.json:
            json_out = info
        else:
            print()
            print_network(info)
        if not info["valid"]:
            sys.exit(2)
    else:
        parser.print_help()
        print("\nTip: start with  python3 ipv6_explorer.py --demo")
        sys.exit(2)

    if json_out is not None:
        print(json.dumps(json_out, indent=2, default=str))
    elif args.why or args.demo:
        print(WHY_IPV6)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
