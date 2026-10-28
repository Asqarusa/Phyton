# Subnet Calculator — the plain-English guide

**Project:** subnet_calculator.py (Day 07 of the build-in-public series — networking theme)
**Run it:** `python3 subnet_calculator.py 192.168.1.10/24`

---

## What's new in this version (improved 2026-10-27)

I went back to this project and gave it four upgrades, all in the same single file:

1. **It now speaks IPv6 too.** The original only handled IPv4. Give it `2001:db8::1/64` and you get the same breakdown — with the honest note that IPv6 has no broadcast address (it uses multicast instead) and that old A/B/C classes don't apply.
2. **Two sizing helpers engineers actually use.** `--split 4` carves a network into 4 equal smaller subnets (that's VLSM in one step: a /24 becomes four /26s of 62 hosts each). `--hosts 50` answers the reverse question: "what's the smallest subnet that fits 50 devices?" (a /26, in that case).
3. **Proper command-line flags.** `--demo` runs four worked examples (home, corporate, tiny link, IPv6) without typing anything, and `--json` prints the same breakdown as JSON so another tool can read it.
4. **Friendlier mistakes.** Forgetting the `/24` used to be a confusing edge case; now you get a plain hint ("add CIDR notation, e.g. 192.168.1.10/24") and a pointer to `--demo`, and bad prefixes or out-of-range numbers get the same treatment instead of a traceback.

Think of it like this: the original calculator was a ruler. The improved one is a ruler plus a "cut this board into 4 equal pieces" guide and a "what size board do I need for 50 shelves?" answer — same tool, now useful for planning, not just measuring.

---

## The big idea (non-tech analogy first)

Imagine an apartment building. The **building address** (123 Main St) tells the
post office which building to go to — that's the **network address**. The
**apartment numbers** (Apt 1 through Apt 254) tell the mail carrier which door
inside the building — those are the **host addresses**. The **broadcast
address** is like shouting in the hallway: everyone hears it at once.

But here's the catch: from the address "123 Main St, Apt 42" alone, you can't
tell where the building part ends and the apartment part begins. Is "Main St"
the building and "123" the apartment? You need a **subnet mask** — a rule that
says "everything before this line is the building, everything after is the
apartment." That's exactly what a subnet mask does for IP addresses.

Network engineers do this math constantly: sizing networks, planning how many
devices fit, writing firewall rules. My script does the whole calculation from
a single input like `192.168.1.10/24`.

---

## What the script does

Give it any IPv4 address in CIDR notation (the `/24` at the end is the key
part), and it prints a full breakdown:

- **Network address** — the ID of the subnet itself (not assigned to any device)
- **Broadcast address** — the address that reaches every device on the subnet
- **First / last usable** — the actual range you can hand out to devices
- **Subnet mask & wildcard mask** — the "dividing line" and its inverse
- **Total vs. usable addresses** — why a /24 gives 254 devices, not 256
- **Class (A/B/C) and private vs. public** — the quick shorthand engineers use
- **Binary view** — the raw 1s and 0s, so you can see the mask "cutting" the address

It also handles mistakes gracefully: a bad address like `999.1.1.1/24` gets a
clear error message instead of a crash.

---

## How the code works, line by line (simple terms)

**1. Imports — borrowing tools instead of building them**
`ipaddress` is Python's built-in library that already knows all the subnet math.
Using it is like using a calculator for arithmetic: you still need to know what
question to ask, but you don't redo the math by hand. `sys` just lets the
script read what you typed on the command line.

**2. `bits_of()` — making binary readable**
Computers see IPs as 32 ones and zeros. This helper formats them into the
familiar four groups of 8 bits (like `11000000.10101000.00000001.00000001`) so a
human can actually read them.

**3. `ip_class()` — the old A/B/C shorthand**
The first number of an IP hints at its traditional "class": Class A networks
are enormous (millions of addresses), Class C are small office/home sized.
It's legacy, but engineers still say it out loud, so the script reports it.

**4. `describe()` — the actual math**
This is the heart of the script:
- `ip_network("192.168.1.10/24", strict=False)` figures out which network that
  host address belongs to (`strict=False` means you can hand it a device's
  address, not just the network address — friendlier).
- From that one object, Python hands us the network address, broadcast
  address, mask, and wildcard for free.
- The usable-host math: the first address (network ID) and last address
  (broadcast) are reserved, so usable = total − 2. Tiny `/31` and `/32`
  subnets are special cases with their own rules, handled separately.
- `is_private` checks whether the address falls in the private ranges
  (10.x.x.x, 172.16.x.x–172.31.x.x, 192.168.x.x) — the addresses that only
  exist inside offices and homes.

**5. `main()` — the front door**
Reads your input (or uses a home-network example if you gave none), checks the
`/24`-style suffix is present, and calls `describe()`. Any bad input is caught
and explained in plain language.

---

## Key terms, translated

| Term | Plain English |
|---|---|
| CIDR (`/24`) | "The first 24 bits identify the network." Bigger number = smaller network. |
| Subnet mask (`255.255.255.0`) | The dividing line between network part and device part, written as an address. |
| Wildcard mask (`0.0.0.255`) | The mask flipped — used in firewall/router rules to say "I don't care about these bits." |
| Network address | The subnet's ID badge. Never given to a device. |
| Broadcast address | The subnet's megaphone. One packet, everyone hears it. |
| Private IP (RFC 1918) | An address that only works inside private networks — your home router hands these out. |
| Class A/B/C | Old-school size categories: huge / medium / small. Still useful shorthand. |

---

## How to run it

```bash
python3 subnet_calculator.py 192.168.1.10/24   # typical home network
python3 subnet_calculator.py 10.0.5.23/16      # bigger corporate-style network
python3 subnet_calculator.py 172.16.0.1/30     # tiny 2-device link (like a router-to-router cable)
python3 subnet_calculator.py 2001:db8::1/64    # IPv6 example (new)
python3 subnet_calculator.py --demo             # four worked examples, no typing
python3 subnet_calculator.py 192.168.1.0/24 --split 4   # carve into four /26 subnets (new)
python3 subnet_calculator.py 10.0.0.0/24 --hosts 50     # smallest subnet fitting 50 hosts: /26 (new)
python3 subnet_calculator.py 192.168.1.10/24 --json    # same breakdown as JSON (new)
python3 subnet_calculator.py                   # no argument? runs the home example
```

Requirements: Python 3 only, no extra packages. Works on any laptop — it does
pure math on an address you type in; it sends zero network traffic.

---

## What to learn next

1. **Do it by hand once.** Take `192.168.1.10/24`, write the binary, and find
   the network address yourself. The script's binary view is your answer key.
2. **VLSM (variable-length subnetting).** Real networks are carved into
   different-sized subnets (/25, /26, /27…). Try a few in the script and watch
   the usable counts halve each time — that pattern is the whole trick.
3. **Why it matters for security.** Firewalls, ACLs, and VPN configs are all
   written in CIDR. Misreading one mask bit can expose a whole subnet — or
   block a whole office.
