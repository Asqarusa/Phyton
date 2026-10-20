# Day 22 — IPv6 Address Explorer: a plain-English guide

## The big idea (start here)

Think of IP addresses like **phone numbers for computers**. IPv4 — the old system, the dotted ones like `192.168.1.10` — only had about 4.3 billion numbers. In 1981 that felt infinite. Then every phone, laptop, TV, and smart doorbell wanted one, and we **ran out** (the free pool was empty by 2011).

IPv6 is the new phone book: 128-bit addresses, about 340 *undecillion* of them. That's 340 followed by 36 zeros — roughly 48 octillion addresses **per person on Earth**. It's like a town that ran out of 7-digit numbers and gave every grain of sand its own area code.

Here's the thing that matters for a learner: **both systems are in your logs right now.** Firewalls, alerts, and server logs are full of colon-style addresses like `2001:db8::1` and `fe80::a299:9bff:fe18:6c5a`. If those look like alphabet soup, you read alerts slower and chase more ghosts. This tool teaches you to read one at a glance: is it just my own machine? My own Wi-Fi? Or a real internet address that deserves a closer look?

## What the script does

You hand it one IPv6 address (or run `--demo` to walk through built-in examples), and it prints:

1. **Short form and full form** — the everyday shorthand (`2001:db8::1`) and the fully written-out version (`2001:0db8:0000:0000:0000:0000:0000:0001`). Same address, like "NYC" vs "New York City".
2. **The raw number** — every address is just one giant integer; seeing it demystifies the hex.
3. **Its "neighborhood"** — loopback, link-local, private, multicast, global, and the special ones — with a plain-English explanation of each.
4. **A SOC hint** — a one-line triage nudge: "local-only, normal noise" vs "internet-routable, worth a look."

With `--why` it also prints the 30-second "why IPv6 exists" explainer. It's 100% offline, read-only, and standard-library-only — it does math on the bits you give it and touches nothing else.

## How the code works (line by line, in simple terms)

- **The docstring at the top** — the built-in manual. `python3 ipv6_explorer.py --help` shows the short version; the docstring explains what, why, and how to run it.
- **`import ipaddress`** — Python's standard library for working with IP addresses. It knows how to parse, compress, expand, and compare addresses, so we don't hand-roll any of that.
- **The `NEIGHBORHOODS` list** — the heart of the tool. Each entry is a known IPv6 block (`::1/128` for loopback, `fe80::/10` for link-local, `ff00::/8` for multicast, and so on) paired with a short label and a plain-English explanation. Checking "which neighborhood is this address in" is just asking: which of these blocks contains it? Order matters — specific blocks come before the big general ones, like checking "is it my street?" before "is it my country?"
- **`classify(addr)`** — loops through the neighborhoods and returns the first match's label and explanation. If nothing matches, it says so honestly ("special/reserved — look it up") instead of guessing.
- **`explain(address_text)`** — the main worker:
  - `ipaddress.IPv6Address(...)` parses whatever you typed (compressed, full, or mixed) into one normalized object. Bad input gets a friendly error, not a crash.
  - `.compressed` / `.exploded` give the short and full forms; `int(addr)` reveals the underlying number.
  - Then it prints the classification plus the one-line SOC hint for the common cases.
- **`DEMO_ADDRESSES`** — six safe, documentation-only addresses covering every neighborhood, so `--demo` works with zero typing.
- **`main()` and `argparse`** — reads your command line: an optional address, `--demo` to walk the examples, `--why` for the explainer. No address and no `--demo` prints help with a tip, instead of failing mysteriously.

## Key terms, translated

| Term | Plain English |
|---|---|
| IPv6 address | A 128-bit "phone number" for a device, written as 8 groups of hex separated by colons |
| Compressed / exploded form | Shorthand (`2001:db8::1`, where `::` squashes zeros) vs fully written out — same address |
| Loopback (`::1`) | Your own machine talking to itself (IPv4's `127.0.0.1`) |
| Link-local (`fe80::/10`) | Works only on your own cable/Wi-Fi; routers never forward it — shouting across the room |
| Unique local (`fc00::/7`) | IPv6's private addresses — like `192.168.x.x`, never on the public internet |
| Multicast (`ff00::/8`) | One address reaching a whole group at once — a radio station, not a phone call |
| Global unicast (`2000::/3`) | A real public-internet address — the "postal address" |
| IPv4-mapped (`::ffff:0:0/96`) | An IPv4 address in an IPv6 costume, for the transition between the two systems |
| Hex (hexadecimal) | Base-16 numbers (0-9 plus a-f) — a compact way to write long binary numbers |

## How to run it

```bash
python3 ipv6_explorer.py --demo            # learn from built-in examples
python3 ipv6_explorer.py 2001:db8::1       # explain one address
python3 ipv6_explorer.py fe80::1 --why     # plus the "why IPv6" explainer
```

No installs, no network, no admin rights — any laptop with Python 3 runs it.

## What to learn next

- **Read real logs with new eyes.** Next time an alert shows an IPv6 address, classify it before reacting: `fe80::` or `::1`? Background noise. A global unicast you've never seen? Worth the click.
- **Meet the IPv6 header.** Day 18's packet decoder read IPv4 headers — compare: the IPv6 header is simpler and fixed-size (40 bytes), and it dropped the checksum entirely. Simpler headers, same analyst skills.
- **Neighbor Discovery.** IPv6 replaced ARP (day 14) with a protocol called NDP that uses multicast instead of broadcast. Same "who has this address?" job, new mechanics — and new spoofing tricks to learn about defensively.
- **Try the `ipaddress` module yourself.** `IPv6Network("2001:db8::/32").supernet()` and friends let you do subnet math (day 7) in the IPv6 world.

---

*Built as a defensive learning exercise: read-only, offline, educational. All example addresses use RFC 3849 / RFC 5737 documentation ranges — no real addresses anywhere.*
