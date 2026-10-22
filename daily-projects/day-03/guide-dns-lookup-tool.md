# DNS Lookup Tool — Plain-English Guide

*Part of my "learn cybersecurity by building tiny tools" series. Day 3, evening project.*
*Last updated: 2026-10-22 — improved version (see "What's new" below).*

## What's new in this version

Like a good phone book, a good tool should get better with each edition. I went back
through my Day 3 DNS lookup tool and made it genuinely more useful:

- **Forward-confirmed reverse DNS (FCrDNS).** For every reverse lookup, the tool now
  checks whether the name points *back* to the same IP address. Think of it like this:
  you call a number, someone says "this is the bank" — then you hang up and call the
  bank's official number to check it's really them. Spam filters do exactly this to
  judge whether a mail server is who it claims to be.
- **Input validation.** Feed it junk like `not a domain!!` and it now says **INVALID**
  instead of confusing you with a weird error. It also strips ports and paths, so
  `example.com:8080/page` still works.
- **Proper command-line flags.** Real `--examples`, `--json`, `--timeout`, and
  `--no-reverse` options instead of hand-rolled argument parsing — plus a `--help`
  screen that documents everything.
- **JSON output (`--json`).** Machine-readable results, so another script can consume
  the tool's answers — a small step toward building real toolchains.
- **Per-step timing and a batch summary.** Each lookup shows its own time, and when
  you check several domains you get a summary table comparing them all at a glance.
- **Friendly failures.** Timeouts and missing networks now produce clear messages
  ("Timed out resolving…") instead of tracebacks.

## The big idea (start here)

## The big idea (start here)

Imagine the internet as a giant city where every building has a name (like `google.com`)
and a phone number (like `142.250.190.46`). Computers only "call" phone numbers — they
can't dial names. So every time you type a website name, your computer quietly asks a
special directory: **"What's the phone number for this name?"**

That directory is called **DNS — the Domain Name System**. It's basically the
internet's phone book, and it's one of the oldest and most important services running
the web. When DNS breaks, the internet feels broken, even though every cable and
server is fine.

This little project asks the phone book a few questions and shows you the answers:
forward lookups (name → number) and reverse lookups (number → name).

## What the script does

`dns_lookup_tool.py` takes one or more domain names and, for each one:

1. **A-record lookup** — asks DNS for the IPv4 address (the classic "phone number").
2. **AAAA-record lookup** — asks DNS for the IPv6 address (the newer, longer "phone number").
3. **Reverse (PTR) lookup** — takes the IPv4 address and asks, "what name is registered
   at this address?" This is like calling a number and asking who lives there.
4. **Timing** — measures how long the lookups took, so you can feel how fast DNS really is.

Run it with your own domains or with `--examples` to use built-in sample domains.

## How the code works, line by line (in simple terms)

- **`import socket`** — Python's built-in networking library. Everything DNS-related
  in this script comes from this one import. No extra installs needed.
- **`lookup_ipv4(domain)`** — calls `socket.gethostbyname_ex(domain)`, which is Python's
  way of saying "hey, DNS server, give me the IPv4 addresses for this name." It returns
  the official name, any aliases, and the list of addresses.
- **`lookup_ipv6(domain)`** — calls `socket.getaddrinfo(domain, None, socket.AF_INET6)`,
  asking the same question but specifically for IPv6 addresses (`AAAA` records). Many
  sites still don't have IPv6, so "not found" is a perfectly normal answer.
- **`reverse_lookup(ip_address)`** — calls `socket.gethostbyaddr(ip_address)`. This asks
  for the **PTR record** — the reverse page of the phone book. Lots of IPs don't have
  one registered, and the script says so plainly instead of crashing.
- **`is_valid_domain(domain)`** — the bouncer at the door. Uses a regular expression
  to check the input actually looks like a domain (letters, digits, hyphens, at least
  one dot). Junk gets flagged **INVALID** with a clear message before any network
  call happens.
- **`forward_confirmed(ip, ptr_name)`** — the "call back to verify" step. Takes the
  name the PTR record claims and resolves it forward; if the same IP comes back, the
  reverse record is *confirmed*. Spam filters (like Gmail's) really do run this check.
- **`argparse`** — Python's standard library for command-line options. This is what
  real tools use for `--help`, `--json`, `--timeout`: defined once, documented
  automatically.
- **`--json`** — prints the whole result set as JSON. Same data, different shape:
  humans get the pretty table, scripts get the JSON. Both come from one code path.
- **The `try/except` blocks** — DNS can fail for boring reasons (typo in the name, no
  network, no reverse record). Instead of crashing, each lookup returns a friendly
  "couldn't resolve" message. Timeouts now get their own clear message too.
  Handling errors gracefully is a real-world skill.
- **`time.perf_counter()`** — a stopwatch around the lookups. DNS answers in
  milliseconds, and seeing the number makes that real.
- **The input cleanup in `main()`** — strips `http://`, trailing slashes, and paths,
  so `https://example.com/page` still works as `example.com`. Small kindnesses like
  this are what make tools pleasant to use.

## Key terms, translated

| Term | Plain English |
|---|---|
| DNS | The internet's phone book: turns names into numbers |
| A record | A phone-book entry: "this name lives at this IPv4 address" |
| AAAA record | The same entry, but for the newer IPv6 address format |
| PTR record | The reverse page of the phone book: "who lives at this IP?" |
| IPv4 | Classic address format: four numbers, e.g. `93.184.216.34` |
| IPv6 | Newer address format: longer, written with colons |
| DNS server | Who you ask — usually your router or your internet provider |

## How to run it

```bash
# Built-in examples (safe, no typing needed)
python3 dns_lookup_tool.py --examples

# Your own domains, with a batch summary table
python3 dns_lookup_tool.py example.com github.com

# Messy input is cleaned up automatically
python3 dns_lookup_tool.py https://example.com:8080/some/page

# Machine-readable JSON for other scripts
python3 dns_lookup_tool.py example.com --json

# Skip reverse lookups (faster), custom timeout
python3 dns_lookup_tool.py example.com --no-reverse --timeout 3
```

## Why this matters for cybersecurity

DNS is a favorite target in real attacks. Attackers poison DNS caches to redirect you
to fake banking sites, or they quietly watch DNS queries to learn which sites a
company visits. Understanding what a *normal* DNS answer looks like is step one toward
recognizing an abnormal one — which is exactly what SOC analysts do all day.

## What to learn next

- Try `nslookup example.com` or `dig example.com` in your terminal — the same lookups,
  no Python needed.
- Look up **MX records** (they say where a domain's email goes) — same idea, different
  page of the phone book.
- Read about **DNS over HTTPS (DoH)** — the modern, encrypted version of these queries,
  and why it matters for privacy.
