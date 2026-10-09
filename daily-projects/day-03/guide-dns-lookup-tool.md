# DNS Lookup Tool — Plain-English Guide

*Part of my "learn cybersecurity by building tiny tools" series. Day 3, evening project.*

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
- **The `try/except` blocks** — DNS can fail for boring reasons (typo in the name, no
  network, no reverse record). Instead of crashing, each lookup returns a friendly
  "couldn't resolve" message. Handling errors gracefully is a real-world skill.
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

# Your own domains
python3 dns_lookup_tool.py example.com github.com

# Messy input is cleaned up automatically
python3 dns_lookup_tool.py https://example.com/some/page
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
