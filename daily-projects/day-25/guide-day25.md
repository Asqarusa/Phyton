# Day 25 — Active Connection Watcher

A small Python tool that answers one question: **"Who is my computer
talking to right now?"** It reads your machine's list of active
(ESTABLISHED) TCP connections and explains each one in plain English —
the way a SOC analyst triages a suspect host.

## The big idea (non-tech analogy)

Think of your computer like a house with a telephone. Most of the time
it's making calls you'd expect: the browser calling a website, the
system checking the time, your chat app checking for messages. But if
malware gets in, the first thing it does is **phone home** — it opens a
quiet connection back to the attacker's server so it can receive orders
or send out stolen data.

This script is like pulling the phone bill. Your operating system
already keeps a list of every active call (in files called
`/proc/net/tcp` and `/proc/net/tcp6` on Linux). The script reads that
list — without making any calls itself — and translates each entry:
who you're talking to, what service that usually means, and whether it
looks ordinary or deserves a second look.

## What the script does

1. Reads the active-connection list from `/proc/net/tcp` and
   `/proc/net/tcp6` (read-only — it never sends a single packet).
2. Keeps only **ESTABLISHED** connections — real, ongoing conversations
   — and skips closed or listening sockets.
3. Decodes the cryptic hex addresses Linux stores (like `0A0200C0:01BB`)
   into `192.0.2.10:443`.
4. Labels each remote port with what it *usually* means (443 = HTTPS web,
   53 = DNS, 445 = SMB file sharing…).
5. Classifies every connection:
   - `[ok]` — loopback (talking to itself) or staying on your private LAN
   - `[ok]` — ordinary outbound traffic to the public internet
   - `[CHECK]` — worth investigating: a port famously abused by attack
     tools (like 4444), or an uncommon port nobody can name
   - `[demo]` — sample data (only in `--demo` mode)
6. Prints a SOC triage summary: total conversations, unique remote
   hosts, how many were flagged, and the next steps for each flag.

Run it with `--demo` on any computer (even non-Linux) to see it work
with built-in sample data. Every sample address comes from the
documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x,
2001:db8::/32), so none of them can ever be a real host.

## How the code works (line by line, in simple terms)

- **`KNOWN_PORTS`** — a dictionary that translates port numbers into
  human labels. Port numbers are just conventions (anyone *can* run
  anything on any port), so these are hints, not proof.
- **`SUSPICIOUS_PORTS`** — a small set of ports with a bad reputation
  (23 = unencrypted Telnet, 4444/5555 = default attack-tool ports,
  6667 = IRC, a classic malware hangout). A connection to one of these
  is a lead worth chasing.
- **`hex_to_ipv4` / `hex_to_ipv6`** — Linux stores addresses
  little-endian ("backwards"), so `0100007F` really means `127.0.0.1`.
  These functions flip the bytes back into the address you recognize.
- **`parse_proc_lines`** — reads each row of the connection table,
  skips the header and any malformed rows (bad input never crashes the
  tool — it just gets skipped).
- **`classify_ip`** — buckets each remote address: loopback, private
  LAN, documentation/sample range, or public internet, using Python's
  built-in `ipaddress` module.
- **`assess`** — the heart of the tool. It combines the zone, the port
  label, and the suspicious-port list into one verdict (`OK`, `CHECK`,
  or `SAMPLE`) plus the *reasons* — so every flag is explainable.
- **`print_report`** — groups conversations by remote host, prints the
  verdict table, then the triage summary with next steps.

## How to run it

```bash
python3 active_connection_watcher.py            # live view (Linux)
python3 active_connection_watcher.py --demo     # sample data, any OS
python3 active_connection_watcher.py --verbose  # also show local socket + user id
```

Requirements: Python 3, standard library only — no installs.

## The SOC takeaway

Unexpected **outbound** connections are one of the strongest signs of
compromise. Firewalls mostly watch what's coming *in*; malware counts
on nobody watching what's going *out*. The discipline this tool teaches
is the same one analysts use daily: for every unfamiliar connection,
identify the local program, ask "did I start this?", and treat every
flag as a **lead to confirm** — never proof. Alert-chasing blocks
innocent traffic; real triage confirms first.
