# Day 16: What Is Listening on Your Laptop? — Listening Service Inventory

## What's new in this version (improved 2026-11-06)

The first version only counted TCP doors and quietly skipped anything it
didn't understand. This version counts more doors, and is honest about
which ones face the whole street:

- **UDP listeners are now counted too.** The old script only looked at TCP
  (the "phone call" kind of connection). UDP (the "postcard" kind — used by
  DNS, gaming, video calls) now shows up in the same table with a PROTO
  column, so no door is missed.
- **Real IPv6 support — a bug fix.** The old script silently skipped every
  IPv6 listener (it saw an address it couldn't read and threw it away).
  Now `::1` and other IPv6 addresses are decoded properly and listed.
- **EXPOSED flag: localhost vs. the whole network.** A door on `127.0.0.1`
  can only be knocked on from inside your own laptop. A door on `0.0.0.0`
  can be knocked on by anyone on your network — or the internet. Those
  now get a big `[EXPOSED]` warning, because that's the first thing a SOC
  analyst checks.
- **--save / --compare baseline.** Save today's door list, run it again
  next week, and the script tells you which doors are NEW and which are
  GONE — like a "what changed since last time" alarm.
- **--json output** for feeding the results into other tools or a report,
  plus **--risky-only** and **--port N** filters so you can zoom in on one
  door instead of reading the whole list.
- **More services recognized** (Docker, Kubernetes, Elasticsearch,
  Memcached, SNMP, NFS, databases…) and **clear exit codes**: 0 = all
  quiet, 1 = something risky or exposed was found, 2 = a usage error.

## The big idea (the non-tech analogy)

Think of your laptop as an apartment building. A **port** is like a door,
and a **listening port** is a door that is unlocked and waiting for visitors.
Some doors should be open: the mail slot (email), the service entrance you
use yourself (a dev server you started on purpose).

But sometimes there are doors you didn't know existed — a back door left
open by a program you installed months ago, or worse, by malware. Security
analysts call the sum of all these doors your **attack surface**: every open
door is one more way in.

The first step of any security check is simply counting your doors. That is
what this script does — on YOUR machine only, and without changing anything.

## What the script does

Running it prints a table like this:

```
PORT   LISTENING ON   SERVICE         OWNER                 NOTES
8000   127.0.0.1      Dev server      ?                     Django and Python dev servers default to this
2900   127.0.0.1      unknown service ?                     no common service registered here — worth a look [!]
```

For each listening port it shows:

- **PORT** — the door number.
- **LISTENING ON** — which address the door faces. `127.0.0.1` means "only
  people already inside this laptop can knock." `0.0.0.0` would mean "the
  whole world can knock" — much more exposed.
- **SERVICE** — its best guess at what's behind the door (from a built-in
  list of common ports).
- **OWNER** — which program holds the door open (`--verbose`, Linux only).
- **NOTES + [!]** — plain-English context, and a flag on ports that are
  historically risky (Telnet, FTP, SMB, RDP) or just unknown.

## How the code works, line by line

1. **KNOWN_SERVICES** — a dictionary (a lookup table) mapping port numbers
   to what usually lives there: 22 = SSH, 80 = HTTP, 3389 = RDP, and so on.
   Each entry also carries a short explanation and whether the port is
   commonly abused.

2. **hex_port_to_int / hex_ip_to_str** — Linux stores socket info in
   hexadecimal (base 16). These two tiny helpers translate, e.g. `1F40`
   into port `8000` and `0100007F` into `127.0.0.1`.

3. **parse_proc_net_tcp** — Linux keeps a live list of every TCP socket in
   the file `/proc/net/tcp`. It's not a real file on disk; the operating
   system generates it on the fly, like a dashboard. Each row has a state
   column, and `0A` means "LISTENING". The function keeps only those rows.

4. **find_owning_process** — every socket has an ID number (an "inode").
   On Linux you can walk through `/proc/<pid>/fd` (each running program's
   open files) to find which program owns a given socket ID. The script does
   this read-only — it only *looks*.

5. **collect_listeners** — the main data-gathering step. On Linux it reads
   `/proc/net/tcp`; on Mac or Windows (where that file doesn't exist) it
   falls back to gently knocking on common ports of `127.0.0.1` (your own
   loopback address) and noting which answer. **It never contacts any other
   computer.**

6. **describe** — looks a port up in the known-services table. Anything not
   in the table is reported as "unknown service" and flagged — because the
   whole point is that an unexplained door deserves a question, not an
   assumption.

7. **main** — ties it together: parse `--demo`/`--verbose` flags, collect
   the listeners, print the table, and finish with totals and the SOC
   takeaway.

**New in this version:** `parse_proc_net` now takes a protocol and a
listen state, so the same code reads TCP (`0A` = listening) and UDP
(`07` = open for datagrams), and `hex_ip_to_str` understands IPv6
addresses. `is_exposed` checks whether a listener sits on `0.0.0.0` or
`::` (the whole network) instead of localhost. `save_baseline` /
`load_baseline` store today's door list as JSON so `--compare` can flag
NEW and GONE listeners, and `main` returns exit code 1 when anything
risky, exposed, or new shows up.

## Key terms, translated

- **Port** — a numbered door on your machine where network traffic arrives.
  There are 65,535 possible ports.
- **Listener / listening socket** — a program that has opened a door and is
  waiting for someone to knock.
- **127.0.0.1 (loopback)** — "this machine". Traffic to this address never
  leaves your laptop.
- **Attack surface** — everything an attacker could potentially touch. Fewer
  open doors = smaller attack surface.
- **SOC** — Security Operations Center, the team that watches for attacks.
  SOC analysts routinely audit listeners to spot rogue services.

## How to run it

```bash
python3 listener_inventory.py            # inventory of this machine
python3 listener_inventory.py --demo     # same report on sample data
python3 listener_inventory.py --verbose  # also show the owning program (Linux)
python3 listener_inventory.py --json     # machine-readable output
python3 listener_inventory.py --risky-only  # only flagged listeners
python3 listener_inventory.py --port 443    # zoom in on one port
python3 listener_inventory.py --save baseline.json     # remember today's doors
python3 listener_inventory.py --compare baseline.json  # what's NEW / GONE?
```

No packages to install — it only uses Python's standard library.

## What to try next

1. Run it, pick one listener you recognize, and confirm which program it
   belongs to (`--verbose` on Linux, or your OS's task manager).
2. Find one thing listening you *didn't* expect and research it. Is it a
   feature, a forgotten install, or something to remove?
3. Check whether any listener faces `0.0.0.0` (the whole world) instead of
   `127.0.0.1`. Ask yourself: does it need to?
4. For SOC practice: pair this with yesterday's account-takeover detector.
   An unknown listener *plus* suspicious login attempts is how real
   investigations start — one weak signal rarely stands alone.
