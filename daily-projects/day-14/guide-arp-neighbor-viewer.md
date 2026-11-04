# Day 14 — Who Is on My Local Network? (ARP Neighbor Viewer)

## What's new in this version (2026-11-03)

Think of the original script like a photo of the office lobby — it showed you who was there right now. This version adds a security guard's memory and instincts:

- **Spoofing alarm:** it now notices when two different name badges claim the same seat number (one IP, two MACs) — the classic sign someone is impersonating another device — and when one name badge claims several seat numbers. It prints a clear warning and exits with code 1 so automated checks can catch it.
- **Before-and-after snapshots:** `--save` stores today's device list, and `--compare` checks a later run against it, flagging devices as NEW, GONE, or CHANGED — like comparing today's lobby photo with yesterday's.
- **Real command-line flags:** `--demo`, `--json` (machine-readable output), `--unknown-only` (show only devices we couldn't identify), and `--quiet` (just the table, no explanations). Run `--help` to see them all.
- **More makers recognized:** the built-in vendor table grew from 24 to 57 entries (Cisco, TP-Link, Netgear, Dell, HP, Intel, Huawei, Xiaomi, Sonos, and more), so fewer devices show up as "Unknown vendor."
- **A small bug fixed:** addresses now sort numerically, so 192.168.1.2 correctly appears before 192.168.1.10 (before, plain text sorting put .10 first).
- **Friendlier errors:** bad files and bad flags now explain the problem and exit with code 2 instead of crashing.

## The big idea (plain English first)

Imagine an office building. Every employee has two identifiers:

1. **A name badge** that never changes — like your MAC address. It's burned into the device's hardware at the factory.
2. **A seat number** that changes whenever they move — like an IP address. Your router assigns it, and it can change.

Your computer keeps a little address book that maps seat numbers to name badges: "whoever is sitting at 192.168.1.10 is wearing name badge 3C:22:FB:D4:E5:F6." That address book is called the **ARP table** (Address Resolution Protocol). Every device on your Wi-Fi has one.

Today's script simply *reads* that address book and shows it to you. It doesn't knock on anyone's door — it just reads a list your own computer already keeps.

## What the script does

- Reads your machine's ARP table (on Linux from `/proc/net/arp`, on macOS via the `arp -a` command).
- Lists every device your computer currently knows about: IP address, MAC address, a guess at the device maker, and whether it's on a private address.
- Guesses the vendor from the first 3 bytes of each MAC address (the manufacturer code, called an **OUI**) using a small built-in table — completely offline.
- Has a `--demo` mode with sample data, so it shows real-looking output even on a machine with an empty ARP table (like a cloud server).

## How the code works, in simple terms

- **`OUI_VENDORS`** — a small dictionary mapping manufacturer codes (like `B8:27:EB`, which belongs to Raspberry Pi) to friendly names. The real OUI list has thousands of entries; this is a demo subset. This version grew it from 24 to 57 entries.
- **`detect_spoofing()`** — the new alarm: it builds two maps (IP → MACs and MAC → IPs) and warns when one IP has two or more MACs, or one MAC has two or more IPs. It returns a list of warning strings; an empty list means the table looks clean.
- **`ip_sort_key()`** — turns `192.168.1.10` into the tuple `(192, 168, 1, 10)` so sorting is numeric, not alphabetical (alphabetical sorting wrongly puts `.10` before `.2`).
- **`load_baseline()` / `save_baseline()`** — `--save` writes the current device list as JSON (`{"entries": {"IP": "MAC", ...}}`); `--compare` loads it back, validates it (valid JSON, right shape, real IPs and MACs), and reports NEW / GONE / CHANGED devices. Bad files get a friendly error and exit code 2.
- **`build_parser()`** — defines all command-line flags with `argparse`, so `--help` prints a proper usage page and typos like `--badopt` get a clear error instead of being silently ignored.
- **`is_private_ip()`** — checks whether an address is a private, home/office-style address (10.x.x.x, 192.168.x.x, 172.16–31.x.x) or loopback. Public addresses get flagged "NOT PRIVATE!".
- **`read_proc_net_arp()`** — on Linux, the operating system exposes the ARP table as a plain text file at `/proc/net/arp`. This function reads it and picks out IP + MAC pairs, skipping incomplete entries (`00:00:00:...` means "we asked, nobody answered").
- **`read_arp_command()`** — a fallback for macOS and other systems: runs the `arp -a` command and parses its output with a regular expression.
- **`guess_vendor()`** — chops off the first 3 bytes of the MAC and looks them up in the mini table.
- **`main()`** — ties it together: print a header, read entries, deduplicate, sort by IP, print the table, and explain what it means.
- **`sample_entries()`** — five made-up home-network devices (router, iPhone with randomized MAC, virtual machine, Raspberry Pi) used by `--demo`.

## Key terms translated

| Term | Plain English |
|---|---|
| ARP | "Address Resolution Protocol" — the system devices use to ask "who has this IP address? Tell me your MAC." |
| MAC address | A device's permanent hardware name tag, e.g. `3C:22:FB:D4:E5:F6` |
| OUI | The first half of a MAC address, registered to a manufacturer (like a car's VIN prefix) |
| Private IP | An address only valid inside your home/office network, like an internal extension number |
| ARP spoofing | An attack where a device lies about its name tag to intercept traffic — why analysts watch this table |

## How to run it

```bash
python3 arp_neighbor_viewer.py           # read your real ARP table
python3 arp_neighbor_viewer.py --demo   # see sample output anywhere
python3 arp_neighbor_viewer.py --demo --json          # machine-readable output
python3 arp_neighbor_viewer.py --save baseline.json  # snapshot today's devices
python3 arp_neighbor_viewer.py --compare baseline.json  # spot NEW / GONE / CHANGED
python3 arp_neighbor_viewer.py --unknown-only        # only unidentified devices
python3 arp_neighbor_viewer.py --help                # list every flag
```

Exit codes: `0` means the table looks clean, `1` means a spoofing warning was found, `2` means bad input (bad flag or unreadable baseline file).

You need nothing installed beyond Python 3 — no libraries, no admin rights, no network access. It is read-only: it sends zero packets and talks to zero devices.

## What to learn next

- Run it twice, an hour apart, and diff the lists. A device that appears or disappears is the start of real network triage.
- Read about **ARP spoofing**: the attack this table makes possible, and how tools detect it (hint: two different MACs claiming the same IP is a red flag).
- Look up your router's DHCP client list and compare it with the ARP table — do they agree? Disagreements are interesting to a SOC analyst.
