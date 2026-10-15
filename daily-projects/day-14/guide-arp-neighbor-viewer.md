# Day 14 — Who Is on My Local Network? (ARP Neighbor Viewer)

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

- **`OUI_VENDORS`** — a small dictionary mapping manufacturer codes (like `B8:27:EB`, which belongs to Raspberry Pi) to friendly names. The real OUI list has thousands of entries; this is a demo subset.
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
```

You need nothing installed beyond Python 3 — no libraries, no admin rights, no network access. It is read-only: it sends zero packets and talks to zero devices.

## What to learn next

- Run it twice, an hour apart, and diff the lists. A device that appears or disappears is the start of real network triage.
- Read about **ARP spoofing**: the attack this table makes possible, and how tools detect it (hint: two different MACs claiming the same IP is a red flag).
- Look up your router's DHCP client list and compare it with the ARP table — do they agree? Disagreements are interesting to a SOC analyst.
