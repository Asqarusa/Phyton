# Day 18 — Reading a Packet Header Like a SOC Analyst 📦

## What's new in this version (2026-11-09)

The decoder grew up: it now reads **two more kinds of envelopes** and takes
proper command-line options.

- **IPv6 support** — the internet is slowly moving to IPv6 (the new, much
  longer address format), and the script can now decode a 40-byte IPv6
  header: traffic class, flow label, payload length, hop limit, and the two
  long addresses, printed in the short `2001:db8::1` style. Try it:
  `python3 packet_decoder.py --demo ipv6`.
- **UDP support** — not every packet is TCP. When the IPv4 header says
  "protocol 17", the script now decodes the 8-byte UDP header (ports and
  length) and guesses the service from well-known ports — 53 is DNS, 123 is
  clock sync, 67/68 is DHCP. Try it: `python3 packet_decoder.py --demo udp`.
- **A real command line** — `--hex` to paste hex directly, `--file` to point
  at a file, `--demo` to pick a built-in sample (`syn`, `rst`, `fin`, `udp`,
  `ipv6`), `--json` for machine-readable output, and `--quiet` for just the
  analyst notes. The old way still works: passing a file name with no flags.
- **Friendlier errors** — bad hex characters, odd-length input, truncated
  packets, and missing files now get a plain-English message and exit code
  2, instead of a Python traceback.
- **Exit codes that mean something** — 0 = clean decode, 1 = decoded fine
  but a scan-like pattern was spotted (a lone SYN or an RST), 2 = input
  error. That makes the script usable inside bigger checks and scripts.
- **Three new samples** — `sample_udp.hex` (a DNS question), `sample_ipv6.hex`
  (an IPv6 SYN knock), and `sample_rst.hex` (a "door slammed" reply).

## The big idea (a non-tech analogy first)

Imagine every message sent across the internet is a letter inside an envelope.
The letter is your data — a web page, a video chunk, a login request. But the
**envelope** is what the network actually reads first: the mailing label says
who sent it and where it's going, and the delivery instructions say which
"door" (port) to knock on and whether this is a new conversation, a reply, or
a goodbye.

Security analysts spend their days reading envelopes, not letters. Why? Because
a flood of envelopes that all say "just knocking, never had a conversation"
is the classic fingerprint of a **port scan** — someone rattling every doorknob
on your network. The envelopes betray the attacker long before any letter
does.

Today's project teaches your computer to read those envelopes: an **IPv4
packet header** (the mailing label) and a **TCP header** (the delivery
instructions).

## What the script does

`packet_decoder.py` takes the raw bytes of a packet header — written as hex
text — and translates them into plain English:

- **IPv4 header:** version, header length, total size, TTL (how many network
  hops the packet may travel), protocol, and the source/destination addresses.
- **TCP header:** source/destination ports, sequence numbers, and the famous
  **flags** — SYN, ACK, FIN, RST, PSH, URG — each translated into what it
  actually means.
- **SOC analyst notes:** automatic observations, e.g. "SYN without ACK means
  this is a connection *request*" or "TTL of 64 suggests a Linux sender."

It works 100% offline. It never touches the network, never sniffs traffic,
never needs special permissions — it only *decodes* headers you hand it. That
makes it a safe teaching tool and a safe demo on any laptop.

Run it with no arguments to decode the built-in sample packet (a TCP SYN
"knock" from a lab machine to port 443), or pass your own hex file:

```
python3 packet_decoder.py
python3 packet_decoder.py sample_packet.hex
python3 packet_decoder.py --demo udp        # a DNS question over UDP
python3 packet_decoder.py --demo ipv6       # the same knock, IPv6 envelope
python3 packet_decoder.py --demo rst        # a "door slammed" RST reply
python3 packet_decoder.py --demo fin        # a polite FIN goodbye
python3 packet_decoder.py --hex 4500...     # paste hex straight on the line
python3 packet_decoder.py --file x.hex --json   # output as JSON
```

## How the code works, line by line (in simple terms)

**`SAMPLE_HEX`** — a hand-crafted 40-byte packet written as hex text. Forty
bytes = the 20-byte IPv4 header + the 20-byte TCP header. No real traffic was
captured; it was built for teaching.

**`clean_hex()`** — removes spaces and newlines so `4500 0028` becomes
`45000028`. Hex files are easier for humans to read with spaces, but Python's
byte converter wants one continuous string.

**`hex_to_bytes()`** — turns the cleaned hex text into actual bytes, and
raises a clear error if you hand it fewer than 40 bytes. Good tools explain
what went wrong instead of crashing mysteriously.

**`decode_ipv4()`** — the heart of the IPv4 half. It uses Python's `struct`
module (`struct.unpack("!BBHHHBBH4s4s", ...)`) to split the 20 bytes into
their real fields. The format string is just a recipe: "B" = one byte, "H" =
two bytes, "4s" = four raw bytes. Two clever bits:

- The first byte packs **two** fields: the top 4 bits are the IP version, the
  bottom 4 bits are the header length. `>> 4` and `& 0x0F` are how you peel
  apart a byte into its two halves — a classic networking trick.
- The four raw bytes of each address get turned into dotted text like
  `10.0.0.5` by joining the numbers with dots.

**`decode_ipv6()`** — the new IPv6 half. An IPv6 header is 40 bytes: the
first 4 bytes pack the version (top 4 bits), traffic class, and flow label
into one number, then payload length, "next header" (which protocol comes
next — 6 for TCP, 17 for UDP), and the hop limit (IPv6's name for TTL).
The two 16-byte addresses are printed in short form with Python's
`ipaddress` module, so `2001:0db8:0000:...:0001` becomes `2001:db8::1`.

**`decode_udp()`** — the new UDP half. A UDP header is only 8 bytes:
source port, destination port, length, checksum. There are no flags and
no handshake in UDP, so the code also guesses the service from well-known
ports (53 = DNS, 123 = NTP clock sync) and says so in plain English.

**`decode_tcp()`** — same idea for the 20-byte TCP header. The interesting
part is the flags byte: six individual on/off switches (FIN, SYN, RST, PSH,
ACK, URG) packed into one byte. The code checks each switch with `&` (bitwise
AND) and translates every set flag into a plain-English sentence like
"SYN (knocking — wants to START a conversation)". New: it also reads the
TCP header length, so if options are present (window scaling, timestamps)
it says so instead of silently ignoring them.

**`soc_notes()`** — turns the decoded fields into analyst observations.
It now returns a second value, `suspicious`, which is True for scan-like
patterns (a lone SYN, an RST). `main()` turns that into exit code 1, so
the script can be chained into bigger checks:

- SYN set but ACK not set → this is a connection *request*, the very first
  knock. Scans send thousands of lone SYNs.
- RST set → someone "slammed the door." Bursts of RSTs can mean a scan hitting
  closed ports.
- TTL value → different operating systems start with different TTLs
  (Windows: 128, Linux/macOS: 64), so the remaining TTL hints at the sender's
  OS and distance. Odd TTLs on far-away-looking sources can suggest spoofing.
  The same logic now applies to IPv6's hop limit.
- Fragmented packets → sometimes used to sneak past simple filters.
- UDP packets → no handshake to read, so the notes explain that analysts
  judge UDP by port and volume, and flag DNS floods specifically.

**`print_section()`** — just pretty-prints each group of fields with a
header, so the output reads like a report.

**`main()`** — ties it together: parse the command line, load hex (from a
demo, `--hex`, a file, or the sample), decode the IP header and then the
TCP or UDP header it points to, print the fields (or JSON with `--json`),
print the analyst notes, and exit 0, 1, or 2 depending on what was found.

## Key terms, translated

| Term | Plain English |
|---|---|
| Packet | One envelope of data traveling across the network |
| IPv4 header | The mailing label: source, destination, and travel rules |
| TCP header | The delivery instructions: which port, and what kind of message |
| Port | A numbered "door" on a computer (443 = the HTTPS door) |
| SYN / ACK / FIN / RST | One-word messages: "knock knock" / "heard you" / "goodbye" / "go away" |
| TTL (Time To Live) | How many network hops this packet may travel before being discarded |
| Hop limit | IPv6's name for TTL — same idea, same OS hints |
| IPv6 | The newer, longer-address version of IP (128-bit addresses) |
| UDP | A simpler protocol with no handshake and no flags — used for DNS, video calls, games |
| Hex | Base-16 writing of raw bytes — `45` means the byte with value 69 |
| `struct.unpack` | Python's way of slicing raw bytes into meaningful numbers |

## How to run it

```bash
python3 packet_decoder.py                 # decode the built-in sample
python3 packet_decoder.py sample_packet.hex   # decode your own header hex
python3 packet_decoder.py --demo ipv6     # IPv6 + TCP sample
python3 packet_decoder.py --demo udp      # IPv4 + UDP (DNS) sample
python3 packet_decoder.py --file x.hex --json   # JSON output for scripts
```

Your own hex file just needs the IPv4 header (20 bytes) followed by the TCP
header (20 bytes), written as hex with or without spaces. No libraries to
install — everything used is in Python's standard library.

## What to learn next

1. **Wireshark** — the free tool professionals use to capture real packets.
   Open any capture, click a packet, and you'll see exactly the fields this
   script decodes — now you'll know what you're looking at.
2. **The TCP three-way handshake** — SYN → SYN-ACK → ACK. The "knock, who's
   there, come in" of the internet. Understanding it explains half of all
   network weirdness.
3. **TCP vs UDP** — UDP packets have no flags and no handshake. Ask yourself:
   what would a UDP header decoder look like, and what could an analyst learn
   from it?
4. **Try decoding by hand** — take the sample hex and a pencil, and decode
   one field yourself using the field order in the code. Analysts who can read
   hex without tools have a real edge.
