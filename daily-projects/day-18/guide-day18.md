# Day 18 — Reading a Packet Header Like a SOC Analyst 📦

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

**`decode_tcp()`** — same idea for the 20-byte TCP header. The interesting
part is the flags byte: six individual on/off switches (FIN, SYN, RST, PSH,
ACK, URG) packed into one byte. The code checks each switch with `&` (bitwise
AND) and translates every set flag into a plain-English sentence like
"SYN (knocking — wants to START a conversation)".

**`soc_notes()`** — turns the decoded fields into analyst observations:

- SYN set but ACK not set → this is a connection *request*, the very first
  knock. Scans send thousands of lone SYNs.
- RST set → someone "slammed the door." Bursts of RSTs can mean a scan hitting
  closed ports.
- TTL value → different operating systems start with different TTLs
  (Windows: 128, Linux/macOS: 64), so the remaining TTL hints at the sender's
  OS and distance. Odd TTLs on far-away-looking sources can suggest spoofing.
- Fragmented packets → sometimes used to sneak past simple filters.

**`print_section()`** — just pretty-prints each group of fields with a
header, so the output reads like a report.

**`main()`** — ties it together: load hex (from a file or the sample),
decode both headers, print them, print the analyst notes, and close with the
takeaway.

## Key terms, translated

| Term | Plain English |
|---|---|
| Packet | One envelope of data traveling across the network |
| IPv4 header | The mailing label: source, destination, and travel rules |
| TCP header | The delivery instructions: which port, and what kind of message |
| Port | A numbered "door" on a computer (443 = the HTTPS door) |
| SYN / ACK / FIN / RST | One-word messages: "knock knock" / "heard you" / "goodbye" / "go away" |
| TTL (Time To Live) | How many network hops this packet may travel before being discarded |
| Hex | Base-16 writing of raw bytes — `45` means the byte with value 69 |
| `struct.unpack` | Python's way of slicing raw bytes into meaningful numbers |

## How to run it

```bash
python3 packet_decoder.py                 # decode the built-in sample
python3 packet_decoder.py sample_packet.hex   # decode your own header hex
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
