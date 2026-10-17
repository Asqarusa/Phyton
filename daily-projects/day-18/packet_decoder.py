#!/usr/bin/env python3
"""
packet_decoder.py — Read an IPv4 + TCP packet header like a SOC analyst.

WHAT IT DOES
------------
Takes a packet's IPv4 and TCP headers (as hex text) and breaks them into
plain-English fields: source/destination addresses, TTL, TCP flags, ports,
sequence numbers, and more. Works 100% offline — no network access, no
sniffing, no raw sockets. It only *decodes* headers you hand it.

WHY THIS MATTERS (the SOC angle)
--------------------------------
Every packet on a network is a little envelope: the IPv4 header is the
mailing label (who sent it, who it goes to, how far it may travel), and the
TCP header is the delivery instructions (which "door"/port, is this a new
conversation, are we closing one?). Analysts read these envelopes all day:
a flood of packets with only the SYN flag set and no replies is the classic
signature of a port scan; weird TTL values can hint at spoofed sources.

USAGE
-----
    python3 packet_decoder.py                # decodes the built-in sample packet
    python3 packet_decoder.py sample_packet.hex   # decodes hex from a file

The hex file should contain the raw bytes of the IPv4 header (20 bytes)
immediately followed by the TCP header (20 bytes), with or without spaces.
"""

import struct
import sys

# ---------------------------------------------------------------------------
# A built-in sample: an IPv4 + TCP SYN packet (40 bytes = 80 hex chars).
# This is a "knock on the door" packet — source 10.0.0.5 (a private, fake
# lab address) asking destination 93.184.216.34 (example.com, an address
# reserved for documentation) to open port 443.
# Crafted by hand for teaching, not captured from a real network.
# ---------------------------------------------------------------------------
SAMPLE_HEX = (
    "4500 0028 1c46 4000 4006 b1e6 0a00 0005 5db8 d822"  # IPv4 header (20 bytes)
    "d431 01bb 0000 0001 0000 0000 5002 7210 0000 0000"  # TCP header  (20 bytes)
)

TCP_FLAG_NAMES = {
    0x01: "FIN (wants to close the conversation)",
    0x02: "SYN (knocking — wants to START a conversation)",
    0x04: "RST (slamming the door — connection refused/reset)",
    0x08: "PSH (push this data through now, don't wait)",
    0x10: "ACK (acknowledging something received)",
    0x20: "URG (urgent data inside)",
}


def clean_hex(raw):
    """Strip spaces/newlines so '4500 0028' becomes '45000028'."""
    return "".join(raw.split())


def hex_to_bytes(raw):
    """Turn hex text into bytes; complain clearly if it's malformed."""
    h = clean_hex(raw)
    if len(h) < 80:
        raise ValueError(
            f"Need at least 40 bytes (80 hex chars) of IPv4+TCP header, got {len(h)//2} bytes."
        )
    return bytes.fromhex(h[:80])


def decode_ipv4(data):
    """Unpack the first 20 bytes as an IPv4 header. Returns a dict of fields."""
    (ver_ihl, tos, total_len, ident, flags_frag,
     ttl, proto, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])

    version = ver_ihl >> 4          # top 4 bits: IP version (should be 4)
    ihl = ver_ihl & 0x0F           # bottom 4 bits: header length in 32-bit words
    df = bool(flags_frag & 0x4000)  # "Don't Fragment" bit
    mf = bool(flags_frag & 0x2000)  # "More Fragments" bit

    def ip_str(b):
        return ".".join(str(x) for x in b)  # 4 raw bytes -> "10.0.0.5"

    return {
        "Version": version,
        "Header length": f"{ihl * 4} bytes",
        "Total packet size": f"{total_len} bytes",
        "TTL (hops remaining)": ttl,
        "Protocol": {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"unknown ({proto})"),
        "Don't Fragment": "yes" if df else "no",
        "More Fragments": "yes (fragmented packet!)" if mf else "no",
        "Source address": ip_str(src),
        "Destination address": ip_str(dst),
    }


def decode_tcp(data):
    """Unpack the next 20 bytes as a TCP header. Returns a dict of fields."""
    (src_port, dst_port, seq, ack,
     offset_flags, window, checksum, urg) = struct.unpack("!HHIIHHHH", data[20:40])

    data_offset = (offset_flags >> 12) * 4   # header length in bytes
    flags = offset_flags & 0x3F              # low 6 bits are the flags

    flag_list = [name for bit, name in sorted(TCP_FLAG_NAMES.items()) if flags & bit]
    if not flag_list:
        flag_list = ["(no flags set — unusual for real traffic)"]

    return {
        "Source port": src_port,
        "Destination port": dst_port,
        "Sequence number": seq,
        "Acknowledgment number": ack,
        "TCP header length": f"{data_offset} bytes",
        "Flags": flag_list,
        "Window size": f"{window} bytes (how much data the sender can receive)",
    }


def soc_notes(ip, tcp):
    """Translate a couple of header fields into analyst observations."""
    notes = []
    flags_text = " ".join(tcp["Flags"])
    if "SYN" in flags_text and "ACK" not in flags_text:
        notes.append(
            "SYN without ACK: this is a connection *request* — the very first "
            "knock. Scans often send thousands of lone SYNs to many ports."
        )
    if "RST" in flags_text:
        notes.append(
            "RST set: someone slammed the door. A burst of RSTs can mean a "
            "scan hitting closed ports, or a firewall killing connections."
        )
    if "FIN" in flags_text:
        notes.append(
            "FIN set: a polite goodbye — this side is closing the conversation."
        )
    ttl = ip["TTL (hops remaining)"]
    if ttl > 128:
        notes.append(
            f"TTL is {ttl} (high): likely a Windows sender (starts at 128) or "
            "a nearby host. Very low TTLs on distant-looking sources can "
            "suggest spoofing."
        )
    elif ttl <= 64:
        notes.append(
            f"TTL is {ttl}: consistent with a Linux/macOS sender (starts at 64)."
        )
    if ip["More Fragments"] != "no":
        notes.append(
            "Fragmented packet: fragments are sometimes abused to sneak past "
            "simple filters — worth a second look."
        )
    if not notes:
        notes.append("Nothing odd jumps out in these header fields.")
    return notes


def print_section(title, fields):
    print(f"\n--- {title} ---")
    for key, value in fields.items():
        if isinstance(value, list):
            print(f"{key}:")
            for item in value:
                print(f"    * {item}")
        else:
            print(f"{key}: {value}")


def main():
    # Load hex: from a file if given, else the built-in sample.
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            raw_hex = f.read()
        print(f"Decoding packet from: {sys.argv[1]}")
    else:
        raw_hex = SAMPLE_HEX
        print("Decoding the built-in sample packet (a TCP SYN 'knock').")
        print("Tip: save your own 40-byte header hex in a file and pass it as an argument.")

    try:
        packet = hex_to_bytes(raw_hex)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    ip = decode_ipv4(packet)
    tcp = decode_tcp(packet)

    print_section("IPv4 header — the mailing label", ip)
    print_section("TCP header — the delivery instructions", tcp)

    print("\n--- SOC analyst notes ---")
    for note in soc_notes(ip, tcp):
        print(f"  > {note}")

    print(
        "\nTakeaway: packets are just envelopes with labels. Learning to read "
        "the labels — addresses, flags, TTL — is the first step toward "
        "reading network traffic like an analyst."
    )


if __name__ == "__main__":
    main()
