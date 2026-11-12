#!/usr/bin/env python3
"""
packet_decoder.py — Read a packet header like a SOC analyst.

WHAT IT DOES
------------
Takes a packet header (as hex text) and breaks it into plain-English
fields: addresses, TTL/hop limit, ports, TCP flags, sequence numbers, and
more. Works 100% offline — no network access, no sniffing, no raw sockets.
It only *decodes* headers you hand it.

NEW IN THIS VERSION
-------------------
- IPv6 headers: decodes the 40-byte IPv6 header (addresses, hop limit,
  next header) plus the TCP/UDP header that follows it.
- UDP headers: when an IPv4 packet says "protocol 17", the script now
  decodes the 8-byte UDP header (ports, length) instead of assuming TCP.
- A real command line: --hex, --file, --json, --demo (syn/rst/fin/udp/ipv6).
- Friendlier errors: bad hex, odd-length input, truncated packets and
  missing files all get a clear message and exit code 2.
- Exit codes: 0 = clean decode, 1 = decode OK but a scan-like pattern was
  spotted (lone SYN, RST), 2 = input error.

WHY THIS MATTERS (the SOC angle)
--------------------------------
Every packet on a network is a little envelope: the IP header is the
mailing label (who sent it, who it goes to, how far it may travel), and
the TCP/UDP header is the delivery instructions (which "door"/port, is
this a new conversation, are we closing one?). Analysts read these
envelopes all day: a flood of packets with only the SYN flag set and no
replies is the classic signature of a port scan; weird TTL values can
hint at spoofed sources.

USAGE
-----
    python3 packet_decoder.py                     # built-in sample (TCP SYN)
    python3 packet_decoder.py sample_packet.hex   # decode hex from a file
    python3 packet_decoder.py --demo udp          # built-in UDP sample
    python3 packet_decoder.py --demo ipv6         # built-in IPv6 sample
    python3 packet_decoder.py --hex 4500...       # decode hex straight away
    python3 packet_decoder.py --file x.hex --json # machine-readable output

Hex input should be the IP header immediately followed by the transport
header (TCP 20 bytes, UDP 8 bytes), with or without spaces. IPv4 headers
are 20 bytes; IPv6 headers are 40 bytes.
"""

import argparse
import ipaddress
import json
import struct
import sys

# ---------------------------------------------------------------------------
# Built-in samples — all hand-crafted for teaching, never captured from a
# real network. The addresses are lab/documentation ranges (RFC 5737 /
# RFC 3849), so nothing here points at a real person or machine.
# ---------------------------------------------------------------------------
SAMPLE_SYN = (
    "4500 0028 1c46 4000 4006 b1e6 0a00 0005 5db8 d822"  # IPv4 header (20 bytes)
    "d431 01bb 0000 0001 0000 0000 5002 7210 0000 0000"  # TCP header  (20 bytes)
)
# A TCP RST ("door slammed") reply to the same knock.
SAMPLE_RST = (
    "4500 0028 1c46 4000 4006 0000 0a00 0005 5db8 d822"
    "d431 01bb 0000 0001 0000 0001 5014 7210 0000 0000"
)
# A polite TCP FIN + ACK goodbye.
SAMPLE_FIN = (
    "4500 0028 1c46 4000 4006 0000 0a00 0005 5db8 d822"
    "d431 01bb 0000 0001 0000 0001 5011 7210 0000 0000"
)
# An IPv4 + UDP packet: a DNS question (port 53) from 10.0.0.5 to 8.8.8.8.
SAMPLE_UDP = (
    "4500 0024 1c47 4000 4011 0000 0a00 0005 0808 0808"  # IPv4 header (20 bytes)
    "14e9 0035 0010 0000"                              # UDP header  (8 bytes)
)
# An IPv6 + TCP SYN packet: same kind of knock, new-style envelope.
SAMPLE_IPV6 = (
    "6000 0000 0014 0640"                              # IPv6 header, first 8 bytes
    "2001 0db8 0000 0000 0000 0000 0000 0001"           # source address (16 bytes)
    "2001 0db8 0000 0000 0000 0000 0000 0002"           # destination address (16 bytes)
    "d431 01bb 0000 0001 0000 0000 5002 7210 0000 0000"  # TCP header (20 bytes)
)

DEMOS = {
    "syn": ("TCP SYN knock (IPv4)", SAMPLE_SYN),
    "rst": ("TCP RST reply (IPv4)", SAMPLE_RST),
    "fin": ("TCP FIN goodbye (IPv4)", SAMPLE_FIN),
    "udp": ("UDP DNS question (IPv4)", SAMPLE_UDP),
    "ipv6": ("TCP SYN knock (IPv6)", SAMPLE_IPV6),
}

TCP_FLAG_NAMES = {
    0x01: "FIN (wants to close the conversation)",
    0x02: "SYN (knocking — wants to START a conversation)",
    0x04: "RST (slamming the door — connection refused/reset)",
    0x08: "PSH (push this data through now, don't wait)",
    0x10: "ACK (acknowledging something received)",
    0x20: "URG (urgent data inside)",
}

# Well-known UDP ports, so the notes can say what the traffic probably is.
UDP_PORT_NAMES = {
    53: "DNS (name lookup)",
    67: "DHCP server (hands out addresses)",
    68: "DHCP client (asks for an address)",
    123: "NTP (clock sync)",
    161: "SNMP (device monitoring)",
    1900: "SSDP (device discovery)",
    5353: "mDNS (local name lookup)",
}

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def clean_hex(raw):
    """Strip spaces/newlines so '4500 0028' becomes '45000028'."""
    return "".join(raw.split())


def hex_to_bytes(raw):
    """Turn hex text into bytes, with friendly errors for bad input.

    Raises ValueError with a plain-English message instead of a cryptic
    traceback: odd-length hex, characters that aren't hex, or a packet
    too short to hold even the smallest header.
    """
    h = clean_hex(raw)
    if not h:
        raise ValueError("No hex given — the input was empty.")
    if len(h) % 2:
        raise ValueError(
            f"Hex has an odd length ({len(h)} characters). Every byte needs "
            "two hex characters — did a character get cut off?"
        )
    try:
        data = bytes.fromhex(h)
    except ValueError:
        bad = sorted({c for c in h if c not in "0123456789abcdefABCDEF"})
        raise ValueError(
            "Not valid hex. Characters that aren't hex digits: "
            + ", ".join(repr(c) for c in bad[:5])
            + ". Hex only uses 0-9 and a-f."
        )
    if len(data) < 1:
        raise ValueError("Need at least 1 byte to read the IP version.")
    version = data[0] >> 4
    if version == 4:
        need = 20  # IPv4 header alone
    elif version == 6:
        need = 40  # IPv6 header alone
    else:
        raise ValueError(
            f"The first nibble says IP version {version}, but this tool only "
            "understands IPv4 (starts with 4) and IPv6 (starts with 6). "
            "Did the hex get shifted by a character?"
        )
    if len(data) < need:
        raise ValueError(
            f"Packet is too short: got {len(data)} bytes, but an IPv{version} "
            f"header alone needs {need} bytes."
        )
    return data


def ip4_str(b):
    """4 raw bytes -> '10.0.0.5'."""
    return ".".join(str(x) for x in b)


def ip6_str(b):
    """16 raw bytes -> a compressed IPv6 address like '2001:db8::1'."""
    return str(ipaddress.IPv6Address(b))


def decode_ipv4(data):
    """Unpack the first 20 bytes as an IPv4 header. Returns a dict of fields."""
    (ver_ihl, tos, total_len, ident, flags_frag,
     ttl, proto, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])

    version = ver_ihl >> 4          # top 4 bits: IP version (should be 4)
    ihl = ver_ihl & 0x0F           # bottom 4 bits: header length in 32-bit words
    df = bool(flags_frag & 0x4000)  # "Don't Fragment" bit
    mf = bool(flags_frag & 0x2000)  # "More Fragments" bit

    return {
        "Version": version,
        "Header length": f"{ihl * 4} bytes",
        "Total packet size": f"{total_len} bytes",
        "TTL (hops remaining)": ttl,
        "Protocol": PROTOCOL_NAMES.get(proto, f"unknown ({proto})"),
        "Protocol number": proto,
        "Don't Fragment": "yes" if df else "no",
        "More Fragments": "yes (fragmented packet!)" if mf else "no",
        "Source address": ip4_str(src),
        "Destination address": ip4_str(dst),
    }


def decode_ipv6(data):
    """Unpack the first 40 bytes as an IPv6 header. Returns a dict of fields."""
    (ver_class_flow, payload_len, next_header,
     hop_limit) = struct.unpack("!IHBB", data[:8])
    version = ver_class_flow >> 28
    traffic_class = (ver_class_flow >> 20) & 0xFF
    flow_label = ver_class_flow & 0xFFFFF

    return {
        "Version": version,
        "Traffic class": traffic_class,
        "Flow label": flow_label,
        "Payload length": f"{payload_len} bytes (everything after this header)",
        "Next header": PROTOCOL_NAMES.get(next_header, f"unknown ({next_header})"),
        "Next header number": next_header,
        "Hop limit (hops remaining)": hop_limit,
        "Source address": ip6_str(data[8:24]),
        "Destination address": ip6_str(data[24:40]),
    }


def decode_tcp(data, start):
    """Unpack 20 bytes of TCP header starting at `start`. Returns a dict."""
    if len(data) < start + 20:
        raise ValueError(
            f"Packet ends after {len(data)} bytes — a TCP header needs "
            f"{start + 20} bytes (the IP header plus 20)."
        )
    (src_port, dst_port, seq, ack,
     offset_flags, window, checksum, urg) = struct.unpack(
        "!HHIIHHHH", data[start:start + 20])

    data_offset = (offset_flags >> 12) * 4   # header length in bytes
    flags = offset_flags & 0x3F              # low 6 bits are the flags

    flag_list = [name for bit, name in sorted(TCP_FLAG_NAMES.items()) if flags & bit]
    if not flag_list:
        flag_list = ["(no flags set — unusual for real traffic)"]

    result = {
        "Source port": src_port,
        "Destination port": dst_port,
        "Sequence number": seq,
        "Acknowledgment number": ack,
        "TCP header length": f"{data_offset} bytes",
        "Flags": flag_list,
        "Window size": f"{window} bytes (how much data the sender can receive)",
    }
    if data_offset > 20:
        result["TCP options"] = (
            f"present ({data_offset - 20} extra bytes — e.g. window scaling, "
            "timestamps, or selective ACK)"
        )
    return result


def decode_udp(data, start):
    """Unpack 8 bytes of UDP header starting at `start`. Returns a dict."""
    if len(data) < start + 8:
        raise ValueError(
            f"Packet ends after {len(data)} bytes — a UDP header needs "
            f"{start + 8} bytes (the IP header plus 8)."
        )
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[start:start + 8])
    return {
        "Source port": src_port,
        "Destination port": dst_port,
        "UDP length": f"{length} bytes (header + data)",
        "Checksum": f"0x{checksum:04x}",
        "Probably": (
            UDP_PORT_NAMES.get(dst_port)
            or UDP_PORT_NAMES.get(src_port)
            or "unknown service — check the port number"
        ),
    }


def soc_notes(ip, transport, kind):
    """Translate decoded fields into analyst observations.

    Returns (notes, suspicious) — suspicious is True when the pattern
    looks like scanning behaviour worth flagging.
    """
    notes = []
    suspicious = False

    if kind == "tcp":
        flags_text = " ".join(transport["Flags"])
        if "SYN" in flags_text and "ACK" not in flags_text:
            notes.append(
                "SYN without ACK: this is a connection *request* — the very "
                "first knock. Scans often send thousands of lone SYNs to "
                "many ports."
            )
            suspicious = True
        if "RST" in flags_text:
            notes.append(
                "RST set: someone slammed the door. A burst of RSTs can mean "
                "a scan hitting closed ports, or a firewall killing "
                "connections."
            )
            suspicious = True
        if "FIN" in flags_text:
            notes.append(
                "FIN set: a polite goodbye — this side is closing the "
                "conversation."
            )
        if "TCP options" in transport:
            notes.append(
                "TCP options are present: the sender is a modern OS, not a "
                "bare-bones scanner (simple scanners usually send no options)."
            )
    elif kind == "udp":
        notes.append(
            "UDP has no handshake and no flags — there is no 'knock' to "
            "read, so analysts judge UDP traffic by port and volume instead. "
            "A flood of UDP to many ports is the UDP version of a scan."
        )
        if transport["Destination port"] == 53:
            notes.append(
                "Destination port 53: a DNS question. Huge numbers of DNS "
                "questions from one host can mean DNS tunneling or a flood."
            )

    # TTL / hop-limit hints work for both IP versions.
    ttl = ip.get("TTL (hops remaining)", ip.get("Hop limit (hops remaining)"))
    if ttl is not None:
        if ttl > 128:
            notes.append(
                f"Hop limit/TTL is {ttl} (high): likely a Windows sender "
                "(starts at 128) or a nearby host. Very low values on "
                "distant-looking sources can suggest spoofing."
            )
        elif ttl <= 64:
            notes.append(
                f"Hop limit/TTL is {ttl}: consistent with a Linux/macOS "
                "sender (starts at 64)."
            )
    if ip.get("More Fragments", "no") != "no":
        notes.append(
            "Fragmented packet: fragments are sometimes abused to sneak past "
            "simple filters — worth a second look."
        )
    if not notes:
        notes.append("Nothing odd jumps out in these header fields.")
    return notes, suspicious


def print_section(title, fields):
    print(f"\n--- {title} ---")
    for key, value in fields.items():
        if isinstance(value, list):
            print(f"{key}:")
            for item in value:
                print(f"    * {item}")
        else:
            print(f"{key}: {value}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Decode an IPv4/IPv6 + TCP/UDP packet header into plain English. "
                    "Fully offline — it only reads the hex you hand it.",
        epilog="Exit codes: 0 = clean decode, 1 = decoded but a scan-like "
               "pattern was spotted, 2 = input error.",
    )
    parser.add_argument("file", nargs="?", default=None,
                        help="file holding the header hex (optional)")
    parser.add_argument("--hex", dest="hex_text", default=None,
                        help="decode this hex text directly")
    parser.add_argument("--file", dest="file_opt", default=None,
                        help="file holding the header hex")
    parser.add_argument("--demo", choices=sorted(DEMOS),
                        help="decode a built-in sample: syn, rst, fin, udp, ipv6")
    parser.add_argument("--json", action="store_true",
                        help="print the decoded fields as JSON instead of text")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the SOC notes (plus JSON if --json)")
    return parser


def load_hex(args):
    """Pick the hex source in priority order: --demo, --hex, --file, file, sample."""
    if args.demo:
        label, raw_hex = DEMOS[args.demo]
        return raw_hex, f"Decoding the built-in {args.demo} sample ({label})."
    if args.hex_text:
        return args.hex_text, "Decoding hex from the command line."
    path = args.file_opt or args.file
    if path:
        try:
            with open(path) as f:
                raw_hex = f.read()
        except FileNotFoundError:
            print(f"Error: no file called '{path}'. Check the spelling and try again.",
                  file=sys.stderr)
            sys.exit(2)
        except OSError as e:
            print(f"Error: could not read '{path}': {e}", file=sys.stderr)
            sys.exit(2)
        return raw_hex, f"Decoding packet from: {path}"
    return SAMPLE_SYN, (
        "Decoding the built-in sample packet (a TCP SYN 'knock').\n"
        "Tip: try --demo udp, --demo ipv6, or pass your own hex file."
    )


def main():
    args = build_parser().parse_args()
    raw_hex, source_note = load_hex(args)

    try:
        packet = hex_to_bytes(raw_hex)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    version = packet[0] >> 4
    if version == 4:
        ip = decode_ipv4(packet)
        ip_title = "IPv4 header — the mailing label"
        transport_start = 20
        proto = ip["Protocol number"]
    else:
        ip = decode_ipv6(packet)
        ip_title = "IPv6 header — the mailing label"
        transport_start = 40
        proto = ip["Next header number"]

    try:
        if proto == 6:
            transport = decode_tcp(packet, transport_start)
            transport_title = "TCP header — the delivery instructions"
            kind = "tcp"
        elif proto == 17:
            transport = decode_udp(packet, transport_start)
            transport_title = "UDP header — the delivery instructions"
            kind = "udp"
        else:
            print(
                f"Error: this packet's next protocol is {proto} "
                f"({PROTOCOL_NAMES.get(proto, 'unknown')}), and this tool only "
                "decodes TCP (6) and UDP (17) headers after the IP header.",
                file=sys.stderr,
            )
            sys.exit(2)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    notes, suspicious = soc_notes(ip, transport, kind)

    if args.json:
        print(json.dumps({
            "ip": ip,
            "transport": transport,
            "transport_kind": kind,
            "soc_notes": notes,
            "suspicious": suspicious,
        }, indent=2))
    else:
        if not args.quiet:
            print(source_note)
            print_section(ip_title, ip)
            print_section(transport_title, transport)
        print("\n--- SOC analyst notes ---")
        for note in notes:
            print(f"  > {note}")
        if not args.quiet:
            print(
                "\nTakeaway: packets are just envelopes with labels. Learning "
                "to read the labels — addresses, flags, TTL — is the first "
                "step toward reading network traffic like an analyst."
            )

    sys.exit(1 if suspicious else 0)


if __name__ == "__main__":
    main()
