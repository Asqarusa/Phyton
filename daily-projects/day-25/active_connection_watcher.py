#!/usr/bin/env python3
"""
Day 25 — Active Connection Watcher
===================================
"Who is my computer talking to right now?"

Reads the machine's ACTIVE (ESTABLISHED) TCP connections from
/proc/net/tcp and /proc/net/tcp6 and explains each one in plain English:
which local program socket is talking to which remote address, what
service that remote port usually means, and whether the connection looks
ordinary or worth a second look.

This is the FIRST thing a SOC analyst checks on a suspect host:
malware "phones home" to an attacker's server, and that phone call shows
up here as an outbound ESTABLISHED connection.

Read-only and offline: the script never sends a single packet. It only
reads the connection list your own operating system already keeps.

Usage:
    python3 active_connection_watcher.py            # live view (Linux)
    python3 active_connection_watcher.py --demo    # sample data, any OS
    python3 active_connection_watcher.py --verbose # add per-connection detail
"""

import argparse
import ipaddress
import socket
import struct
import sys

# ---------------------------------------------------------------------------
# Known ports: what a remote port number USUALLY means. Used only as a label —
# port 443 is *normally* HTTPS, but anyone can run anything on any port.
# ---------------------------------------------------------------------------
KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet (unencrypted!)", 25: "SMTP email",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP web",
    110: "POP3 email", 123: "NTP time sync", 143: "IMAP email",
    161: "SNMP monitoring", 389: "LDAP directory", 443: "HTTPS web",
    445: "SMB file sharing", 465: "SMTPS email", 514: "Syslog",
    587: "SMTP submit", 636: "LDAPS", 993: "IMAPS email", 995: "POP3S email",
    1433: "MS SQL Server", 1521: "Oracle DB", 1723: "PPTP VPN",
    3306: "MySQL", 3389: "RDP remote desktop", 5432: "PostgreSQL",
    5900: "VNC remote desktop", 5985: "WinRM", 6379: "Redis",
    6443: "Kubernetes API", 6667: "IRC chat", 8000: "Alt HTTP",
    8080: "Alt HTTP / proxy", 8443: "Alt HTTPS", 8888: "Alt HTTP",
    9000: "Alt HTTP", 9090: "Alt HTTP / admin", 27017: "MongoDB",
    4444: "often used by attack tools (Metasploit default)",
    5555: "often used by attack tools / Android ADB",
}

# Ports that are FAMOUSLY abused by malware / scanners. A connection to one
# of these from your machine deserves a closer look (still just a lead!).
SUSPICIOUS_PORTS = {23, 4444, 5555, 6667, 1337, 31337, 12345, 27374, 31337}

# In /proc/net/tcp the connection "state" column is hex. 0A = LISTEN,
# 01 = ESTABLISHED (an active conversation). We only want the conversations.
STATE_NAMES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}

DOC_RANGES = (  # RFC 5737 / 3849 ranges reserved for documentation & samples
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# Sample /proc/net/tcp lines for --demo (hand-written). Every address is from
# the RFC 5737 / 3849 documentation ranges, so nothing here can ever be a
# real host. The local ports are typical ephemeral ports.
# Layout per line: sl, local_address, rem_address, st, ... (see /proc/net/tcp)
# Hex IPs are little-endian per 32-bit word, exactly like the real file.
DEMO_LINES_V4 = [
    # local web browser tab talking to itself (loopback)
    "   0: 0100007F:C001 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
    # HTTPS to a documentation-range web server (stands in for a real site)
    "   1: 0100007F:C002 0A0200C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0",
    # plain HTTP to another documentation-range host
    "   2: 0100007F:C003 176433C6:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0",
    # file share with a machine on the home LAN (private range = normal)
    "   3: 0100007F:C004 281E140A:01BD 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0",
    # the interesting one: outbound to port 4444 — a classic attack-tool port.
    # In demo data this stays SAMPLE, but on a real host it would be [CHECK].
    "   4: 0100007F:C005 2D7100CB:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12349 1 0000000000000000 100 0 0 10 0",
]
# One IPv6 sample: DNS-over-IPv6 to a documentation address (2001:db8::/32).
# Each 8-hex-char word is little-endian, exactly like /proc/net/tcp6.
DEMO_LINES_V6 = [
    "   0: 00000000000000000000000001000000:C101 B80D0120000000000000000001000000:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22345 1 0000000000000000 100 0 0 10 0",
]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def hex_to_ipv4(hex_ip):
    """'0100007F' -> '127.0.0.1'. /proc stores IPv4 little-endian."""
    try:
        packed = struct.pack("<L", int(hex_ip, 16))
        return socket.inet_ntoa(packed)
    except (ValueError, struct.error):
        return None


def hex_to_ipv6(hex_ip):
    """32 hex chars -> normal IPv6 text. /proc stores each 32-bit word
    little-endian, so we flip every group of 8 chars."""
    try:
        if len(hex_ip) != 32:
            return None
        words = [hex_ip[i:i + 8] for i in range(0, 32, 8)]
        flipped = "".join(
            struct.pack("<L", int(w, 16)).hex() for w in words
        )
        return str(ipaddress.IPv6Address(int(flipped, 16)))
    except (ValueError, struct.error, ipaddress.AddressValueError):
        return None


def split_address(field, v6=False):
    """'0100007F:1F90' -> ('127.0.0.1', 8080). Returns (None, None) if broken."""
    if ":" not in field:
        return None, None
    hex_ip, hex_port = field.rsplit(":", 1)
    try:
        port = int(hex_port, 16)
    except ValueError:
        return None, None
    ip = hex_to_ipv6(hex_ip) if v6 else hex_to_ipv4(hex_ip)
    if ip is None:
        return None, None
    return ip, port


def parse_proc_lines(lines, v6=False):
    """Turn raw /proc/net/tcp lines into a list of connection dicts."""
    conns = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("sl"):
            continue  # header row
        parts = line.split()
        if len(parts) < 10:
            continue  # malformed row — skip, don't crash
        local_ip, local_port = split_address(parts[1], v6)
        remote_ip, remote_port = split_address(parts[2], v6)
        if local_ip is None or remote_ip is None:
            continue
        state = parts[3].upper()
        uid = parts[7] if len(parts) > 7 else "?"
        conns.append({
            "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port,
            "state": state, "uid": uid, "v6": v6,
        })
    return conns


def read_proc_files():
    """Read /proc/net/tcp and tcp6. Returns (connections, warnings)."""
    all_conns, warnings = [], []
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path, "r") as fh:
                all_conns.extend(parse_proc_lines(fh.readlines(), v6))
        except FileNotFoundError:
            warnings.append(f"{path} not found (not a Linux host?)")
        except PermissionError:
            warnings.append(f"cannot read {path} (permission denied)")
        except OSError as exc:
            warnings.append(f"error reading {path}: {exc}")
    return all_conns, warnings


# ---------------------------------------------------------------------------
# Analysis: classify each connection and decide if it deserves attention
# ---------------------------------------------------------------------------
def classify_ip(ip_str):
    """Bucket an address: loopback / private LAN / documentation / public."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unparseable"
    if any(ip in net for net in DOC_RANGES):
        return "documentation range (sample data)"
    if ip.is_loopback:
        return "loopback (this machine)"
    if ip.is_private:
        return "private LAN"
    if ip.is_multicast:
        return "multicast"
    return "public internet"


def assess(conn, demo=False):
    """Return (verdict, reasons) for one ESTABLISHED connection.

    In demo mode every address is a documentation-range sample, so nothing
    can be truly suspicious — but we still explain what WOULD be flagged
    on a real host, which is the whole teaching point.
    """
    reasons = []
    remote = conn["remote_ip"]
    rport = conn["remote_port"]
    zone = classify_ip(remote)

    service = KNOWN_PORTS.get(rport, "unknown service")
    conn["service"] = service
    conn["zone"] = zone

    if zone.startswith("documentation"):
        verdict = "SAMPLE"
        reasons.append("documentation-range address — demo data, not real")
        if rport in SUSPICIOUS_PORTS:
            reasons.append(
                f"teaching moment: on a REAL host, port {rport} is famously "
                f"abused by attack tools — that would earn a [CHECK]")
        elif service == "unknown service":
            reasons.append(
                f"teaching moment: on a REAL host, uncommon port {rport} "
                f"would earn a [CHECK] until the program is identified")
        return verdict, reasons

    if zone.startswith("loopback"):
        verdict = "OK"
        reasons.append("talking to itself — normal for local apps")
    elif zone == "private LAN":
        verdict = "OK"
        reasons.append("staying inside your own network")
    else:
        verdict = "OK"
        reasons.append(f"outbound to the public internet ({service})")

    if rport in SUSPICIOUS_PORTS:
        verdict = "CHECK"
        reasons.append(f"remote port {rport} is famously abused by attack tools")
    elif service == "unknown service" and zone == "public internet":
        verdict = "CHECK"
        reasons.append(f"uncommon remote port {rport} — worth identifying the program")

    return verdict, reasons


def print_report(conns, verbose=False, demo=False):
    established = [c for c in conns if c["state"] == "01"]
    other = len(conns) - len(established)

    print("=" * 70)
    print("ACTIVE CONNECTION WATCHER — who is this machine talking to?")
    if demo:
        print("(demo mode: sample data, documentation-range addresses)")
    print("=" * 70)

    if not established:
        print("\nNo ESTABLISHED connections right now. Quiet machine.")
        if other:
            print(f"({other} non-established sockets seen and skipped.)")
        return

    # Aggregate: how many conversations per remote host?
    by_remote = {}
    for c in established:
        by_remote.setdefault(c["remote_ip"], []).append(c)

    print(f"\n{len(established)} active conversation(s) with "
          f"{len(by_remote)} remote host(s):\n")

    checks = 0
    for remote_ip, group in sorted(by_remote.items()):
        verdict, reasons = assess(group[0], demo=demo)
        mark = {"OK": "[ok]  ", "CHECK": "[CHECK]", "SAMPLE": "[demo] "}[verdict]
        if verdict == "CHECK":
            checks += 1
        ports = ", ".join(
            f"{c['remote_port']} ({KNOWN_PORTS.get(c['remote_port'], '?')})"
            + (" [IPv6]" if c["v6"] else "")
            for c in group
        )
        print(f"{mark} {remote_ip}  [{group[0]['zone']}]")
        print(f"         remote port(s): {ports}")
        print(f"         why: {'; '.join(reasons)}")
        if verbose:
            for c in group:
                print(f"           local {c['local_ip']}:{c['local_port']} "
                      f"(uid {c['uid']})")
        print()

    # ---- SOC triage summary ----
    print("-" * 70)
    print("SOC TRIAGE SUMMARY")
    print(f"  Active conversations : {len(established)}")
    print(f"  Unique remote hosts  : {len(by_remote)}")
    print(f"  Flagged for review   : {checks}")
    if checks:
        print("\n  Next steps for anything flagged [CHECK]:")
        print("  1. Identify the local program (uid above; try `ss -tunp`).")
        print("  2. Ask: did YOU start it? Browser, updater, chat app = normal.")
        print("  3. Unknown program + odd port + odd hour = investigate the host.")
    else:
        print("  Nothing unusual — every conversation has an ordinary explanation.")
        if demo:
            print("  (The port-4444 sample above shows what a [CHECK] flag")
            print("   looks like on a real host.)")
    print("\nRemember: a flag is a LEAD, not proof. Confirm before you act.")
    print("-" * 70)


# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="List this machine's active TCP conversations in plain English."
    )
    parser.add_argument("--demo", action="store_true",
                        help="use built-in sample data (works on any OS)")
    parser.add_argument("--verbose", action="store_true",
                        help="show the local socket and uid behind each connection")
    args = parser.parse_args()

    if args.demo:
        conns = parse_proc_lines(DEMO_LINES_V4, v6=False)
        conns += parse_proc_lines(DEMO_LINES_V6, v6=True)
        print_report(conns, verbose=args.verbose, demo=True)
        return 0

    conns, warnings = read_proc_files()
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not conns and warnings:
        print("\nNo connection data available on this system.", file=sys.stderr)
        print("Tip: run with --demo to see the tool work with sample data.",
              file=sys.stderr)
        return 1
    print_report(conns, verbose=args.verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
