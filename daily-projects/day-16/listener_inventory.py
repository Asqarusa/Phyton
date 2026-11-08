#!/usr/bin/env python3
"""
Day 16 — Listening Service Inventory (networking, defensive-only)
IMPROVED version (2026-11-06): UDP listeners, real IPv6 support, exposure
flags, --json, --save/--compare baseline, --risky-only and --port filters.

Big idea: every open "door" on your laptop is a chance for an attacker.
This script takes stock of every TCP and UDP port your OWN machine is
listening on, names the service behind the common ones, and flags anything
surprising. Nothing leaves your laptop: it only reads your own machine's
socket table.

Usage:
    python3 listener_inventory.py              # inventory of this machine
    python3 listener_inventory.py --demo       # same report on sample data
    python3 listener_inventory.py --verbose    # also show the owning process (Linux)
    python3 listener_inventory.py --json       # machine-readable output
    python3 listener_inventory.py --risky-only# only flagged listeners
    python3 listener_inventory.py --port 443   # only look at one port
    python3 listener_inventory.py --save baseline.json
    python3 listener_inventory.py --compare baseline.json
                                               # NEW / GONE since the save

Exit codes: 0 = nothing flagged, 1 = a risky or exposed listener was found,
2 = a usage error (bad flag, unreadable baseline file, ...).

Safe by default: read-only. No connections to anyone else's machine,
no port scanning of remote hosts, no changes to the system.
"""

import argparse
import json
import os
import socket
import sys

# ---------------------------------------------------------------------------
# Known services: what a listener on a common port usually means.
# 'note' is a plain-English explanation for a beginner; 'risk' flags
# services that commonly appear in attacker tooling or default installs.
# ---------------------------------------------------------------------------
KNOWN_SERVICES = {
    21:   ("FTP",            "old file-transfer protocol (sends passwords in plain text)", True),
    22:   ("SSH",            "secure remote shell; normal on dev machines/servers", False),
    23:   ("Telnet",         "ancient remote shell with NO encryption — risky if open", True),
    25:   ("SMTP",           "mail relay; spammers love open mail servers", True),
    53:   ("DNS",            "domain-name lookups; expected on routers/VPN tools", False),
    80:   ("HTTP",           "unencrypted web traffic; normal for local dev servers", False),
    111:  ("RPC/portmapper", "old Unix service directory; often probed by scanners", True),
    123:  ("NTP",            "clock sync; abused in the past for reflection attacks", False),
    139:  ("SMB/NetBIOS",    "Windows file sharing; worms have abused it for years", True),
    143:  ("IMAP",           "email inbox access", False),
    161:  ("SNMP",           "network-device monitoring; leaks info if left public", True),
    443:  ("HTTPS",          "encrypted web traffic; normal", False),
    445:  ("SMB",            "Windows file sharing (WannaCry used this port)", True),
    1433: ("MS SQL Server",  "database server; should only listen on localhost", True),
    1521: ("Oracle DB",      "database server; should only listen on localhost", True),
    2049: ("NFS",            "network file sharing; dangerous if open to the world", True),
    2375: ("Docker",         "Docker remote API with NO auth by default — lock it down", True),
    3306: ("MySQL",          "database server; should only listen on localhost", False),
    3389: ("RDP",            "Windows Remote Desktop; attackers brute-force it", True),
    5432: ("PostgreSQL",     "database server; should only listen on localhost", False),
    5900: ("VNC",            "remote screen sharing; fine on a LAN, scary on the internet", True),
    6379: ("Redis",          "in-memory database; ship it with a password or bind to localhost", True),
    6443: ("Kubernetes API", "cluster control plane; should never face the internet", True),
    8080: ("HTTP-alt",       "web servers and proxies often live here; common in dev", False),
    8443: ("HTTPS-alt",      "encrypted web traffic on an alternate port", False),
    9200: ("Elasticsearch",  "search database; has shipped with no password by default", True),
    11211:("Memcached",      "in-memory cache; abused for huge reflection attacks", True),
    27017:("MongoDB",        "database server; should only listen on localhost", True),
    3000: ("Dev server",     "Node/React/Next.js dev servers default to this", False),
    5000: ("Dev server",     "Flask and other frameworks default to this", False),
    8000: ("Dev server",     "Django and Python dev servers default to this", False),
}

# Addresses that mean "only this machine" vs "the whole network can knock".
LOCALHOST_ADDRESSES = {"127.0.0.1", "::1"}
WILDCARD_ADDRESSES = {"0.0.0.0", "::"}

# ---------------------------------------------------------------------------
# Sample data for --demo: rows exactly like Linux /proc/net/tcp, /proc/net/tcp6
# and /proc/net/udp rows. Fields: sl, local_address(hex ip:hex port),
# rem_address, st, ... For TCP, st == 0A means LISTENING. UDP has no listen
# state: st == 07 means the socket is open and waiting for datagrams.
# ---------------------------------------------------------------------------
SAMPLE_PROC_LINES = [
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
    "   0: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0",
    "   1: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0",
    "   2: 0100007F:0B54 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0",
    "   3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 100 0 0 10 0",
    # 0100007F = 127.0.0.1 (hex, reversed), 1F40 = 8000, 01BB = 443,
    # 0B54 = 2900, 00000000:1F90 = 0.0.0.0:8080 (open to the whole network!)
]
SAMPLE_PROC_TCP6_LINES = [
    "  sl  local_address                         remote_address                        st",
    "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12349 1 0000000000000000 100 0 0 10 0",
    # ::1 (hex, per-word reversed) on port 0016 = 22 (SSH, localhost-only)
]
SAMPLE_PROC_UDP_LINES = [
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
    "   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 12350 1 0000000000000000 100 0 0 10 0",
    # 127.0.0.1:53 (DNS over UDP) — state 07 means "open for datagrams"
]


def hex_port_to_int(hex_port):
    """Convert a hex port string like '1F40' into the number 8000."""
    return int(hex_port, 16)


def hex_ip_to_str(hex_ip):
    """
    Convert a hex IP from /proc/net/* into a readable address.
    IPv4 (8 hex chars) is stored little-endian: '0100007F' -> '127.0.0.1'.
    IPv6 (32 hex chars) is stored as four little-endian 32-bit words:
    '00000000000000000000000001000000' -> '::1'. We reverse the bytes
    inside each 4-byte word, then let inet_ntop do the formatting.
    Raises ValueError on malformed input, so a bad row is skipped, not fatal.
    """
    raw = bytes.fromhex(hex_ip)
    if len(raw) == 4:
        return ".".join(str(b) for b in reversed(raw))
    if len(raw) == 16:
        fixed = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, fixed)
    raise ValueError(f"unexpected address length: {hex_ip!r}")


def parse_proc_net(lines, protocol, listen_state):
    """
    Read /proc/net/{tcp,tcp6,udp,udp6}-style lines and return a list of
    listener dicts for every socket in the listening state
    (TCP '0A', UDP '07'). Malformed rows are skipped with a warning count.
    """
    listeners = []
    skipped = 0
    for line in lines[1:]:  # first line is the header row
        parts = line.split()
        if len(parts) < 10:
            skipped += 1
            continue
        local_address, state = parts[1], parts[3]
        if state != listen_state:  # only keep sockets that are listening
            continue
        try:
            hex_ip, hex_port = local_address.split(":")
            address = hex_ip_to_str(hex_ip)
            port = hex_port_to_int(hex_port)
            inode = int(parts[9])
        except (ValueError, IndexError):
            skipped += 1
            continue
        listeners.append({"protocol": protocol, "address": address,
                          "port": port, "inode": inode, "owner": "?"})
    return listeners, skipped


def find_owning_process(linux_inode, verbose):
    """
    On Linux, the inode column links a socket to a process.
    Walk /proc/<pid>/fd looking for 'socket:[inode]'. Read-only.
    """
    if not verbose or linux_inode == 0:
        return "?"
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except (PermissionError, FileNotFoundError):
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target == f"socket:[{linux_inode}]":
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        return f"{f.read().strip()} (pid {pid})"
                except OSError:
                    return f"pid {pid}"
    return "?"


def collect_listeners(demo, verbose):
    """
    Inventory this machine's listeners:
      1. Linux: parse /proc/net/tcp, tcp6, udp and udp6 (the real data).
      2. Anywhere else: probe common ports on 127.0.0.1 (localhost only).
    Both stay on your own machine — nothing touches the network.
    Returns (listeners, skipped_rows).
    """
    if demo:
        listeners, skipped = parse_proc_net(SAMPLE_PROC_LINES, "TCP", "0A")
        extra, more = parse_proc_net(SAMPLE_PROC_TCP6_LINES, "TCP", "0A")
        listeners += extra
        skipped += more
        extra, more = parse_proc_net(SAMPLE_PROC_UDP_LINES, "UDP", "07")
        listeners += extra
        skipped += more
        return listeners, skipped

    listeners = []
    skipped = 0
    # (path, protocol, listen-state) — TCP listens at 0A, UDP sits at 07.
    for path, protocol, state in (("/proc/net/tcp", "TCP", "0A"),
                                  ("/proc/net/tcp6", "TCP", "0A"),
                                  ("/proc/net/udp", "UDP", "07"),
                                  ("/proc/net/udp6", "UDP", "07")):
        try:
            with open(path) as f:
                lines = f.readlines()
        except FileNotFoundError:
            continue
        except PermissionError:
            print(f"[warning] cannot read {path} (permission denied) — "
                  "run as your own user or with sudo to see everything.",
                  file=sys.stderr)
            continue
        found, bad = parse_proc_net(lines, protocol, state)
        listeners += found
        skipped += bad

    if listeners:
        for item in listeners:
            item["owner"] = find_owning_process(item["inode"], verbose)
        return listeners, skipped

    # Fallback for macOS/Windows: check common ports on localhost only.
    print("[info] /proc/net/* not found — probing localhost instead "
          "(127.0.0.1 only, nothing remote).")
    for port in sorted(KNOWN_SERVICES):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                listeners.append({"protocol": "TCP", "address": "127.0.0.1",
                                  "port": port, "inode": 0, "owner": "?"})
        except OSError as exc:
            print(f"[warning] could not probe port {port}: {exc}",
                  file=sys.stderr)
        finally:
            s.close()
    return listeners, skipped


def describe(port):
    """Return (name, note, risky) for a port, or a generic label if unknown."""
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    return ("unknown service", "no common service registered here — worth a look", True)


def is_exposed(address):
    """True when a listener faces the whole network (0.0.0.0 or ::)."""
    return address in WILDCARD_ADDRESSES


def listener_key(item):
    """The identity of a listener, used for --save/--compare baselines."""
    return (item["protocol"], item["address"], item["port"])


def save_baseline(listeners, path):
    """Write the current listener set to a JSON file for later comparison."""
    data = [{"protocol": p, "address": a, "port": n}
            for p, a, n in sorted(listener_key(i) for i in listeners)]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[info] baseline saved: {len(data)} listeners -> {path}")


def load_baseline(path):
    """Load a baseline file, or exit 2 with a friendly message if unusable."""
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[error] baseline file not found: {path}\n"
              "        Run with --save first to create one.", file=sys.stderr)
        sys.exit(2)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[error] cannot read baseline file {path}: {exc}",
              file=sys.stderr)
        sys.exit(2)
    try:
        return {(item["protocol"], item["address"], item["port"])
                for item in data}
    except (KeyError, TypeError):
        print(f"[error] baseline file {path} is not in the expected format "
              "(a JSON list of {protocol, address, port}).", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(
        description="Inventory of TCP + UDP listeners on THIS machine (read-only).")
    parser.add_argument("--demo", action="store_true",
                        help="run on built-in sample data")
    parser.add_argument("--verbose", action="store_true",
                        help="also show the owning process (Linux only)")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON instead of a table")
    parser.add_argument("--risky-only", action="store_true",
                        help="only show risky, unknown or exposed listeners")
    parser.add_argument("--port", type=int, default=None, metavar="N",
                        help="only show listeners on port N (1-65535)")
    parser.add_argument("--save", metavar="FILE",
                        help="save the current listeners as a baseline JSON file")
    parser.add_argument("--compare", metavar="FILE",
                        help="compare against a saved baseline and flag NEW/GONE")
    args = parser.parse_args()

    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    listeners, skipped = collect_listeners(args.demo, args.verbose)

    if args.port is not None:
        listeners = [i for i in listeners if i["port"] == args.port]
    if args.risky_only:
        listeners = [i for i in listeners
                     if describe(i["port"])[2] or is_exposed(i["address"])]

    # Deduplicate (same socket can appear twice via tcp + tcp6) and sort.
    seen = {}
    for item in listeners:
        seen.setdefault(listener_key(item), item)
    listeners = sorted(seen.values(),
                       key=lambda x: (x["port"], x["protocol"], x["address"]))

    if args.save:
        save_baseline(listeners, args.save)

    changes = {"new": [], "gone": []}
    if args.compare:
        baseline = load_baseline(args.compare)
        now = {listener_key(i) for i in listeners}
        changes["new"] = sorted(now - baseline)
        changes["gone"] = sorted(baseline - now)

    if not listeners and not changes["new"] and not changes["gone"]:
        print("No TCP/UDP listeners found on this machine. Nice and quiet.")
        return 0

    # Enrich every listener with its service description + exposure flag.
    for item in listeners:
        name, note, risky = describe(item["port"])
        item["service"], item["note"] = name, note
        item["risky"] = risky
        item["exposed"] = is_exposed(item["address"])
        item.pop("inode", None)

    risky_count = sum(1 for i in listeners if i["risky"])
    exposed_count = sum(1 for i in listeners if i["exposed"])

    if args.json:
        print(json.dumps({"listeners": listeners,
                          "changes": {"new": [list(k) for k in changes["new"]],
                                      "gone": [list(k) for k in changes["gone"]]},
                          "totals": {"listeners": len(listeners),
                                     "risky_or_unknown": risky_count,
                                     "exposed": exposed_count}},
                         indent=2))
    else:
        print(f"\n{'PROTO':<6}{'PORT':<7}{'LISTENING ON':<16}{'SERVICE':<17}"
              f"{'OWNER':<22}NOTES")
        print("-" * 112)
        for item in listeners:
            flags = ""
            if item["risky"]:
                flags += " [!]"
            if item["exposed"]:
                flags += " [EXPOSED — anyone on the network can reach it]"
            print(f"{item['protocol']:<6}{item['port']:<7}{item['address']:<16}"
                  f"{item['service']:<17}{item['owner']:<22}"
                  f"{item['note']}{flags}")
        print("-" * 112)
        print(f"Total listening ports: {len(listeners)} "
              f"({sum(1 for i in listeners if i['protocol'] == 'TCP')} TCP, "
              f"{sum(1 for i in listeners if i['protocol'] == 'UDP')} UDP)")
        print(f"Flagged as risky/unknown: {risky_count}")
        print(f"Exposed to the whole network: {exposed_count}")
        if changes["new"]:
            print("\nNEW since baseline:")
            for proto, addr, port in changes["new"]:
                print(f"  + {proto} {addr}:{port} — a door opened since the last check")
        if changes["gone"]:
            print("\nGONE since baseline:")
            for proto, addr, port in changes["gone"]:
                print(f"  - {proto} {addr}:{port} — a door closed since the last check")
        if skipped:
            print(f"\n[info] skipped {skipped} malformed socket-table row(s).")
        print("\nSOC takeaway: your attack surface is the sum of these doors. "
              "A listener you can't explain is your first lead —\n"
              "figure out what it is, then decide whether it should be listening at all.")

    # Exit 1 when something deserves a look, so scripts and cron jobs can react.
    if risky_count or exposed_count or changes["new"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
