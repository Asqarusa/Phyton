#!/usr/bin/env python3
"""
Day 25 — Active Connection Watcher (Improved)
=============================================
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

What's new in this version (2026-11-22):
  * --json output for piping into other tools, --quiet (flagged only),
    --all (show non-ESTABLISHED sockets too) and --port N (one port only).
  * --file mode: analyse a saved /proc/net/tcp-style text file, so a
    connection list captured on another machine can be reviewed offline.
  * --save / --compare baseline snapshots: spot NEW and GONE remote
    hosts compared with the last run, the way a SOC watches for change.
  * A group's verdict is now the WORST verdict of any connection in the
    group (before, only the first connection decided it, so a suspicious
    second connection to the same host could hide behind an ordinary one).
  * Malformed rows are counted and reported instead of silently skipped,
    unencrypted services (plain HTTP, FTP, Telnet...) get a plain-English
    warning, and the summary adds a per-zone breakdown, the chattiest
    host and the busiest remote port.
  * Exit codes: 0 = nothing flagged, 1 = at least one [CHECK],
    2 = usage / input error (bad port, missing file, bad baseline).

Usage:
    python3 active_connection_watcher.py            # live view (Linux)
    python3 active_connection_watcher.py --demo    # sample data, any OS
    python3 active_connection_watcher.py --verbose # add per-connection detail
    python3 active_connection_watcher.py --json    # machine-readable output
    python3 active_connection_watcher.py --file sample_connections.txt
    python3 active_connection_watcher.py --save baseline.json
    python3 active_connection_watcher.py --compare baseline.json
"""

import argparse
import ipaddress
import json
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
    445: "SMB file sharing", 465: "SMTPS email", 500: "IKE VPN",
    514: "Syslog", 587: "SMTP submit", 636: "LDAPS", 993: "IMAPS email",
    995: "POP3S email", 1194: "OpenVPN", 1433: "MS SQL Server",
    1521: "Oracle DB", 1701: "L2TP VPN", 1723: "PPTP VPN",
    1900: "SSDP discovery", 2375: "Docker API (unencrypted!)",
    3306: "MySQL", 3389: "RDP remote desktop", 4500: "NAT-T VPN",
    5353: "mDNS discovery", 5355: "LLMNR discovery", 5432: "PostgreSQL",
    5900: "VNC remote desktop", 5985: "WinRM", 6379: "Redis",
    6443: "Kubernetes API", 6667: "IRC chat", 8000: "Alt HTTP",
    8080: "Alt HTTP / proxy", 8443: "Alt HTTPS", 8888: "Alt HTTP",
    9000: "Alt HTTP", 9090: "Alt HTTP / admin", 9200: "Elasticsearch",
    10250: "Kubernetes kubelet", 11211: "Memcached", 27017: "MongoDB",
    1337: "often used by attack tools",
    2323: "Telnet alt (often abused)",
    4444: "often used by attack tools (Metasploit default)",
    5555: "often used by attack tools / Android ADB",
    7547: "TR-069 (often abused)",
    8291: "Winbox (often abused)",
    31337: "often used by attack tools (\"elite\")",
}

# Ports that are FAMOUSLY abused by malware / scanners. A connection to one
# of these from your machine deserves a closer look (still just a lead!).
SUSPICIOUS_PORTS = {23, 2323, 4444, 5555, 6667, 1337, 31337, 7547,
                    8291, 12345, 27374}

# Ports whose traffic is sent in the clear (no encryption). Fine for a
# web page, risky for anything private — worth a plain-English warning.
PLAINTEXT_PORTS = {21, 23, 69, 80, 110, 143, 161, 514, 2375}

# In /proc/net/tcp the connection "state" column is hex. 0A = LISTEN,
# 01 = ESTABLISHED (an active conversation). We only want the conversations
# by default; --all shows the other states too.
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
    # NEW in this version: outbound to port 31337 ("elite") — another
    # famously abused port, so the demo now shows two teaching moments.
    "   5: 0100007F:C006 636433C6:7A69 01 00000000:00000000 00:00000000 00000000  1000        0 12350 1 0000000000000000 100 0 0 10 0",
]
# One IPv6 sample: DNS-over-IPv6 to a documentation address (2001:db8::/32).
# Each 8-hex-char word is little-endian, exactly like /proc/net/tcp6.
DEMO_LINES_V6 = [
    "   0: 00000000000000000000000001000000:C101 B80D0120000000000000000001000000:0035 01 00000000:00000000 00:00000000 00000000  1000        0 22345 1 0000000000000000 100 0 0 10 0",
]

# Worst verdict wins when a group holds several connections.
VERDICT_RANK = {"OK": 0, "SAMPLE": 1, "CHECK": 2}


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
    """Turn raw /proc/net/tcp lines into (connections, skipped) — skipped
    counts malformed rows, which used to vanish silently. Bad input never
    crashes the tool; it is counted and reported instead."""
    conns, skipped = [], 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("sl"):
            continue  # header row
        parts = line.split()
        if len(parts) < 10:
            skipped += 1
            continue
        local_ip, local_port = split_address(parts[1], v6)
        remote_ip, remote_port = split_address(parts[2], v6)
        if local_ip is None or remote_ip is None:
            skipped += 1
            continue
        state = parts[3].upper()
        uid = parts[7] if len(parts) > 7 else "?"
        conns.append({
            "local_ip": local_ip, "local_port": local_port,
            "remote_ip": remote_ip, "remote_port": remote_port,
            "state": state, "uid": uid, "v6": v6,
        })
    return conns, skipped


def parse_mixed_lines(lines):
    """Parse a saved file that may mix IPv4 and IPv6 rows (as --file
    accepts). Each row's address length decides: 32 hex chars = IPv6,
    anything shorter = IPv4. Returns (connections, skipped)."""
    conns, skipped = [], 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("sl"):
            continue
        parts = stripped.split()
        if len(parts) < 3 or ":" not in parts[1]:
            skipped += 1
            continue
        hex_ip = parts[1].rsplit(":", 1)[0]
        v6 = len(hex_ip) == 32
        chunk, chunk_skipped = parse_proc_lines([line], v6=v6)
        conns.extend(chunk)
        skipped += chunk_skipped
    return conns, skipped


def read_proc_files():
    """Read /proc/net/tcp and tcp6. Returns (connections, warnings, skipped)."""
    all_conns, warnings, skipped = [], [], 0
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path, "r") as fh:
                conns, bad = parse_proc_lines(fh.readlines(), v6)
                all_conns.extend(conns)
                skipped += bad
        except FileNotFoundError:
            warnings.append(f"{path} not found (not a Linux host?)")
        except PermissionError:
            warnings.append(f"cannot read {path} (permission denied)")
        except OSError as exc:
            warnings.append(f"error reading {path}: {exc}")
    return all_conns, warnings, skipped


def read_saved_file(path):
    """Read a saved /proc-style file. Raises OSError for the caller to
    turn into a friendly exit-2 message."""
    with open(path, "r", errors="replace") as fh:
        return parse_mixed_lines(fh.readlines())


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
        reasons.append("outbound to the public internet")

    if rport in SUSPICIOUS_PORTS:
        verdict = "CHECK"
        reasons.append(f"remote port {rport} is famously abused by attack tools")
    elif service == "unknown service" and zone == "public internet":
        verdict = "CHECK"
        reasons.append(f"uncommon remote port {rport} — worth identifying the program")

    if rport in PLAINTEXT_PORTS:
        reasons.append(
            f"unencrypted service (port {rport}) — fine for public data, "
            f"risky for anything private")

    return verdict, reasons


def build_groups(conns, demo=False, include_all=False):
    """Group connections by remote host. A group's verdict is the WORST
    verdict of any connection in it (fix: the old code only looked at
    the first connection, so a suspicious second connection could hide).
    Returns (groups, summary) where each group carries its connections,
    verdict, merged reasons, zone and state names."""
    selected = conns if include_all else [c for c in conns if c["state"] == "01"]
    other = len(conns) - len(selected)

    by_remote = {}
    for c in selected:
        by_remote.setdefault(c["remote_ip"], []).append(c)

    groups = []
    checks = 0
    for remote_ip, group in sorted(by_remote.items()):
        verdicts, reasons = [], []
        for c in group:
            verdict, conn_reasons = assess(c, demo=demo)
            c["verdict"] = verdict
            verdicts.append(verdict)
            for reason in conn_reasons:
                if reason not in reasons:
                    reasons.append(reason)
        verdict = max(verdicts, key=lambda v: VERDICT_RANK[v])
        if verdict == "CHECK":
            checks += 1
        groups.append({
            "remote_ip": remote_ip, "connections": group,
            "verdict": verdict, "reasons": reasons,
            "zone": group[0]["zone"],
            "states": sorted({STATE_NAMES.get(c["state"], c["state"])
                              for c in group}),
        })

    # Summary extras: zone breakdown, chattiest host, busiest remote port.
    by_zone = {}
    for c in selected:
        by_zone[c.get("zone", classify_ip(c["remote_ip"]))] = \
            by_zone.get(c.get("zone", classify_ip(c["remote_ip"])), 0) + 1
    by_port = {}
    for c in selected:
        by_port[c["remote_port"]] = by_port.get(c["remote_port"], 0) + 1
    summary = {
        "connections": len(selected),
        "unique_remote_hosts": len(by_remote),
        "flagged": checks,
        "skipped_non_established": other,
        "by_zone": by_zone,
        "chattiest_host": max(by_remote, key=lambda h: len(by_remote[h]))
            if by_remote else None,
        "busiest_remote_port": max(by_port, key=by_port.get) if by_port else None,
    }
    return groups, summary


def print_report(groups, summary, verbose=False, demo=False, quiet=False,
                 skipped=0, baseline_note=None):
    print("=" * 70)
    print("ACTIVE CONNECTION WATCHER — who is this machine talking to?")
    if demo:
        print("(demo mode: sample data, documentation-range addresses)")
    print("=" * 70)
    if skipped:
        print(f"({skipped} malformed row(s) skipped — see --file input or "
              f"/proc data.)")

    if not groups:
        print("\nNo ESTABLISHED connections right now. Quiet machine.")
        if summary["skipped_non_established"]:
            print(f"({summary['skipped_non_established']} non-established "
                  f"sockets seen and skipped.)")
    else:
        print(f"\n{summary['connections']} active conversation(s) with "
              f"{summary['unique_remote_hosts']} remote host(s):\n")
        for group in groups:
            if quiet and group["verdict"] != "CHECK":
                continue
            mark = {"OK": "[ok]  ", "CHECK": "[CHECK]",
                    "SAMPLE": "[demo] "}[group["verdict"]]
            ports = ", ".join(
                f"{c['remote_port']} ({KNOWN_PORTS.get(c['remote_port'], '?')})"
                + (" [IPv6]" if c["v6"] else "")
                for c in group["connections"]
            )
            print(f"{mark} {group['remote_ip']}  [{group['zone']}]")
            print(f"         remote port(s): {ports}")
            if group["states"] != ["ESTABLISHED"]:
                print(f"         state(s): {', '.join(group['states'])}")
            print(f"         why: {'; '.join(group['reasons'])}")
            if verbose:
                for c in group["connections"]:
                    print(f"           local {c['local_ip']}:{c['local_port']} "
                          f"(uid {c['uid']})")
            print()

    if baseline_note:
        print(baseline_note)
        print()

    # ---- SOC triage summary ----
    print("-" * 70)
    print("SOC TRIAGE SUMMARY")
    print(f"  Active conversations : {summary['connections']}")
    print(f"  Unique remote hosts  : {summary['unique_remote_hosts']}")
    print(f"  Flagged for review   : {summary['flagged']}")
    if summary["by_zone"]:
        zones = ", ".join(f"{zone}: {n}" for zone, n in
                          sorted(summary["by_zone"].items()))
        print(f"  By zone              : {zones}")
    if summary["chattiest_host"]:
        print(f"  Chattiest host       : {summary['chattiest_host']}")
    if summary["busiest_remote_port"] is not None:
        port = summary["busiest_remote_port"]
        print(f"  Busiest remote port  : {port} "
              f"({KNOWN_PORTS.get(port, 'unknown service')})")
    if summary["flagged"]:
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


def report_as_json(groups, summary, demo=False, skipped=0, baseline=None):
    """Machine-readable version of the same report (same facts, no prose)."""
    payload = {
        "demo": demo,
        "malformed_rows_skipped": skipped,
        "summary": summary,
        "hosts": [
            {
                "remote_ip": g["remote_ip"],
                "zone": g["zone"],
                "verdict": g["verdict"],
                "reasons": g["reasons"],
                "states": g["states"],
                "connections": [
                    {"local": f"{c['local_ip']}:{c['local_port']}",
                     "remote_port": c["remote_port"],
                     "service": c.get("service", "unknown service"),
                     "uid": c["uid"], "ipv6": c["v6"]}
                    for c in g["connections"]
                ],
            }
            for g in groups
        ],
    }
    if baseline is not None:
        payload["baseline"] = baseline
    print(json.dumps(payload, indent=2, sort_keys=True))


# ---------------------------------------------------------------------------
# Baselines: remember today's remote hosts, spot what changed next time
# ---------------------------------------------------------------------------
def connection_keys(conns):
    """The identity of a connection for baseline purposes: remote host + port."""
    return sorted({f"{c['remote_ip']}:{c['remote_port']}" for c in conns})


def load_baseline(path):
    """Read a baseline file. Returns the saved key list, or raises
    ValueError with a plain-English reason the caller reports as exit 2."""
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise ValueError(f"baseline file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline file is not valid JSON: {path} ({exc})")
    except OSError as exc:
        raise ValueError(f"cannot read baseline file {path}: {exc}")
    if isinstance(data, dict):
        keys = data.get("connections")
    else:
        keys = data
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        raise ValueError(
            f"baseline file {path} must hold a JSON list of "
            f'"host:port" strings (or an object with a "connections" list)')
    return keys


def save_baseline(path, keys):
    try:
        with open(path, "w") as fh:
            json.dump({"connections": keys}, fh, indent=2)
            fh.write("\n")
    except OSError as exc:
        raise ValueError(f"cannot write baseline file {path}: {exc}")


def compare_keys(saved, current):
    saved_set, current_set = set(saved), set(current)
    return sorted(current_set - saved_set), sorted(saved_set - current_set)


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    return 2


def port_number(text):
    """argparse type: a port must be 1-65535, or the run stops with exit 2
    and a friendly message instead of a traceback."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port must be a number, got {text!r}")
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError(
            f"port must be 1-65535, got {value}")
    return value


# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="List this machine's active TCP conversations in plain English."
    )
    parser.add_argument("--demo", action="store_true",
                        help="use built-in sample data (works on any OS)")
    parser.add_argument("--verbose", action="store_true",
                        help="show the local socket and uid behind each connection")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of the text report")
    parser.add_argument("--quiet", action="store_true",
                        help="text mode only: show flagged hosts and the summary")
    parser.add_argument("--all", action="store_true",
                        help="include non-ESTABLISHED sockets (LISTEN, TIME_WAIT, ...)")
    parser.add_argument("--port", type=port_number, metavar="N",
                        help="only show connections to remote port N (1-65535)")
    parser.add_argument("--file", metavar="PATH",
                        help="analyse a saved /proc/net/tcp-style text file "
                             "instead of the live system")
    parser.add_argument("--save", metavar="PATH",
                        help="save this run's remote host:port list as a "
                             "baseline JSON file")
    parser.add_argument("--compare", metavar="PATH",
                        help="compare this run with a saved baseline file "
                             "and report NEW / GONE hosts")
    args = parser.parse_args(argv)

    if args.demo and args.file:
        parser.error("--demo and --file cannot be used together")
    if args.json and args.quiet:
        parser.error("--json and --quiet cannot be used together")

    if args.demo:
        conns, skipped = parse_proc_lines(DEMO_LINES_V4, v6=False)
        more, more_skipped = parse_proc_lines(DEMO_LINES_V6, v6=True)
        conns += more
        skipped += more_skipped
        warnings = []
    elif args.file:
        try:
            conns, skipped = read_saved_file(args.file)
        except FileNotFoundError:
            return fail(f"file not found: {args.file} "
                        f"(check the path and try again)")
        except OSError as exc:
            return fail(f"cannot read {args.file}: {exc}")
        warnings = []
    else:
        conns, warnings, skipped = read_proc_files()

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not conns and warnings:
        print("\nNo connection data available on this system.", file=sys.stderr)
        print("Tip: run with --demo to see the tool work with sample data.",
              file=sys.stderr)
        return 1

    if args.port is not None:
        conns = [c for c in conns if c["remote_port"] == args.port]
        if not conns:
            print(f"No connections to remote port {args.port} right now.")
            return 0

    # Baseline handling is skipped in demo mode: sample hosts are not real,
    # so comparing them with a real baseline would only produce noise.
    baseline = None
    baseline_note = None
    current_keys = connection_keys(
        [c for c in conns if c["state"] == "01"])
    if not args.demo:
        if args.save:
            try:
                save_baseline(args.save, current_keys)
            except ValueError as exc:
                return fail(str(exc))
            baseline_note = (f"Baseline saved to {args.save} "
                             f"({len(current_keys)} remote host:port entries).")
        if args.compare:
            try:
                saved_keys = load_baseline(args.compare)
            except ValueError as exc:
                return fail(str(exc))
            new, gone = compare_keys(saved_keys, current_keys)
            baseline = {"new": new, "gone": gone,
                        "compared_with": args.compare}
            lines = [f"Baseline comparison vs {args.compare}:"]
            lines.append(f"  NEW since baseline : "
                         f"{', '.join(new) if new else 'none'}")
            lines.append(f"  GONE since baseline: "
                         f"{', '.join(gone) if gone else 'none'}")
            baseline_note = "\n".join(lines)
    elif args.save or args.compare:
        print("note: --save/--compare are ignored in --demo mode "
              "(sample hosts are not real).", file=sys.stderr)

    groups, summary = build_groups(conns, demo=args.demo,
                                   include_all=args.all)

    if args.json:
        report_as_json(groups, summary, demo=args.demo,
                       skipped=skipped, baseline=baseline)
    else:
        print_report(groups, summary, verbose=args.verbose, demo=args.demo,
                     quiet=args.quiet, skipped=skipped,
                     baseline_note=baseline_note)

    if args.demo:
        return 0
    return 1 if summary["flagged"] else 0


if __name__ == "__main__":
    sys.exit(main())
