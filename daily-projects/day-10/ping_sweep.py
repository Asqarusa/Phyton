#!/usr/bin/env python3
"""
ping_sweep.py — Day 10 of my daily security projects (networking theme).

Finds which devices are alive on YOUR OWN network by "knocking on every
door": it sends one ping to each address in a small network range and
reports which ones answer.

SAFE BY DEFAULT:
  - Only private / loopback networks are allowed
    (your home network like 192.168.1.0/24, or 127.0.0.0/8).
    Anything public (like 8.8.8.8) is REFUSED on purpose.
  - Ranges bigger than a /24 (more than ~254 addresses) are refused,
    so you can't accidentally point this at a huge network.
  - One ping packet per address, 1-second timeout each.

Usage:
    python3 ping_sweep.py                 # safe demo: sweeps 127.0.0.0/30
    python3 ping_sweep.py --demo          # same as above
    python3 ping_sweep.py 192.168.1.0/24  # your home network (example)

Only run this against networks you own.
"""

import ipaddress   # built-in module for working with IP addresses & networks
import platform    # lets us detect Windows vs Linux/macOS for ping flags
import socket      # for reverse-DNS lookups (IP -> hostname)
import subprocess # for running the system's `ping` command
import sys         # for reading command-line arguments and exiting
import time       # for timing how long the sweep takes
from concurrent.futures import ThreadPoolExecutor  # runs many pings at once


# --- safety rules -----------------------------------------------------------
MAX_HOSTS = 254          # refuse networks bigger than a /24
PING_TIMEOUT_S = 1       # wait at most 1 second for each reply


def is_allowed(network):
    """Return True only if EVERY address in `network` is private or loopback."""
    for addr in network.hosts():
        # is_private covers 10.x, 172.16.x, 192.168.x (RFC 1918)
        # is_loopback covers 127.x (your own machine)
        if not (addr.is_private or addr.is_loopback):
            return False
    return True


def parse_target(user_input):
    """
    Turn the user's text into a safe ipaddress network object,
    or raise a friendly error explaining why it's not allowed.
    """
    try:
        # strict=False lets people type "192.168.1.5/24" and still get the /24
        network = ipaddress.ip_network(user_input, strict=False)
    except ValueError:
        raise ValueError(f"'{user_input}' is not a valid network like 192.168.1.0/24.")

    if network.version != 4:
        raise ValueError("This tool only works with IPv4 (like 192.168.1.0/24).")

    if network.num_addresses - 2 > MAX_HOSTS:   # minus network & broadcast addr
        raise ValueError(
            f"{user_input} is bigger than a /24 ({network.num_addresses - 2} hosts). "
            "Keeping it small on purpose — sweep a smaller range."
        )

    if not is_allowed(network):
        raise ValueError(
            f"{user_input} is not a private/loopback network. "
            "Only your own private networks (10.x, 172.16.x, 192.168.x) or "
            "127.0.0.0/8 are allowed. Public addresses are refused."
        )

    return network


def ping_once(ip):
    """
    Send ONE ping to `ip`. Return the round-trip time in ms if it answers,
    or None if it doesn't (host down, or blocked by firewall).
    """
    # ping flags differ per OS: "-c1 -W1" on Linux/macOS, "-n 1 -w 1000" on Windows
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(PING_TIMEOUT_S), str(ip)]

    try:
        # capture_output hides ping's own text; we only care about success/failure
        result = subprocess.run(cmd, capture_output=True, timeout=PING_TIMEOUT_S + 2)
        if result.returncode == 0:
            return parse_rtt(result.stdout.decode(errors="ignore"))
        return None
    except Exception:
        return None  # timeout, missing ping binary, etc. -> treat as no answer


def parse_rtt(ping_text):
    """Pull the 'time=X ms' number out of ping's output (Linux/macOS format)."""
    for token in ping_text.replace("=", " ").split():
        if token.endswith("ms"):
            try:
                return float(token.replace("ms", ""))
            except ValueError:
                pass
    return None


def reverse_name(ip):
    """Try to turn an IP into a hostname (like 'router.local'). None if unknown."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return None


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "--demo"

    if arg in ("--demo", "-d", "demo"):
        # 127.0.0.1–127.0.0.2: always safe, always "yours", usually answers.
        target = "127.0.0.0/30"
        print("(demo mode — your own loopback network; "
              "pass your network like 192.168.1.0/24 to scan your LAN)\n")
    else:
        target = arg

    try:
        network = parse_target(target)
    except ValueError as e:
        print(f"Not allowed: {e}")
        sys.exit(1)

    hosts = list(network.hosts())  # all usable addresses, e.g. .1 to .254
    print(f"Sweeping {network} — knocking on {len(hosts)} doors...\n")

    alive = []                      # (ip, rtt_ms, hostname) tuples
    started = time.time()

    # Threads let many pings be "in flight" at once, so 254 hosts take
    # seconds instead of minutes. 50 workers is plenty for a home LAN.
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = pool.map(ping_once, hosts)

    for ip, rtt in zip(hosts, results):
        if rtt is not None:         # it answered!
            name = reverse_name(ip)
            alive.append((ip, rtt, name))
            line = f"  [alive] {ip}  ({rtt:.1f} ms)"
            if name:
                line += f"  -> {name}"
            print(line)

    elapsed = time.time() - started
    print(f"\nDone in {elapsed:.1f}s: {len(alive)} of {len(hosts)} hosts answered.")

    if not alive:
        print("Tip: some devices ignore pings (firewalls) — 'no answer' is not "
              "proof a device isn't there.")


if __name__ == "__main__":
    main()
