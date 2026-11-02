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
  - One ping packet per address, short timeout each.

WHAT'S NEW (improved version):
  - Proper command-line flags: --network, --timeout, --workers,
    --json (machine-readable output), --no-reverse, --quiet.
  - Response-time stats: fastest / slowest / average reply.
  - --save + --compare: save a sweep to a file, then compare a later
    sweep against it — NEW devices and devices that VANISHED are
    flagged. That's exactly how a SOC analyst spots a rogue device.
  - Friendlier errors with exit code 2 for bad input, and a clear
    message if the `ping` program itself is missing.

Usage:
    python3 ping_sweep.py                          # safe demo: sweeps 127.0.0.0/30
    python3 ping_sweep.py --demo                   # same as above
    python3 ping_sweep.py 192.168.1.0/24           # your home network (example)
    python3 ping_sweep.py 192.168.1.0/24 --json    # machine-readable output
    python3 ping_sweep.py 192.168.1.0/24 --save baseline.json
    python3 ping_sweep.py 192.168.1.0/24 --compare baseline.json

Only run this against networks you own.
"""

import argparse  # friendly command-line flags (replaces hand-rolled argv parsing)
import ipaddress  # built-in module for working with IP addresses & networks
import json       # for --json output and --save/--compare files
import platform   # lets us detect Windows vs Linux/macOS for ping flags
import shutil     # to check whether the `ping` program exists at all
import socket     # for reverse-DNS lookups (IP -> hostname)
import subprocess  # for running the system's `ping` command
import sys         # for reading command-line arguments and exiting
import time        # for timing how long the sweep takes
from concurrent.futures import ThreadPoolExecutor  # runs many pings at once


# --- safety rules -----------------------------------------------------------
MAX_HOSTS = 254          # refuse networks bigger than a /24
DEFAULT_TIMEOUT_S = 1    # wait at most 1 second for each reply
DEFAULT_WORKERS = 50     # how many pings fly at once


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


def ping_once(ip, timeout):
    """
    Send ONE ping to `ip`. Return the round-trip time in ms if it answers,
    or None if it doesn't (host down, or blocked by firewall).
    """
    # ping flags differ per OS: "-c1 -W1" on Linux/macOS, "-n 1 -w 1000" on Windows
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), str(ip)]

    try:
        # capture_output hides ping's own text; we only care about success/failure
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        if result.returncode == 0:
            return parse_rtt(result.stdout.decode(errors="ignore"))
        return None
    except FileNotFoundError:
        # The `ping` program itself is missing — handled once in main().
        raise
    except Exception:
        return None  # timeout, etc. -> treat as no answer


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


def load_baseline(path):
    """Load a previous --save file. Returns a dict of ip -> hostname, or None."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        hosts = data.get("alive", [])
        return {str(h["ip"]): h.get("hostname") for h in hosts}
    except FileNotFoundError:
        print(f"Error: baseline file '{path}' not found. "
              "Run a sweep with --save first.", file=sys.stderr)
        sys.exit(2)
    except (json.JSONDecodeError, KeyError, AttributeError):
        print(f"Error: '{path}' is not a valid sweep file "
              "(run with --save to create one).", file=sys.stderr)
        sys.exit(2)


def print_comparison(alive, baseline):
    """Compare this sweep with a saved baseline and flag what changed."""
    now = {str(ip): name for ip, _rtt, name in alive}
    new = sorted(set(now) - set(baseline))
    gone = sorted(set(baseline) - set(now))

    print("\n--- Compared with baseline ---")
    if new:
        print(f"  [NEW] {len(new)} device(s) appeared since the baseline:")
        for ip in new:
            line = f"        {ip}"
            if now[ip]:
                line += f"  -> {now[ip]}"
            print(line)
        print("        New device on your network? Check whether you recognize it.")
    else:
        print("  [ok] No new devices since the baseline.")
    if gone:
        print(f"  [GONE] {len(gone)} device(s) from the baseline did not answer:")
        for ip in gone:
            line = f"        {ip}"
            if baseline[ip]:
                line += f"  -> {baseline[ip]}"
            print(line)
        print("        (Could be switched off — or worth a second look.)")
    else:
        print("  [ok] Every baseline device still answered.")


def build_parser():
    """All the command-line flags, in one place, with plain-English help."""
    parser = argparse.ArgumentParser(
        description="Ping sweep: knock on every door in YOUR OWN small network "
                    "and list who answers. Private/loopback networks only.")
    parser.add_argument("network", nargs="?", default=None,
                        help="network to sweep, e.g. 192.168.1.0/24 "
                             "(default: safe demo on 127.0.0.0/30)")
    parser.add_argument("--demo", action="store_true",
                        help="sweep the safe loopback demo network (127.0.0.0/30)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help=f"seconds to wait per ping (default: {DEFAULT_TIMEOUT_S})")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"how many pings fly at once (default: {DEFAULT_WORKERS})")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON instead of the human-readable table")
    parser.add_argument("--no-reverse", action="store_true",
                        help="skip hostname lookups (faster, less chatty)")
    parser.add_argument("--quiet", action="store_true",
                        help="only print the final summary line")
    parser.add_argument("--save", metavar="FILE",
                        help="save the alive hosts to a JSON file for later comparison")
    parser.add_argument("--compare", metavar="FILE",
                        help="compare this sweep against a saved --save file and "
                             "flag new or vanished devices")
    return parser


def main():
    args = build_parser().parse_args()

    # --- validate the flags before doing any work --------------------------
    if args.timeout <= 0:
        print("Error: --timeout must be more than 0 seconds.", file=sys.stderr)
        sys.exit(2)
    if args.workers < 1:
        print("Error: --workers must be at least 1.", file=sys.stderr)
        sys.exit(2)
    if args.save and args.compare and args.save == args.compare:
        print("Error: --save and --compare point at the same file — "
              "use a different file for the new save.", file=sys.stderr)
        sys.exit(2)

    # The `ping` program has to exist, or nothing here can work.
    if shutil.which("ping") is None:
        print("Error: the 'ping' program was not found on this machine. "
              "Install it (e.g. iputils-ping on Linux) and try again.",
              file=sys.stderr)
        sys.exit(2)

    if args.demo or args.network is None:
        # 127.0.0.1–127.0.0.2: always safe, always "yours", usually answers.
        target = "127.0.0.0/30"
        if not args.json and not args.quiet:
            print("(demo mode — your own loopback network; "
                  "pass your network like 192.168.1.0/24 to scan your LAN)\n")
    else:
        target = args.network

    try:
        network = parse_target(target)
    except ValueError as e:
        print(f"Not allowed: {e}", file=sys.stderr)
        sys.exit(2)

    baseline = load_baseline(args.compare) if args.compare else None

    hosts = list(network.hosts())  # all usable addresses, e.g. .1 to .254
    if not args.json and not args.quiet:
        print(f"Sweeping {network} — knocking on {len(hosts)} doors...\n")

    alive = []                      # (ip, rtt_ms, hostname) tuples
    started = time.time()

    # Threads let many pings be "in flight" at once, so 254 hosts take
    # seconds instead of minutes.
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = pool.map(lambda ip: ping_once(ip, args.timeout), hosts)
    except FileNotFoundError:
        print("Error: the 'ping' program disappeared mid-sweep. "
              "Try again — or check your system PATH.", file=sys.stderr)
        sys.exit(2)

    for ip, rtt in zip(hosts, results):
        if rtt is not None:         # it answered!
            name = None if args.no_reverse else reverse_name(ip)
            alive.append((ip, rtt, name))

    elapsed = time.time() - started
    rtts = [rtt for _ip, rtt, _name in alive if rtt is not None]

    if args.save:
        # Save only what a later --compare needs: IP + hostname.
        data = {"network": str(network),
                "alive": [{"ip": str(ip), "hostname": name}
                          for ip, _rtt, name in alive]}
        try:
            with open(args.save, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            if not args.json and not args.quiet:
                print(f"Saved {len(alive)} alive host(s) to {args.save}\n")
        except OSError as e:
            print(f"Error: could not write '{args.save}': {e}", file=sys.stderr)
            sys.exit(2)

    if args.json:
        # Machine-readable: one JSON object, easy to pipe into other tools.
        print(json.dumps({
            "network": str(network),
            "hosts_checked": len(hosts),
            "alive": [{"ip": str(ip), "rtt_ms": rtt, "hostname": name}
                      for ip, rtt, name in alive],
            "elapsed_s": round(elapsed, 1),
        }, indent=2))
    else:
        if not args.quiet:
            for ip, rtt, name in alive:
                line = f"  [alive] {ip}"
                if rtt is not None:
                    line += f"  ({rtt:.1f} ms)"
                if name:
                    line += f"  -> {name}"
                print(line)

        print(f"\nDone in {elapsed:.1f}s: {len(alive)} of {len(hosts)} hosts answered.")
        if rtts:
            print(f"Reply times: fastest {min(rtts):.1f} ms, "
                  f"slowest {max(rtts):.1f} ms, "
                  f"average {sum(rtts) / len(rtts):.1f} ms.")
        if not alive:
            print("Tip: some devices ignore pings (firewalls) — 'no answer' is not "
                  "proof a device isn't there.")

    if baseline is not None:
        print_comparison(alive, baseline)


if __name__ == "__main__":
    main()
