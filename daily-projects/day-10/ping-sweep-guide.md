# Ping Sweep: Find Out Who's Home on Your Network

*Day 10 of my daily security projects — networking theme. Code: `ping_sweep.py`*

## The big idea (non-tech analogy first)

Imagine you just moved into an apartment building and want to know which units
are occupied. You could knock on every door: a knock answered = someone's home.
A knock with no answer = empty (or they just didn't open).

A **ping sweep** is exactly that for a computer network. A "ping" is a tiny
"are you there?" message. The script knocks on every address in your network
range and writes down who answered. Network admins do this to take inventory:
"we thought we had 12 devices on the office Wi-Fi — why are there 19?"

## What the script does

1. You give it a network, like `192.168.1.0/24` (your home Wi-Fi), or run it
   with no arguments for a safe built-in demo.
2. **Safety check first.** It refuses to run against public internet addresses
   (like Google's 8.8.8.8) and refuses ranges bigger than a /24 — so it can't
   be pointed at the open internet or used to scan a huge network.
3. It pings every usable address in the range — up to 254 "doors" — all at
   once, so it finishes in seconds instead of minutes.
4. For every host that answers, it shows the IP, how fast it replied, and —
   if possible — the device's hostname (like `router.local`).
5. It prints a summary: "14 of 254 hosts answered."

## How the code works, line by line (simple terms)

**Imports** — the script borrows tools from Python's built-in library:

- `ipaddress` — understands network notation like `192.168.1.0/24` and lists
  every address in it.
- `subprocess` — runs the computer's real `ping` program and reads the result.
- `concurrent.futures` / `ThreadPoolExecutor` — lets many pings fly at the
  same time instead of waiting for each one to finish before starting the next.
- `socket` — tries to turn an IP back into a human-readable hostname.
- `platform` — checks Windows vs. Linux/Mac so the right ping flags are used.

**`is_allowed(network)`** — the safety gate. Loops through every address and
returns `True` only if each one is *private* (10.x, 172.16.x, 192.168.x —
the ranges reserved for home/office networks) or *loopback* (127.x — your own
machine). One public address in the range = the whole sweep is refused.

**`parse_target(user_input)`** — takes your typed text and turns it into a
network object. `strict=False` means typing `192.168.1.5/24` still gives you
the whole /24 (nice for beginners who paste their own IP). It raises a
friendly error if the input isn't valid IPv4, is bigger than a /24, or isn't
private/loopback.

**`ping_once(ip)`** — sends exactly ONE ping with a 1-second timeout and
returns the response time in milliseconds, or `None` if nothing answered.
`capture_output=True` keeps ping's chatter hidden — we only care about
success or failure. Any exception (timeout, missing ping program) counts as
"no answer", not a crash.

**`parse_rtt(ping_text)`** — digs the `time=0.42 ms` number out of ping's
output text so we can display how fast each host replied.

**`reverse_name(ip)`** — asks "what's your name?" via reverse DNS. Wrapped in
a safety net: unknown hosts just return `None` instead of crashing.

**`main()`** — the flow:

1. No argument? Run the **demo**: sweeps `127.0.0.0/30` — your own machine's
   loopback, always safe, and 127.0.0.1 almost always answers.
2. Validate the target with `parse_target()` — exit with a clear message if
   it's not allowed.
3. List all host addresses, then ping them all in parallel with 50 worker
   threads.
4. Print each live host as it answers, then a final summary with timing.

## Key terms, translated

| Term | Plain English |
|---|---|
| Ping | A tiny "are you there?" network message; the reply time is measured |
| Ping sweep | Pinging every address in a range to see which are alive |
| CIDR / `/24` | Shorthand for a network's size: `/24` = 256 addresses (254 usable) |
| RFC 1918 private range | IP blocks reserved for inside networks (10.x, 172.16.x, 192.168.x) — never on the public internet |
| Loopback (127.0.0.1) | A special address that always means "this machine itself" |
| Latency / RTT | Round-trip time: how long the ping took to go and come back, in ms |
| Reverse DNS | Asking the network for a hostname from an IP — like reverse phone lookup |
| Thread pool | Running many small tasks at once instead of one after another |

## How to run it

```bash
# Safe demo (your own machine — nothing leaves your laptop)
python3 ping_sweep.py

# Your home network (example — use YOUR router's range, check your Wi-Fi settings)
python3 ping_sweep.py 192.168.1.0/24
```

What you'll see on a home network: your router, your phone, your laptop,
maybe a smart TV — everything that answered the knock.

⚠️ **Only scan networks you own.** Try a public address like `8.8.8.0/30`
and the script refuses — that refusal is a feature, not a bug.

## What to learn next

- **ARP vs ping:** devices can hide from ping behind a firewall but still show
  up in your machine's ARP table — try comparing the two.
- **Port scanning:** once you know *who's* home, the next question is *what
  doors are open* (see my Day 2 project — the port scanner).
- **nmap:** the professional tool that does ping sweeps, port scans, and OS
  detection in one package — this script is the "how does it actually work?"
  version.
- **Defensive use:** unexpected new devices on a sweep = a classic sign of an
  unauthorized device on the network — exactly the kind of thing a SOC analyst
  investigates.
