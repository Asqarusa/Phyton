# Your Laptop's Network ID Card — plain-English guide

*A tiny Python tool that shows your computer's network identity: hostname, local IP, MAC address, and public IP — and explains what each one means.*

---

## The big idea (the non-tech analogy first)

Think of your home network like an apartment building:

- **Your local IP** (like `192.168.1.42`) is your **apartment number**. It only makes sense *inside* the building. Every building reuses the same apartment numbers — your neighbor's building has a "unit 42" too.
- **Your public IP** (like `73.114.20.5`) is the building's **street address**. It's what the outside world sees. Every apartment in the building shares that one street address — the mailroom (your router) sorts out which package goes to which apartment.
- **Your MAC address** (like `02:42:ac:11:00:02`) is the **serial number engraved on your phone**. It never changes, no matter which building you move to.
- **Your hostname** is just the **nickname** you gave your computer, like writing your name on your lunchbox.

The mailroom trick has a real name: **NAT (Network Address Translation)**. Your router rewrites the "return address" on every packet leaving your home, then remembers which apartment asked, so replies find their way back.

## What the script does

`network_identity.py` asks your operating system four questions and prints the answers as an "ID card":

1. **Hostname** — `socket.gethostname()`
2. **Local IP** — the clever UDP trick (see below)
3. **MAC address** — `uuid.getnode()`, formatted into `xx:xx:xx:xx:xx:xx`
4. **Public IP** — one tiny HTTPS request to `api.ipify.org`, a service that just echoes your public IP back

Then it prints a short explainer: whether your local IP is private, and the SOC rule of thumb (below).

## How the code works, line by line (in simple terms)

**`get_hostname()`** — One line: ask the OS "what am I called?" Every computer has a name; this just reads it.

**`get_local_ip()`** — The sneaky-clever part. It opens a UDP "connection" to `8.8.8.8` (Google's DNS). Here's the trick: *UDP `connect()` doesn't send anything.* It just asks the OS, "if I *were* to send something there, which local address would you use?" The OS picks a route and tells us — and that address is our local IP. No packets leave the machine. We close the socket right after.

**`get_mac()`** — `uuid.getnode()` returns the network card's hardware address as one big number. The line with `>>` and `& 0xFF` is just slicing that number into six pairs of digits and gluing them with colons. Bit-shifting sounds scary; all it does is "cut the number into byte-sized pieces."

**`get_public_ip()`** — Makes one small web request to `https://api.ipify.org`, which responds with your public IP as plain text (like `104.29.194.33`). This is exactly what happens when you Google "what is my IP." It's wrapped in `try/except`: if you're offline, the tool says "unavailable" instead of crashing.

**`is_private()`** — Checks whether an IP starts with `10.`, `172.16.`–`172.31.`, or `192.168.` — the three address ranges reserved for private networks. These are the "apartment numbers" of the internet: they never appear on the public internet, so they're reusable in every home and office.

**`main()`** — Calls the four getters, prints the ID card, then prints the explainer bullets.

## Key terms, translated

| Term | Plain English |
|---|---|
| IP address | A computer's mailing address on a network |
| Private IP | An "apartment number" — works only inside your own network |
| Public IP | A "street address" — visible to the whole internet |
| NAT | The router's mailroom: translates between apartment numbers and the street address |
| MAC address | The network card's permanent serial number |
| Hostname | Your computer's nickname |
| SOC | Security Operations Center — the team watching for attacks |

## How to run it

```bash
python3 network_identity.py
```

No libraries to install — it uses only Python's standard library. Works on Windows, macOS, and Linux.

## Why a SOC analyst cares

When an analyst opens a firewall or proxy log, the screen is full of IP addresses. The very first triage question is always: **"Is this traffic mine, or is it someone else's?"** If you can't recognize your own machine's hostname and IPs, you can't tell your own shadow from an intruder. Knowing your network identity is the baseline everything else is measured against.

## What to learn next

1. **Run `ipconfig` (Windows) or `ip addr` (Linux/Mac)** and compare with the script's output — same numbers?
2. **Find your router's admin page** (usually `192.168.1.1`) and see the list of devices — those are all "apartments" in your building.
3. **Look up what an IPv6 address looks like** — the internet is slowly moving to much longer addresses.
4. **Next tool idea:** a script that lists every device currently on your Wi-Fi (an ARP scan) — the building's full tenant directory.
