# Banner Grabber — reading the nameplates on your own doors

**Day 20 · networking series · by Askarbek Akhrorov**
Code: `banner_grabber.py` (+ `sample_banners.txt`)

## What's new in this version (2026-11-12)

The first version just read banners and guessed the service. This version turns the tool into something a SOC analyst would actually run on a schedule:

- **Risk grades for every banner.** Each banner now gets a grade — LOW (a generic greeting that reveals almost nothing), MEDIUM (the software is named but no version is shown), or HIGH (an exact version is on show, so an attacker can look up exploits for it) — with a plain-English reason and one concrete hardening tip. Think of it like a health check: green, amber, red.
- **Known-bad version watch.** A small watchlist flags versions with a famous bad reputation by name — vsftpd 2.3.4 (which shipped with a backdoor), very old OpenSSH, and end-of-life Apache 2.2 — so they jump out instead of blending in.
- **Smarter version check.** The old version-spotter flagged `HTTP/1.1` as a software version; that was a false alarm, because 1.1 is the *protocol* version, not the software's. Fixed — only real software versions count now.
- **`--file` mode.** Analyse banners saved in a text file (`PORT | BANNER`, one per line) instead of the network — handy for banners captured somewhere else and pasted in.
- **`--json` mode.** Machine-readable output, so the results can feed a script or a SIEM instead of only a human's eyes.
- **`--save` / `--compare` baselines.** Snapshot your banners, then later compare: NEW, CHANGED and GONE banners are listed. A service quietly changing its banner is worth a look — it might be a patch, or it might be something else.
- **Friendlier errors and exit codes.** Bad ports, bad timeouts and missing files now explain the problem and exit with code 2 instead of crashing. Exit code 1 means "at least one HIGH-risk banner found" — the signal a scheduled script would watch for.
- **5 new sample banners** in `--demo` (Apache 2.2, nginx, old OpenSSH 7.4, vsftpd 2.3.4, ProFTPD) so the new grading and watchlist are visible without any network.

## The big idea (analogy first)

Last time we walked the hallway and found which doors were open — that was the port scanner. Today we *knock on each open door and read the nameplate*.

Almost every network service greets a new connection with a short message called a **banner**. It usually says what the service is and exactly which version: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`. Imagine every office door in a building had a little plaque reading "Door co. model 2017, lock serial 4482" — convenient for the maintenance crew, and equally convenient for a burglar who knows exactly which lock-picks fit model 2017.

That's the double edge of banners:
- **Defenders** use them to take inventory: what runs on my machine, and what needs patching?
- **Attackers** use them for the same reason: an exact version number tells them which known exploit to try.

This is why "version disclosure" — a service advertising its exact version — is treated as a misconfiguration in security hardening. One of the cheapest hardening wins there is: make the banner say less.

## What the script does

1. Connects to a list of common ports **on your own machine only** (127.0.0.1 — localhost; any other address is refused by design).
2. Reads the first ~1 KB the service sends — the banner — then politely hangs up.
3. Takes a best guess at which service it is (SSH server, web server, mail server…) from known banner fragments.
4. Flags banners that leak a version number, with the hardening reminder.
5. `--demo` mode replays real-world sample banners from `sample_banners.txt` with zero network traffic, so it works on any laptop — even one with nothing listening.

HTTP servers don't volunteer a banner, so for those the script sends a minimal `HEAD /` request to coax a reply, like saying "hello?" through a door that doesn't have a nameplate.

## How the code works (line by line, simple terms)

- **`DEFAULT_PORTS`** — the usual suspects: 21 (FTP), 22 (SSH), 25/110/143 (mail), 80/443 (web), 3306 (MySQL), 3389 (RDP), and friends.
- **`ALLOWED_TARGET = "127.0.0.1"`** — the safety lock. The whole script is built around this one constant: it can only ever knock on your own machine. Defensive education only.
- **`KNOWN_SIGNATURES`** — a cheat sheet: if the banner contains "SSH-" it's an SSH server; "+OK" means POP3-style mail; "vsftpd" is vsftpd FTP, and so on. This is fingerprinting, simplified.
- **`grab_banner(port, timeout)`** — opens a TCP connection (`socket.connect`), asks politely for up to 1024 bytes (`sock.recv`), decodes them into text, and closes the connection. If nothing answers (connection refused, timeout), it returns `None` — "no nameplate here" — which is a perfectly normal answer.
- **`VERSION_RE`** — a tiny pattern (`\d+\.\d+`) that spots things like `8.9` or `4.96`: evidence of version disclosure.
- **`demo_mode()`** — reads the sample file line by line, skipping comments, and runs the same guessing logic on it. Same brain, fake ears.
- **`main()`** — argument parsing (`--ports`, `--timeout`, `--demo`), then loops over the ports and prints a small report: banner, best guess, and the hardening tip where relevant.

## Key terms, translated

| Term | Plain English |
|---|---|
| Banner | The greeting text a service sends when you connect |
| Banner grabbing | Reading those greetings to identify services |
| Service fingerprinting | Figuring out *what* software is running from its behavior/text |
| Version disclosure | A banner that names the exact version — an attacker freebie |
| Localhost (127.0.0.1) | "This machine" — a network address that never leaves your laptop |
| TCP connect | The standard handshake any client does before talking |

## How to run it

```bash
cd daily-projects/day-20
python3 banner_grabber.py                 # knock on common ports on your own machine
python3 banner_grabber.py --ports 22,80   # only check these ports
python3 banner_grabber.py --demo          # sample banners, no network at all
python3 banner_grabber.py --demo --json   # sample banners as JSON
python3 banner_grabber.py --file sample_banners.txt   # analyse saved banners
python3 banner_grabber.py --save baseline.json        # snapshot today's banners
python3 banner_grabber.py --compare baseline.json     # spot what changed since
```

You'll need Python 3 (no extra libraries — this is standard-library-only code).

## What to learn next

- **Nmap's service detection** (`-sV`) does this same job at professional scale, with thousands of fingerprints.
- **Shodan** is essentially banner grabbing done for the entire internet — defenders use it to find *their own* exposed services, attackers use it to shop for targets.
- Try checking a real banner on your own machine (e.g. spin up `python3 -m http.server` and note how the `Server:` header answers), then look up how to suppress version info in a web server config — that config change is real hardening.
- Pair it with day-02's port scanner: first find the open doors, then read the nameplates. That two-step combo is the start of an asset inventory — the first thing any security team builds.
