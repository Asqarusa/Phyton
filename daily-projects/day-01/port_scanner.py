"""
port_scanner.py — Project 2: Simple Port Scanner
-------------------------------------------------
What it does (plain English):
    Checks which "doors" (ports) are open on a computer. Every computer
    has 65,535 numbered ports — open ones are how services like websites
    or file sharing talk to the network. Network and security folks scan
    ports to make sure no unexpected doors are open for attackers.

    SAFETY: this script only scans YOUR OWN computer (127.0.0.1) by
    default. Never scan systems you don't own or don't have written
    permission to test — that's illegal in most places.

How to run:
    python3 port_scanner.py
"""

import socket

TARGET = "127.0.0.1"  # your own computer — do not change to someone else's
TIMEOUT_SECONDS = 0.5

# A small list of well-known ports and what normally lives behind them
COMMON_PORTS = {
    21: "FTP (file transfers)",
    22: "SSH (secure remote login)",
    23: "Telnet (old, insecure remote login)",
    25: "SMTP (sending email)",
    53: "DNS (turns names into addresses)",
    80: "HTTP (websites, unencrypted)",
    110: "POP3 (receiving email)",
    443: "HTTPS (websites, encrypted)",
    3306: "MySQL (databases)",
    3389: "RDP (Windows remote desktop)",
}


def is_port_open(host, port):
    """Try to open a connection to one port. True = someone answered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)  # don't wait forever on closed ports
    try:
        sock.connect((host, port))  # raises an error if the door is shut
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()


def main():
    print(f"Scanning {TARGET} (your own computer)...\n")
    open_ports = []
    for port, description in COMMON_PORTS.items():
        if is_port_open(TARGET, port):
            open_ports.append(port)
            print(f"  [OPEN]   Port {port:>5} — {description}")
        else:
            print(f"  [closed] Port {port:>5}")

    print()
    if open_ports:
        print(f"Done. {len(open_ports)} open port(s) found: {open_ports}")
        print("Tip: every open port should have a reason to be open.")
    else:
        print("Done. No open ports found in the scanned list.")


if __name__ == "__main__":
    main()
