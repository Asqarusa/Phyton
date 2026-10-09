"""
brute_force_detector.py — Project 1: SOC Log Analyzer
-----------------------------------------------------
What it does (plain English):
    Reads a server login log and finds IP addresses that failed to log in
    too many times. Lots of failed logins from one address usually means
    someone is guessing passwords automatically — this is called a
    "brute-force attack," and spotting it is a core SOC analyst skill.

How to run:
    python3 brute_force_detector.py
    (reads sample_auth.log in the same folder)

Try changing ALERT_THRESHOLD to see how the results change.
"""

import re
from collections import Counter

LOG_FILE = "sample_auth.log"
ALERT_THRESHOLD = 5  # flag any IP with this many failed logins (or more)


def find_failed_logins(log_file):
    """Pull every failed-login IP address out of the log file."""
    failed_ips = []
    # This pattern matches lines like:
    #   "Failed password for root from 185.220.101.4 port 51234"
    pattern = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)")
    with open(log_file) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                failed_ips.append(match.group(1))  # group(1) = the IP address
    return failed_ips


def main():
    failed_ips = find_failed_logins(LOG_FILE)

    print(f"Total failed login attempts in log: {len(failed_ips)}")
    print(f"Alert threshold: {ALERT_THRESHOLD} failures from one IP\n")

    counts = Counter(failed_ips)  # count failures per IP, e.g. {"1.2.3.4": 8}
    suspects = {ip: n for ip, n in counts.items() if n >= ALERT_THRESHOLD}

    if not suspects:
        print("No brute-force activity detected. All clear.")
        return

    print("POSSIBLE BRUTE-FORCE ATTACKS:")
    for ip, count in sorted(suspects.items(), key=lambda x: x[1], reverse=True):
        print(f"  ! {ip} — {count} failed logins  -> investigate / block this IP")


if __name__ == "__main__":
    main()
