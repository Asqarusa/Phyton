#!/usr/bin/env python3
"""
password_strength.py — Day 11: Password Strength Meter (SOC/security-hygiene basics)

What it does:
    Scores a password on a 0-100 scale and explains WHY, in plain English.
    It looks at four things SOC analysts and security teams care about:
      1. Length        — the single biggest factor
      2. Character variety — uppercase, lowercase, digits, symbols
      3. Uniqueness  — repeated characters and keyboard patterns weaken it
      4. Dictionary risk — passwords that look like common words/phrases

Safety note:
    This script NEVER sends your password anywhere. It runs 100% locally.
    Never type a real password into any tool you don't fully trust — and
    definitely never paste a real password into a web form.
    When demoing, use example passwords like the ones in demo_passwords.txt.
"""

import math
import re

# A tiny built-in blocklist of the most-cracked passwords of all time.
# Real password-cracking tools (like Hydra or John the Ripper) try these FIRST,
# which is why a "strong-looking" password like "P@ssw0rd!" still falls fast.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "letmein", "welcome", "monkey", "dragon", "football",
    "p@ssw0rd", "passw0rd", "password1", "qwerty123", "admin",
}


def character_pool_size(password: str) -> int:
    """Count how many different character TYPES the password uses."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26          # lowercase letters
    if re.search(r"[A-Z]", password):
        pool += 26          # uppercase letters
    if re.search(r"[0-9]", password):
        pool += 10          # digits
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32          # symbols (approx. printable set)
    return pool


def estimate_entropy_bits(password: str) -> float:
    """
    Entropy = the "search space" an attacker must brute-force, in bits.
    Think of bits like locks on a door: every extra bit doubles the work.
    Formula: bits = length * log2(pool_size).
    """
    pool = character_pool_size(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def looks_like_common_password(password: str) -> bool:
    """Check the password against the blocklist (case-insensitive, simple leetspeak stripped)."""
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return True
    # Strip simple leetspeak (0->o, 3->e, 1->l, !->i) and check again,
    # e.g. "P@ssw0rd!" becomes "password" after stripping.
    stripped = lowered.replace("@", "a").replace("0", "o").replace("3", "e") \
                      .replace("1", "l").replace("!", "i").replace("$", "s")
    return stripped in COMMON_PASSWORDS


def has_repetition_or_pattern(password: str) -> str | None:
    """
    Spot the two weakest human habits:
      - the same character 3+ times in a row ("aaa")
      - keyboard walks like "qwerty" or "12345"
    Returns a description of the problem, or None if clean.
    """
    if re.search(r"(.)\1{2,}", password):
        return "repeats the same character 3+ times in a row"
    lowered = password.lower()
    for walk in ("qwerty", "asdf", "zxcv", "12345", "abcde", "54321"):
        if walk in lowered:
            return f"contains a keyboard walk ('{walk}')"
    return None


def score_password(password: str) -> dict:
    """Score a password 0-100 and return a full breakdown dictionary."""
    feedback = []

    # --- 1. Length: worth up to 40 points ---
    length = len(password)
    length_score = min(40, length * 3)      # 13+ chars earns the full 40
    if length < 8:
        feedback.append(f"Too short ({length} chars) — aim for 12+ characters.")
    elif length < 12:
        feedback.append(f"Okay length ({length} chars) — 12+ is much stronger.")
    else:
        feedback.append(f"Good length ({length} chars).")

    # --- 2. Variety: up to 30 points (10 per character type, capped) ---
    types_used = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[^a-zA-Z0-9]", password)),
    ])
    variety_score = types_used * 7.5       # 4 types = full 30
    if types_used < 3:
        feedback.append(f"Only {types_used} character type(s) used — mix upper, lower, digits, symbols.")
    else:
        feedback.append(f"Good mix: {types_used} character types.")

    # --- 3. Uniqueness penalties: up to -25 ---
    penalty = 0
    pattern = has_repetition_or_pattern(password)
    if pattern:
        penalty += 15
        feedback.append(f"Weak pattern: {pattern}.")
    if re.search(r"^(.)\1+$", password):   # e.g. "aaaaaaaa"
        penalty += 10
        feedback.append("The whole password is one repeated character.")

    # --- 4. Dictionary risk: instant cap ---
    if looks_like_common_password(password):
        penalty += 30
        feedback.append("This is (close to) one of the most-cracked passwords ever — attackers try these first.")

    entropy = estimate_entropy_bits(password)

    # --- Final score and verdict ---
    score = max(0, min(100, round(length_score + variety_score - penalty)))
    if score >= 80:
        verdict = "STRONG"
    elif score >= 60:
        verdict = "DECENT"
    elif score >= 40:
        verdict = "WEAK"
    else:
        verdict = "VERY WEAK"

    return {
        "score": score, "verdict": verdict, "entropy_bits": round(entropy, 1),
        "length": length, "types_used": types_used, "feedback": feedback,
    }


def print_report(password: str, label: str) -> None:
    """Print a friendly score report for one password."""
    result = score_password(password)
    # Mask the password in output so demos don't leak it on screen captures.
    masked = password[0] + "*" * max(0, len(password) - 2) + password[-1] if len(password) > 1 else "*"
    print(f"Password: {masked}   ({label})")
    print(f"  Score:   {result['score']}/100  →  {result['verdict']}")
    print(f"  Entropy: {result['entropy_bits']} bits "
          f"(≈ 2^{result['entropy_bits']:.0f} guesses to brute-force)")
    for tip in result["feedback"]:
        print(f"  • {tip}")
    print()


def main() -> None:
    print("=" * 60)
    print("PASSWORD STRENGTH METER — Day 11")
    print("Runs 100% offline. Use example passwords, not real ones!")
    print("=" * 60 + "\n")

    try:
        with open("demo_passwords.txt", encoding="utf-8") as f:
            samples = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("demo_passwords.txt not found — using built-in examples.")
        samples = ["password", "Tr0ub4dor&3", "correct-horse-battery-staple"]

    for i, pw in enumerate(samples, 1):
        print_report(pw, f"example #{i}")

    print("TIP: length beats cleverness. A long passphrase of 4+ random")
    print("words outlives a short 'clever' one like P@ssw0rd! every time.")


if __name__ == "__main__":
    main()
