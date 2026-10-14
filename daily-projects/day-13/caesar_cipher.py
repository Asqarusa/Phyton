#!/usr/bin/env python3
"""
caesar_cipher.py — Caesar cipher encrypt/decrypt + a tiny frequency-analysis
"breaker" to show why weak ciphers fail.

SOC angle: analysts constantly meet encrypted or obfuscated blobs
(base64 strings, weirdly shifted text in logs, config secrets). Knowing what
a substitution cipher LOOKS like — and how trivially it breaks — is crypto
basics every defender should feel in their hands.

Pure stdlib. Offline. Educational only.
"""

import string

ALPHABET = string.ascii_uppercase  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def shift_letter(char: str, shift: int) -> str:
    """Shift one letter by `shift` positions, wrapping around the alphabet.
    Non-letters (spaces, digits, punctuation) pass through untouched."""
    if char not in ALPHABET:
        return char
    position = ALPHABET.index(char)
    new_position = (position + shift) % 26  # % 26 wraps Z back to A
    return ALPHABET[new_position]


def caesar(text: str, shift: int) -> str:
    """Apply a Caesar shift to a whole string. Positive shift = encrypt,
    negative shift (or 26 - shift) = decrypt."""
    return "".join(shift_letter(ch, shift) for ch in text.upper())


def score_english(text: str) -> int:
    """Rough 'does this look like English?' score: count how many of a small
    list of very common English words appear. The right decryption key will
    almost always score highest."""
    common_words = {
        "THE", "AND", "FOR", "WITH", "THIS", "THAT", "FROM", "HAVE",
        "ARE", "WAS", "WERE", "YOU", "YOUR", "NOT", "BUT", "ALL",
        "CAN", "OUR", "SECRET", "ATTACK", "SERVER", "ALERT",
    }
    words = text.split()
    return sum(1 for w in words if w in common_words)


def break_caesar(ciphertext: str) -> None:
    """Brute-force all 25 possible shifts and show which one most likely
    reveals the original message. There are only 25 keys, so a computer
    tries every one in milliseconds."""
    print(f"\nTrying all 25 possible keys on: {ciphertext!r}\n")
    candidates = [(key, caesar(ciphertext, -key)) for key in range(1, 26)]
    best_key, best_text = max(candidates, key=lambda pair: score_english(pair[1]))
    for key, candidate in candidates:
        marker = "  <-- best guess" if key == best_key else ""
        print(f"  key {key:2d}: {candidate}{marker}")
    print(f"\nMost likely key: {best_key}  ->  {best_text!r}")


def demo() -> None:
    """Built-in demo so the script is interesting with zero arguments."""
    message = "ATTACK AT DAWN"
    shift = 3
    encrypted = caesar(message, shift)
    print(f"Original message : {message}")
    print(f"Encrypted (key={shift}) : {encrypted}")
    print(f"Decrypted back   : {caesar(encrypted, -shift)}")
    # Now show the cracker recovering the message from ciphertext alone:
    break_caesar(encrypted)
    print("\nSOC takeaway: 25 keys is nothing. If your 'encryption' has fewer")
    print("possible keys than a combination lock, attackers don't need your")
    print("key -- they can just try them all. That's why we use AES, not Caesar.")


def main() -> None:
    import sys

    if len(sys.argv) == 1:
        demo()
        return

    command = sys.argv[1].lower()
    if command in ("encrypt", "e") and len(sys.argv) == 4:
        print(caesar(sys.argv[2], int(sys.argv[3])))
    elif command in ("decrypt", "d") and len(sys.argv) == 4:
        print(caesar(sys.argv[2], -int(sys.argv[3])))
    elif command in ("break", "b") and len(sys.argv) == 3:
        break_caesar(sys.argv[2])
    else:
        print("Usage:")
        print("  python3 caesar_cipher.py                    # run the built-in demo")
        print("  python3 caesar_cipher.py encrypt TEXT SHIFT # encrypt")
        print("  python3 caesar_cipher.py decrypt TEXT SHIFT # decrypt")
        print('  python3 caesar_cipher.py break "CIPHERTEXT"  # brute-force all keys')


if __name__ == "__main__":
    main()
