#!/usr/bin/env python3
"""
caesar_cipher.py — Caesar cipher encrypt/decrypt + a frequency-analysis
"breaker" to show why weak ciphers fail.

SOC angle: analysts constantly meet encrypted or obfuscated blobs
(base64 strings, weirdly shifted text in logs, config secrets). Knowing what
a substitution cipher LOOKS like — and how trivially it breaks — is crypto
basics every defender should feel in their hands.

Pure stdlib. Offline. Educational only.

What's new (2026-11-03 improvement pass):
  * Proper argparse CLI: --encrypt / --decrypt / --break, --shift, --text,
    --file, --json, --demo, --examples.
  * Case-preserving shifts: "Attack" now encrypts to "Dwwdfn", not "DWWDFN".
  * Smarter breaker: scores candidates with English letter-frequency
    (chi-squared) plus a common-word bonus, so it cracks short messages
    the old word-list-only scorer missed.
  * --file mode: encrypt/decrypt/break a whole text file.
  * --json output for piping results into other tools.
  * Friendly errors: bad shift, missing file, or empty input now explain
    the problem and exit with code 2 instead of crashing.
"""

import argparse
import json
import string
import sys

ALPHABET = string.ascii_uppercase  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# How often each letter appears in normal English (percent). Real language
# has a fingerprint: E shows up ~12% of the time, Z almost never. The
# breaker compares each candidate decryption against this fingerprint.
ENGLISH_FREQUENCY = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70, "F": 2.23,
    "G": 2.02, "H": 6.09, "I": 6.97, "J": 0.15, "K": 0.77, "L": 4.03,
    "M": 2.41, "N": 6.75, "O": 7.51, "P": 1.93, "Q": 0.10, "R": 5.99,
    "S": 6.33, "T": 9.06, "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15,
    "Y": 1.97, "Z": 0.07,
}

COMMON_WORDS = {
    # The 60 most common English words, plus a few SOC/demo favourites.
    "THE", "AND", "FOR", "WITH", "THIS", "THAT", "FROM", "HAVE",
    "ARE", "WAS", "WERE", "YOU", "YOUR", "NOT", "BUT", "ALL",
    "CAN", "OUR", "SECRET", "ATTACK", "SERVER", "ALERT",
    "HELLO", "WORLD", "GOOD", "MORNING", "MEET", "NOON", "QUICK",
    "BROWN", "FOX", "LAZY", "DOG", "PASSWORD", "LOGIN", "USER",
    "ADMIN", "DATA", "FILE", "SYSTEM", "NETWORK", "SECURITY",
    "WILL", "WOULD", "THERE", "THEIR", "WHAT", "WHEN", "WHICH",
    "ABOUT", "INTO", "THROUGH", "AFTER", "BEFORE", "PEOPLE",
    "BEEN", "MORE", "TIME", "VERY", "JUST", "KNOW", "TAKE",
    "SEE", "HIM", "HER", "HIS", "THEY", "THEM", "THEN", "THAN",
    "OVER", "UNDER", "ONLY", "SOME", "LIKE", "INTO", "BACK",
}


def die(message: str) -> None:
    """Print a friendly error and exit with code 2 (bad usage)."""
    print(f"Error: {message}", file=sys.stderr)
    print("Tip: run with --help to see the options.", file=sys.stderr)
    sys.exit(2)


def check_shift(shift: int) -> int:
    """A Caesar key only makes sense from 1 to 25 (0 = no change,
    26 = a full loop back to the same text)."""
    if not 1 <= shift <= 25:
        die(f"shift must be between 1 and 25 (you gave {shift}).")
    return shift


def shift_letter(char: str, shift: int) -> str:
    """Shift one letter by `shift` positions, wrapping around the alphabet.
    Uppercase stays uppercase, lowercase stays lowercase; spaces, digits
    and punctuation pass through untouched."""
    if char.isupper() and char in ALPHABET:
        position = ALPHABET.index(char)
        return ALPHABET[(position + shift) % 26]  # % 26 wraps Z back to A
    if char.islower() and char.upper() in ALPHABET:
        position = ALPHABET.index(char.upper())
        return ALPHABET[(position + shift) % 26].lower()
    return char


def caesar(text: str, shift: int) -> str:
    """Apply a Caesar shift to a whole string. Positive shift = encrypt,
    negative shift (or 26 - shift) = decrypt."""
    return "".join(shift_letter(ch, shift) for ch in text)


def score_english(text: str) -> float:
    """Score how much `text` looks like English. Lower is better.

    Two signals combined:
      * Letter frequency: compare the text's letter counts to normal
        English with a chi-squared test (small = close to English).
      * Common words: each familiar word found subtracts a bonus.
    The correct key usually wins on both signals at once, even for
    short messages where the word list alone finds nothing.
    """
    letters = [ch for ch in text.upper() if ch in ALPHABET]
    if not letters:
        return float("inf")  # no letters at all: can't be English
    total = len(letters)
    chi_squared = 0.0
    for letter, expected_percent in ENGLISH_FREQUENCY.items():
        observed = letters.count(letter)
        expected = total * expected_percent / 100
        chi_squared += (observed - expected) ** 2 / expected
    word_bonus = sum(1 for w in text.upper().split() if w in COMMON_WORDS)
    return chi_squared - 15 * word_bonus


def break_caesar(ciphertext: str) -> list:
    """Try all 25 possible keys and return every candidate, best first.
    Each entry is (key, plaintext, score) — lower score = more English-like.
    There are only 25 keys, so a computer tries every one in milliseconds."""
    candidates = [
        (key, caesar(ciphertext, -key), score_english(caesar(ciphertext, -key)))
        for key in range(1, 26)
    ]
    candidates.sort(key=lambda item: item[2])
    return candidates


def print_break(ciphertext: str, as_json: bool = False) -> None:
    """Show the breaker results, either as a readable table or JSON."""
    candidates = break_caesar(ciphertext)
    best_key, best_text, _best_score = candidates[0]
    if as_json:
        print(json.dumps({
            "ciphertext": ciphertext,
            "best_key": best_key,
            "best_plaintext": best_text,
            "candidates": [
                {"key": key, "plaintext": text, "score": round(score, 2)}
                for key, text, score in candidates
            ],
        }, indent=2))
        return
    print(f"\nTrying all 25 possible keys on: {ciphertext!r}\n")
    for key, candidate, _score in candidates:
        marker = "  <-- best guess" if key == best_key else ""
        print(f"  key {key:2d}: {candidate}{marker}")
    print(f"\nMost likely key: {best_key}  ->  {best_text!r}")


def read_input(args: argparse.Namespace) -> str:
    """Get the text to work on: --text, a --file, or a positional argument."""
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as handle:
                text = handle.read()
        except FileNotFoundError:
            die(f"no such file: {args.file!r}. Check the path and try again.")
        except IsADirectoryError:
            die(f"{args.file!r} is a directory, not a text file.")
        except UnicodeDecodeError:
            die(f"{args.file!r} doesn't look like a text file (not UTF-8).")
        if not text.strip():
            die(f"{args.file!r} is empty — nothing to work on.")
        return text
    if args.text is not None:
        if not args.text.strip():
            die("the text you gave is empty — nothing to work on.")
        return args.text
    if args.positional:
        return args.positional
    return ""


def demo() -> None:
    """Built-in demo so the script is interesting with zero arguments."""
    message = "Attack at dawn"
    shift = 3
    encrypted = caesar(message, shift)
    print(f"Original message : {message}")
    print(f"Encrypted (key={shift}) : {encrypted}")
    print(f"Decrypted back   : {caesar(encrypted, -shift)}")
    # Now show the cracker recovering the message from ciphertext alone:
    print_break(encrypted)
    print("\nSecond example — ROT13 (key 13, the classic 'spoiler tag' cipher):")
    spoiler = "The password is hunter2"
    print(f"  {spoiler!r} -> {caesar(spoiler, 13)!r}")
    print("\nSOC takeaway: 25 keys is nothing. If your 'encryption' has fewer")
    print("possible keys than a combination lock, attackers don't need your")
    print("key -- they can just try them all. That's why we use AES, not Caesar.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Caesar cipher: encrypt, decrypt, and break weak ciphers. "
                    "Educational only — never use this to protect real secrets.",
        epilog="Examples:\n"
               "  python3 caesar_cipher.py --encrypt --text 'Meet at noon' --shift 5\n"
               "  python3 caesar_cipher.py --decrypt --text 'Rjjy fy stts' --shift 5\n"
               "  python3 caesar_cipher.py --break --text 'Dwwdfn dw gdzq'\n"
               "  python3 caesar_cipher.py --encrypt --file note.txt --shift 13\n"
               "  python3 caesar_cipher.py --break --text 'Dwwdfn dw gdzq' --json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--encrypt", "-e", action="store_true",
                       help="encrypt the text with --shift")
    group.add_argument("--decrypt", "-d", action="store_true",
                       help="decrypt the text with --shift")
    group.add_argument("--break", "-b", dest="break_mode", action="store_true",
                       help="brute-force all 25 keys and show the best guess")
    group.add_argument("--demo", action="store_true",
                       help="run the built-in demo (default with no arguments)")
    parser.add_argument("--text", "-t", default=None,
                        help="the text to encrypt, decrypt, or break")
    parser.add_argument("--file", "-f", default=None,
                        help="read the text from a file instead of --text")
    parser.add_argument("--shift", "-s", type=int, default=3,
                        help="the key: how many letters to shift (1-25, default 3)")
    parser.add_argument("--json", "-j", action="store_true",
                        help="print the result as JSON (handy for other tools)")
    parser.add_argument("positional", nargs="?", default=None,
                        help="shorthand: the text to encrypt/decrypt/break")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.demo or (not any([args.encrypt, args.decrypt, args.break_mode])
                     and args.text is None and args.file is None
                     and args.positional is None):
        demo()
        return

    if args.break_mode:
        text = read_input(args)
        print_break(text, as_json=args.json)
        return

    if not args.encrypt and not args.decrypt:
        # A bare text with no mode: break it, same as the old positional
        # "break" behaviour, instead of failing silently.
        if args.positional or args.text:
            print_break(read_input(args), as_json=args.json)
            return
        parser.print_help()
        return

    check_shift(args.shift)
    text = read_input(args)
    result = caesar(text, args.shift if args.encrypt else -args.shift)
    if args.json:
        print(json.dumps({
            "mode": "encrypt" if args.encrypt else "decrypt",
            "shift": args.shift,
            "input": text,
            "output": result,
        }, indent=2))
    else:
        print(result)


if __name__ == "__main__":
    main()
