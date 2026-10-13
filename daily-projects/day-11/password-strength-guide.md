# Day 11: Password Strength Meter 🔐

## The big idea (a non-tech analogy)

Imagine a thief trying to guess your combination lock. A 3-digit lock has 1,000 possible combos — they'll crack it in an afternoon. A 12-digit lock with letters, numbers, and symbols has more combinations than there are grains of sand on Earth. That "number of possible combinations" is called **entropy**, and it's the core of password strength.

But here's the twist a SOC analyst learns fast: attackers don't guess randomly. They try the world's most-used passwords first ("password", "123456", "qwerty") — the digital equivalent of checking if your door key is under the welcome mat. A password that *looks* clever ("P@ssw0rd!") can be weak because thousands of other people had the same "clever" idea.

## What the script does

`password_strength.py` scores any password from 0–100 and explains **why**, checking four things security teams actually care about:

1. **Length** (up to 40 points) — the single biggest factor. 13+ characters earns full marks.
2. **Character variety** (up to 30 points) — mixing lowercase, UPPERCASE, digits, and symbols.
3. **Weak patterns** (penalties) — repeated characters ("aaa") and keyboard walks ("qwerty", "12345").
4. **Dictionary risk** (big penalty) — flags passwords matching the most-cracked passwords ever, including simple leetspeak tricks ("P@ssw0rd!" → "password").

It also estimates **entropy in bits** — roughly how many guesses a brute-force attack would need.

**Safety note:** the script runs 100% offline. Nothing is ever sent anywhere. And the demo file contains only fake example passwords — never put a real password in a file that goes to GitHub.

## How the code works (line by line, in simple terms)

- **`CHARACTER POOL` / `character_pool_size()`** — counts how many character types are used: 26 for lowercase, 26 for uppercase, 10 for digits, ~32 for symbols. Bigger pool = harder to guess.
- **`estimate_entropy_bits()`** — the math: `bits = length × log₂(pool)`. Each bit doubles the attacker's work. Think of bits as extra locks on the door.
- **`COMMON_PASSWORDS`** — a small blocklist of the most-cracked passwords of all time. Real cracking tools try these first.
- **`looks_like_common_password()`** — checks the blocklist, then strips simple leetspeak (`@`→`a`, `0`→`o`, `3`→`e`…) and checks again. That's how "P@ssw0rd!" gets caught.
- **`has_repetition_or_pattern()`** — uses a regex to spot the same character 3+ times in a row, and scans for keyboard walks like "qwerty".
- **`score_password()`** — adds up the points, subtracts penalties, and converts the score into a verdict: STRONG (80+), DECENT (60+), WEAK (40+), or VERY WEAK.
- **`print_report()`** — prints a friendly report, masking the password (first/last char only) so demos don't leak it on screen.

## Key terms translated

| Term | Plain English |
|---|---|
| Entropy (bits) | How big the guessing game is. 40 bits ≈ 1 trillion guesses. |
| Brute-force | Trying every possible combination until one works. |
| Dictionary attack | Trying a list of known-common passwords first — much faster than brute-force. |
| Leetspeak | Swapping letters for lookalike symbols (a→@, o→0). Attackers know this trick. |
| Keyboard walk | Passwords that follow key order on a keyboard: "qwerty", "12345". |

## How to run it

```bash
python3 password_strength.py
```

It reads the fake example passwords from `demo_passwords.txt` and scores each one. Want to score your own ideas? Add throwaway test strings to the file — never real passwords.

## What to learn next

- Try **zxcvbn** (Dropbox's real-world password estimator) to see how the pros model cracking time.
- Read about **salting and hashing** — why websites store password *hashes*, not passwords (ties into Day 09's hash identifier!).
- Learn how **MFA (multi-factor authentication)** makes even a weak password much harder to exploit.

## Sample output

```
Password: P******!   (example)
  Score:   63/100  →  DECENT
  Entropy: 72.1 bits (≈ 2^72 guesses to brute-force)
  • Okay length (11 chars) — 12+ is much stronger.
  • This is (close to) one of the most-cracked passwords ever — attackers try these first.

TIP: length beats cleverness. A long passphrase of 4+ random
words outlives a short 'clever' one like P@ssw0rd! every time.
```

*Day 11 of my daily cybersecurity learning series. Code: https://github.com/Asqarusa/Phyton/tree/main/daily-projects/day-11*
