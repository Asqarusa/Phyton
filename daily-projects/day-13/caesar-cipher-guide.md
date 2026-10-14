# Caesar Cipher: Crypto Basics for Defenders

**Day 13 — SOC analysis theme**
Code: `caesar_cipher.py` — run it with `python3 caesar_cipher.py`

## The big idea

Imagine you and a friend agree that every letter of the alphabet gets replaced
by the letter 3 spots later: A becomes D, B becomes E, … Z wraps back around
to C. You can now pass secret notes, and anyone who peeks just sees gibberish.

That is the Caesar cipher — named for Julius Caesar, who really used it for
military messages 2,000 years ago. It is the simplest form of encryption:
**substitution**, one letter swapped for another.

Here's why it matters to a security analyst today: you constantly run into
encoded or obfuscated text — weird strings in logs, base64 blobs in configs,
"mystery text" pasted into an alert. Understanding what a simple substitution
cipher *looks like*, and how trivially it breaks, trains the instinct for how
attackers hide things — and why weak "encryption" is no protection at all.

## What the script does

Three things, all in one file:

1. **Encrypt / decrypt** — shift any message by any key (1–25).
2. **Brute-force breaker** — given only ciphertext, try all 25 possible keys
   and show every candidate.
3. **Auto-detection** — score each candidate on "does this look like English?"
   using a tiny list of common English words, and highlight the best guess.

## How the code works (line by line, in plain terms)

- `shift_letter(char, shift)` — takes one letter, finds its position in the
  alphabet (A=0, B=1, … Z=25), adds the shift, and uses `% 26` (the remainder
  operator) to wrap around past Z. Letters shift; spaces and punctuation pass
  through untouched.
- `caesar(text, shift)` — runs `shift_letter` on every character and glues the
  results back together. A positive shift encrypts; a negative shift (or
  `26 − shift`) decrypts.
- `score_english(text)` — splits the candidate into words and counts how many
  are on a small list of common English words (THE, AND, ATTACK, SERVER…).
  The correct key makes real words appear, so it scores highest. This is the
  "frequency analysis" idea: languages have fingerprints.
- `break_caesar(ciphertext)` — loops key 1 through 25, decrypts with each, and
  prints all 25 guesses. There are only 25 keys — a computer checks every one
  in milliseconds.
- `demo()` — runs with no arguments: encrypts "ATTACK AT DAWN" with key 3,
  decrypts it back, then cracks it from ciphertext alone.

## Key terms translated

| Term | Plain English |
|---|---|
| Cipher | A recipe for scrambling a message |
| Key | The secret number that controls the recipe (here: how many letters to shift) |
| Plaintext | The original, readable message |
| Ciphertext | The scrambled output |
| Brute force | Trying every possible key until one works |
| Frequency analysis | Using the statistical fingerprints of a language to guess the key |

## How to run it

```bash
python3 caesar_cipher.py                       # built-in demo
python3 caesar_cipher.py encrypt "MEET AT NOON" 5
python3 caesar_cipher.py decrypt "RJJY FY STTS" 5
python3 caesar_cipher.py break "DWWDFN DW GDZQ"
```

No libraries to install — pure Python standard library, fully offline.

## What to learn next

- The Caesar cipher has only 25 keys. Modern encryption like AES-256 has more
  possible keys than there are atoms in the universe — that gap is what "real"
  encryption means.
- Try base64 next (`python3 -m base64`): attackers love it for hiding payloads
  in logs. It's an *encoding*, not encryption — anyone can decode it.
- In the SOC, whenever you see text that looks scrambled but isn't random,
  ask: is this just substitution? A quick brute-force check takes seconds.
