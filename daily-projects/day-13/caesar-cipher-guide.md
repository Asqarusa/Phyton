# Caesar Cipher: Crypto Basics for Defenders

**Day 13 — SOC analysis theme**
Code: `caesar_cipher.py` — run it with `python3 caesar_cipher.py`

## What's new in this version (2026-11-03)

I went back to this project and gave it a proper upgrade — think of it like
trading a pocket calculator for a full toolbox:

- **It keeps your capital letters now.** The old version shouted everything
  in ALL CAPS. "Attack at dawn" used to come out as "DWWDFN DW GDZQ"; now it
  comes out as "Dwwdfn dw gdzq", exactly matching how you typed it.
- **A smarter code-breaker.** The old breaker only recognised a handful of
  common words, so short messages like "Hello world" stumped it. The new one
  also checks each guess against the *fingerprint* of English — how often
  each letter normally appears (E is common, Z is rare) — so it now cracks
  short messages too. Try `--break` on "Khoor zruog" and watch it find
  "Hello world".
- **A real command line.** No more memorising positional arguments:
  `--encrypt`, `--decrypt`, `--break`, `--shift`, `--text`, `--file`, and
  `--json` are all proper flags with `--help` to explain them.
- **Whole files, and machine-readable output.** Point it at a text file with
  `--file`, or add `--json` to get results another tool can read.
- **Friendlier mistakes.** A bad shift, a missing file, or empty input now
  explains the problem in plain English and exits cleanly instead of
  crashing with a traceback.

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

1. **Encrypt / decrypt** — shift any message by any key (1–25), keeping
   upper- and lowercase as you typed them.
2. **Brute-force breaker** — given only ciphertext, try all 25 possible keys
   and show every candidate, best first.
3. **Auto-detection** — score each candidate on "does this look like English?"
   using *two* signals: a list of common English words, and a comparison of
   the candidate's letter frequencies against normal English (a chi-squared
   test — the same "fingerprint" idea, just with numbers).

## How the code works (line by line, in plain terms)

- `shift_letter(char, shift)` — takes one letter, finds its position in the
  alphabet (A=0, B=1, … Z=25), adds the shift, and uses `% 26` (the remainder
  operator) to wrap around past Z. Uppercase stays uppercase, lowercase stays
  lowercase; spaces and punctuation pass through untouched.
- `caesar(text, shift)` — runs `shift_letter` on every character and glues the
  results back together. A positive shift encrypts; a negative shift (or
  `26 − shift`) decrypts.
- `score_english(text)` — two signals: a chi-squared comparison of the text's
  letter counts against normal English frequencies (E ~12.7%, Z ~0.07%),
  minus a bonus for every common English word found. The correct key makes
  real words appear *and* matches English's letter fingerprint, so it scores
  lowest. This is the "frequency analysis" idea: languages have fingerprints.
- `break_caesar(ciphertext)` — loops key 1 through 25, decrypts with each,
  scores them, and returns every candidate sorted best first. There are only
  25 keys — a computer checks every one in milliseconds.
- `demo()` — runs with no arguments: encrypts "Attack at dawn" with key 3,
  decrypts it back, cracks it from ciphertext alone, then shows a second
  example with ROT13 (key 13, the classic "spoiler tag" cipher).

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
python3 caesar_cipher.py                                  # built-in demo
python3 caesar_cipher.py --encrypt --text "Meet at noon" --shift 5
python3 caesar_cipher.py --decrypt --text "Rjjy fy stts" --shift 5
python3 caesar_cipher.py --break --text "Dwwdfn dw gdzq"
python3 caesar_cipher.py --break --text "Khoor zruog" --json
python3 caesar_cipher.py --encrypt --file note.txt --shift 13
python3 caesar_cipher.py --help                           # all the options
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
