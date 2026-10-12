# Hash Identifier — a SOC beginner's guide to digital fingerprints

## The big idea (a non-tech analogy first)

Imagine every person on Earth had a fingerprint that was always exactly 10 digits long,
and you could look up those 10 digits in a global database to learn who they are —
without ever needing to see the person.

That's what a **hash** is for files. A hash is a fixed-length string of characters
computed from a file's contents — the file's "digital fingerprint." Two identical files
always produce the same hash. Change even one letter, and the hash changes completely.

Security operations center (SOC) analysts use this every day: when they find a
suspicious file, they don't open it — they compute its hash and look that fingerprint
up in a threat-intelligence database. If it matches a known-malware entry, they know
instantly what they're dealing with.

## What the script does

`hash_identifier.py` has two jobs:

1. **Identify mode** — you paste a hash (say, from a malware report or an alert),
   and it tells you which algorithm probably made it: MD5, SHA-1, SHA-256, SHA-512,
   or bcrypt. Each answer comes with a short note on what that hash type means for
   a SOC analyst.
2. **Hash mode** — you point it at one of *your own* files, and it computes that
   file's MD5, SHA-1, and SHA-256 fingerprints — the same values analysts paste
   into lookups to check whether a file is known malware.

Run it with no arguments for a guided demo that shows both.

## How the code works, line by line (in simple terms)

- **`HASH_SIGNATURES`** — a list of "mugshots." Each entry has a name, a pattern,
  and a plain-English SOC note. Every hash algorithm produces output of a fixed
  length (MD5 = 32 characters, SHA-1 = 40, SHA-256 = 64, SHA-512 = 128), so the
  length of the string is the main clue — like guessing a person's height from
  their silhouette.
- **`identify_hash(value)`** — takes the hash you pasted, strips whitespace, and
  checks it against each mugshot with a regular expression (a pattern-matching
  rule). It returns every match, because some hashes are ambiguous.
- **`hash_file(path)`** — opens your file in binary mode (`"rb"`, so it works on
  any file type — text, images, executables) and reads it 64 KB at a time. Reading
  in chunks means even a 10 GB file won't eat all your memory. It feeds each chunk
  into three hash calculators at once (MD5, SHA-1, SHA-256) and returns the results.
- **`run_demo()`** — computes real hashes of the word "hello" using Python's
  `hashlib`, then identifies them, so you can verify the answers yourself. Then it
  fingerprints `sample_file.txt` sitting next to the script.
- **`main()`** — the traffic cop. No arguments → demo. `identify` → interactive
  mode where you paste hashes until you type `quit`. `hash <file>` → fingerprints
  one of your files.

## Key terms, translated

| Term | Plain English |
|---|---|
| **Hash** | A fixed-length fingerprint computed from data |
| **MD5** | Old 128-bit hash (32 characters). Broken — don't trust it for security |
| **SHA-1** | Older 160-bit hash (40 characters). Also weak now, still seen in old reports |
| **SHA-256** | Modern 256-bit hash (64 characters). The SOC standard for file lookups |
| **SHA-512** | Stronger 512-bit hash (128 characters). Used for software download checks |
| **bcrypt** | How passwords are stored safely — deliberately slow to resist cracking |
| **NTLM** | Windows password hash format; looks identical to MD5, which is why length alone isn't always enough |
| **Avalanche effect** | Change one tiny input bit → the whole hash looks completely different |
| **Threat intelligence** | Databases (like VirusTotal) that map file hashes to known malware verdicts |

## How to run it

```bash
python3 hash_identifier.py                  # guided demo
python3 hash_identifier.py identify         # paste your own hashes to identify
python3 hash_identifier.py hash myfile.txt  # fingerprint one of YOUR files
```

Try the avalanche effect yourself: open `sample_file.txt`, change one letter,
save, and run the demo again. All three fingerprints will be completely different.

## What to learn next

1. **Look up a real hash** — take the SHA-256 of the sample file and paste it into
   VirusTotal's search. You'll get "no results," which is itself a lesson: unknown
   hashes are common, and analysts then turn to sandboxes and behavior analysis.
2. **Why MD5 is broken** — read about hash *collisions* (two different files with
   the same MD5). That's why nobody trusts MD5 for integrity anymore.
3. **Salting and bcrypt** — learn why passwords get bcrypt (slow, salted) instead
   of SHA-256 (fast). Speed is a *weakness* when the attacker is guessing passwords.
4. **YARA rules** — the next step up: instead of matching whole-file hashes,
   analysts write rules that match *patterns inside* files, catching malware
   variants whose hashes keep changing.

---

*Day 9 of a daily cybersecurity learning series. Code: single-file Python, standard
library only, runs fully offline on your own machine.*
