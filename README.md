# PassGuard: Password Security Toolkit

A command-line tool, written in Python, that does three things:

1. **Checks** how strong a password is and explains how to improve it
2. **Generates** strong random passwords
3. **Stores** credentials in a vault encrypted with a master password

Built to practise applied cryptography basics: key derivation, authenticated encryption, secure randomness and safe handling of secrets.

## Features

- Strength report with a rating, a score out of 100, an entropy estimate and a rough offline crack-time estimate
- Detects common passwords, "leetspeak" disguises (`P@ssw0rd`), trailing digits (`password123`), sequences (`abc`, `321`), keyboard runs (`qwer`) and repeated characters
- Passwords are read through hidden prompts, so they don't end up on screen
- Encrypted vault with a wrong-password and tamper check
- Unit tests covering the strength logic, the generator and the vault

## Setup

Requires Python 3.8+ and one dependency:

```bash
pip install cryptography
```

## Usage

```bash
# Check a password (you'll be prompted, so it isn't saved in shell history)
python passguard.py check

# Generate passwords
python passguard.py generate -l 20 -n 3
python passguard.py generate --no-symbols

# Encrypted vault
python passguard.py vault init
python passguard.py vault add github myusername --generate
python passguard.py vault list
python passguard.py vault get github
python passguard.py vault delete github
```

Use `--vault PATH` (before the subcommand) to keep the vault somewhere other than `~/.passguard_vault.json`.

### Example output

```
$ python passguard.py check "P@ssw0rd"

  Rating:            Very weak (score 0/100)
  Estimated entropy: 0.0 bits
  Time to crack:     ~instantly (offline attack, 10 billion guesses/second)

  How to improve it:
   - This is (or closely resembles) a very common password. Pick something unique.
   - Use at least 12 characters; length matters more than complexity.
```

## How it works

| Part | Approach |
|------|----------|
| Key derivation | PBKDF2-HMAC-SHA256, 480,000 iterations, random 16-byte salt per vault |
| Encryption | Fernet (AES-128-CBC with an HMAC-SHA256 integrity check) |
| Master password | Never stored. A wrong password fails decryption, and so does a modified file |
| Randomness | `secrets` and `os.urandom` (never `random`) |
| Vault file | JSON containing only the salt, iteration count and encrypted blob. Written atomically with owner-only permissions (`0600`) |
| Entropy estimate | `length × log2(character pool size)`, reduced for sequences and repeats |

## Running the tests

```bash
python -m unittest -v
```

## Limitations

- The strength check is an **estimate**. It only knows a small built-in list of common passwords and can't spot arbitrary dictionary words or personal info. A library like [zxcvbn](https://github.com/dropbox/zxcvbn) does this far better.
- The vault prints retrieved passwords to the terminal. A real tool would use the clipboard with auto-clear.
- This is a learning project. For real-world credentials, use an audited password manager.

## Ideas for improvement

- Load a large common-password list (for example from SecLists)
- Passphrase generation from a word list
- Clipboard support with auto-clear
- Change-master-password command
- Check passwords against the Have I Been Pwned range API (k-anonymity)

## What I learned

[WRITE 2-3 SENTENCES IN YOUR OWN WORDS: for example, what surprised you about entropy, or why a salt matters.]
