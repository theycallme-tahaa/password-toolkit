#!/usr/bin/env python3
"""PassGuard: a small command-line password security toolkit.

Features
  check      Rate a password's strength and explain how to improve it.
  generate   Create strong random passwords with Python's `secrets` module.
  vault      Store credentials in a file encrypted with a master password.

Security design (the parts worth being able to explain):
  * The master password is never stored. A 256-bit key is derived from it with
    PBKDF2-HMAC-SHA256 (480,000 iterations) and a random 16-byte salt.
  * The vault is encrypted with Fernet (AES-128-CBC + HMAC-SHA256), so a wrong
    master password or a tampered file is detected rather than silently accepted.
  * Random values come from `secrets` / `os.urandom`, never from `random`.
"""

import argparse
import base64
import getpass
import json
import math
import os
import re
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS = 480_000
SALT_BYTES = 16
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
DEFAULT_VAULT = Path.home() / ".passguard_vault.json"

# A small sample of very common passwords. For real use, swap in a bigger list
# (for example the "10k most common passwords" lists published by SecLists).
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "1234567", "12345", "1234567890", "111111",
    "000000", "123123", "654321", "666666", "121212", "112233", "123321", "987654321",
    "password", "password1", "passw0rd", "p@ssword", "p@ssw0rd", "pass", "pass123",
    "admin", "admin123", "administrator", "root", "toor", "login", "welcome",
    "welcome1", "letmein", "iloveyou", "monkey", "dragon", "master", "shadow",
    "sunshine", "princess", "football", "baseball", "soccer", "hockey", "batman",
    "superman", "spiderman", "pokemon", "naruto", "starwars", "whatever", "freedom",
    "trustno1", "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm",
    "1q2w3e4r", "1qaz2wsx", "qazwsx", "abc123", "abcd1234", "abcdef", "test", "test123",
    "guest", "hello", "hello123", "secret", "changeme", "default", "access", "flower",
    "hottie", "loveme", "ashley", "michael", "jennifer", "jordan", "hunter", "ranger",
    "buster", "tigger", "charlie", "robert", "thomas", "jessica", "daniel", "george",
    "summer", "winter", "spring", "autumn", "cheese", "cookie", "chocolate", "coffee",
    "computer", "internet", "samsung", "google", "facebook", "instagram", "whatsapp",
    "pakistan", "lahore", "karachi", "islamabad", "allah", "bismillah", "muhammad",
    "ali", "ahmed", "hassan", "hussain", "fatima", "ayesha", "bilal", "usman",
    "iloveu", "ilovey", "mypassword", "yourpassword", "newpassword", "love", "money",
    "killer", "pepper", "ginger", "matrix", "marina", "mustang", "merlin", "lakers",
}

# Common character substitutions ("leetspeak") used to disguise weak passwords.
LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "l", "3": "e",
                          "$": "s", "5": "s", "7": "t", "!": "i"})

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


# --------------------------------------------------------------------------- #
# Strength checking
# --------------------------------------------------------------------------- #
def is_common(password):
    """True if the password (or an obvious variation of it) is a known weak one."""
    p = password.lower()
    stripped = p.rstrip(string.digits + string.punctuation)
    variants = {p, p.translate(LEET_MAP), stripped, stripped.translate(LEET_MAP)}
    return any(len(v) >= 2 and v in COMMON_PASSWORDS for v in variants)


def has_sequence(password, min_len=3):
    """Detect runs like 'abc', '321' or keyboard patterns like 'qwer'."""
    p = password.lower()
    for i in range(len(p) - min_len + 1):
        chunk = p[i:i + min_len]
        if all(c.isalnum() for c in chunk):
            diffs = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(min_len - 1)}
            if diffs == {1} or diffs == {-1}:
                return True
    for row in KEYBOARD_ROWS:
        for pattern in (row, row[::-1]):
            for i in range(len(pattern) - 3):
                if pattern[i:i + 4] in p:
                    return True
    return False


def has_repeats(password):
    """True if any character appears 3+ times in a row (e.g. 'aaa')."""
    return re.search(r"(.)\1{2,}", password) is not None


def character_classes(password):
    return {
        "lowercase letters": any(c in string.ascii_lowercase for c in password),
        "uppercase letters": any(c in string.ascii_uppercase for c in password),
        "digits": any(c in string.digits for c in password),
        "symbols": any(not c.isalnum() for c in password),
    }


def estimate_entropy(password):
    """Rough entropy in bits: length * log2(size of the character pool used)."""
    classes = character_classes(password)
    pool = 0
    pool += 26 if classes["lowercase letters"] else 0
    pool += 26 if classes["uppercase letters"] else 0
    pool += 10 if classes["digits"] else 0
    pool += 32 if classes["symbols"] else 0
    if pool == 0:
        return 0.0
    entropy = len(password) * math.log2(pool)
    if has_sequence(password):
        entropy *= 0.7
    if has_repeats(password):
        entropy *= 0.8
    return entropy


def human_time(seconds):
    """Turn a number of seconds into a readable duration."""
    minute, hour, day, year = 60, 3600, 86400, 31_557_600
    if seconds < 1:
        return "instantly"
    if seconds < minute:
        return f"{seconds:.0f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.0f} minutes"
    if seconds < day:
        return f"{seconds / hour:.0f} hours"
    if seconds < year:
        return f"{seconds / day:.0f} days"
    years = seconds / year
    if years >= 1e9:
        return "over a billion years"
    if years >= 1e6:
        return f"{years / 1e6:.0f} million years"
    return f"{years:,.0f} years"


def analyze_password(password, guesses_per_second=1e10):
    """Return a dict with rating, score, entropy, crack-time estimate and tips."""
    tips = []
    common = is_common(password)
    entropy = 0.0 if common else estimate_entropy(password)

    if common:
        tips.append("This is (or closely resembles) a very common password. Pick something unique.")
    if len(password) < 12:
        tips.append("Use at least 12 characters; length matters more than complexity.")
    for name, present in character_classes(password).items():
        if not present:
            tips.append(f"Add {name} to widen the character pool.")
    if has_sequence(password):
        tips.append("Avoid sequences like 'abc', '123' or keyboard runs like 'qwer'.")
    if has_repeats(password):
        tips.append("Avoid repeating the same character three or more times.")

    if entropy < 28:
        rating = "Very weak"
    elif entropy < 36:
        rating = "Weak"
    elif entropy < 60:
        rating = "Fair"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very strong"

    # On average an attacker finds the password after trying half the space.
    seconds = (2 ** min(entropy, 300)) / 2 / guesses_per_second
    return {
        "rating": rating,
        "score": min(100, round(entropy / 80 * 100)),
        "entropy_bits": round(entropy, 1),
        "crack_time": human_time(seconds),
        "common": common,
        "tips": tips,
    }


# --------------------------------------------------------------------------- #
# Password generation
# --------------------------------------------------------------------------- #
def generate_password(length=16, use_symbols=True):
    """Generate a random password with at least one character of each class."""
    if not 8 <= length <= 128:
        raise ValueError("length must be between 8 and 128")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        pools.append(SYMBOLS)
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Encrypted vault
# --------------------------------------------------------------------------- #
class VaultError(Exception):
    """Raised for any vault problem (missing file, wrong password, corruption)."""


def derive_key(master, salt, iterations=KDF_ITERATIONS):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(master.encode("utf-8")))


def save_vault(path, master, entries, salt, iterations=KDF_ITERATIONS):
    """Encrypt `entries` and write them to `path` (atomically, owner-only access)."""
    token = Fernet(derive_key(master, salt, iterations)).encrypt(json.dumps(entries).encode())
    payload = {
        "version": 1,
        "kdf": "pbkdf2-sha256",
        "iterations": iterations,
        "salt": base64.b64encode(salt).decode(),
        "data": token.decode(),
    }
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)


def create_vault(path, master):
    path = Path(path)
    if path.exists():
        raise VaultError(f"A vault already exists at {path}")
    save_vault(path, master, {}, os.urandom(SALT_BYTES))


def load_vault(path, master):
    """Decrypt and return (entries, salt, iterations). Raises VaultError on failure."""
    path = Path(path)
    if not path.exists():
        raise VaultError(f"No vault found at {path}. Run 'vault init' first.")
    try:
        payload = json.loads(path.read_text())
        salt = base64.b64decode(payload["salt"])
        iterations = int(payload["iterations"])
        token = payload["data"].encode()
    except (ValueError, KeyError) as exc:
        raise VaultError("Vault file is corrupted or not a PassGuard vault.") from exc
    try:
        decrypted = Fernet(derive_key(master, salt, iterations)).decrypt(token)
    except InvalidToken as exc:
        raise VaultError("Wrong master password, or the vault was tampered with.") from exc
    return json.loads(decrypted), salt, iterations


def add_entry(path, master, site, username, password):
    entries, salt, iterations = load_vault(path, master)
    entries[site.lower()] = {
        "username": username,
        "password": password,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    save_vault(path, master, entries, salt, iterations)


def delete_entry(path, master, site):
    entries, salt, iterations = load_vault(path, master)
    if site.lower() not in entries:
        raise VaultError(f"No entry for '{site}'.")
    del entries[site.lower()]
    save_vault(path, master, entries, salt, iterations)


# --------------------------------------------------------------------------- #
# Command-line interface
# --------------------------------------------------------------------------- #
def print_report(result):
    print(f"\n  Rating:            {result['rating']} (score {result['score']}/100)")
    print(f"  Estimated entropy: {result['entropy_bits']} bits")
    print(f"  Time to crack:     ~{result['crack_time']} "
          "(offline attack, 10 billion guesses/second)")
    if result["tips"]:
        print("\n  How to improve it:")
        for tip in result["tips"]:
            print(f"   - {tip}")
    else:
        print("\n  No obvious weaknesses found.")
    print()


def prompt_master(confirm=False):
    master = getpass.getpass("Master password: ")
    if confirm:
        if getpass.getpass("Repeat master password: ") != master:
            raise VaultError("Passwords did not match.")
    return master


def cmd_check(args):
    password = args.password
    if password is None:
        password = getpass.getpass("Password to check (hidden): ")
    elif sys.stdout.isatty():
        print("Tip: omit the password argument to be prompted securely; "
              "arguments can be saved in your shell history.")
    print_report(analyze_password(password))


def cmd_generate(args):
    for _ in range(args.count):
        password = generate_password(args.length, not args.no_symbols)
        print(password)


def cmd_vault(args):
    path = args.vault
    action = args.vault_command

    if action == "init":
        master = prompt_master(confirm=True)
        result = analyze_password(master)
        if result["rating"] in ("Very weak", "Weak"):
            raise VaultError(f"Master password is {result['rating'].lower()}. "
                             "Choose a longer, less predictable one.")
        create_vault(path, master)
        print(f"Vault created at {path}")
        return

    master = prompt_master()
    if action == "add":
        username = args.username
        if args.generate:
            password = generate_password(args.length)
            print(f"Generated password: {password}")
        else:
            password = getpass.getpass(f"Password for {args.site} (hidden): ")
        add_entry(path, master, args.site, username, password)
        print(f"Saved entry for '{args.site}'.")
    elif action == "get":
        entries, _, _ = load_vault(path, master)
        entry = entries.get(args.site.lower())
        if entry is None:
            raise VaultError(f"No entry for '{args.site}'.")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
    elif action == "list":
        entries, _, _ = load_vault(path, master)
        if not entries:
            print("Vault is empty.")
        for site in sorted(entries):
            print(f"- {site}  ({entries[site]['username']})")
    elif action == "delete":
        delete_entry(path, master, args.site)
        print(f"Deleted '{args.site}'.")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="passguard", description="Password strength checker, generator and encrypted vault.")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT,
                        help=f"vault file location (default: {DEFAULT_VAULT})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="rate a password's strength")
    p_check.add_argument("password", nargs="?", help="leave empty to be prompted securely")
    p_check.set_defaults(func=cmd_check)

    p_gen = sub.add_parser("generate", help="generate random passwords")
    p_gen.add_argument("-l", "--length", type=int, default=16)
    p_gen.add_argument("-n", "--count", type=int, default=1)
    p_gen.add_argument("--no-symbols", action="store_true")
    p_gen.set_defaults(func=cmd_generate)

    p_vault = sub.add_parser("vault", help="encrypted credential storage")
    p_vault.set_defaults(func=cmd_vault)
    vsub = p_vault.add_subparsers(dest="vault_command", required=True)
    vsub.add_parser("init", help="create a new vault")
    p_add = vsub.add_parser("add", help="add or update an entry")
    p_add.add_argument("site")
    p_add.add_argument("username")
    p_add.add_argument("--generate", action="store_true", help="generate the password for you")
    p_add.add_argument("--length", type=int, default=20, help="length when using --generate")
    p_get = vsub.add_parser("get", help="show an entry")
    p_get.add_argument("site")
    vsub.add_parser("list", help="list stored sites")
    p_del = vsub.add_parser("delete", help="delete an entry")
    p_del.add_argument("site")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (VaultError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
