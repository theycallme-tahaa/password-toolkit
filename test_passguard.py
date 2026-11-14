"""Unit tests for PassGuard. Run with:  python -m unittest -v"""

import json
import tempfile
import unittest
from pathlib import Path

import passguard as pg


class StrengthTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        result = pg.analyze_password("password")
        self.assertTrue(result["common"])
        self.assertEqual(result["rating"], "Very weak")

    def test_leetspeak_and_trailing_digits_are_caught(self):
        for pw in ("P@ssw0rd", "password123", "Qwerty!!", "Dragon2024"):
            self.assertTrue(pg.is_common(pw), pw)

    def test_sequences_and_repeats(self):
        self.assertTrue(pg.has_sequence("xx123yy"))
        self.assertTrue(pg.has_sequence("myqwertypass"))
        self.assertFalse(pg.has_sequence("x7Kp#2mQ"))
        self.assertTrue(pg.has_repeats("heyyyyou"))
        self.assertFalse(pg.has_repeats("hey you"))

    def test_longer_is_stronger(self):
        self.assertLess(pg.estimate_entropy("Xk7#m"), pg.estimate_entropy("Xk7#mQ9$vL2@"))

    def test_generated_password_rates_strong(self):
        result = pg.analyze_password(pg.generate_password(20))
        self.assertIn(result["rating"], ("Strong", "Very strong"))

    def test_human_time(self):
        self.assertEqual(pg.human_time(0.1), "instantly")
        self.assertEqual(pg.human_time(120), "2 minutes")
        self.assertIn("billion", pg.human_time(1e20))


class GeneratorTests(unittest.TestCase):
    def test_length_and_character_classes(self):
        for _ in range(50):
            pw = pg.generate_password(16)
            self.assertEqual(len(pw), 16)
            self.assertTrue(all(pg.character_classes(pw).values()))

    def test_no_symbols_option(self):
        pw = pg.generate_password(24, use_symbols=False)
        self.assertTrue(pw.isalnum())

    def test_rejects_bad_length(self):
        with self.assertRaises(ValueError):
            pg.generate_password(4)

    def test_passwords_are_not_repeated(self):
        self.assertEqual(len({pg.generate_password(20) for _ in range(100)}), 100)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.json"
        self.master = "correct horse battery staple 9!"

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip(self):
        pg.create_vault(self.path, self.master)
        pg.add_entry(self.path, self.master, "GitHub", "taha", "s3cret-value")
        entries, _, _ = pg.load_vault(self.path, self.master)
        self.assertEqual(entries["github"]["username"], "taha")
        self.assertEqual(entries["github"]["password"], "s3cret-value")

    def test_wrong_master_password_is_rejected(self):
        pg.create_vault(self.path, self.master)
        with self.assertRaises(pg.VaultError):
            pg.load_vault(self.path, "not the master password")

    def test_file_contains_no_plaintext(self):
        pg.create_vault(self.path, self.master)
        pg.add_entry(self.path, self.master, "mybank.example", "taha", "hunter-2-plaintext")
        raw = self.path.read_text()
        for secret in ("mybank", "hunter-2-plaintext", "taha"):
            self.assertNotIn(secret, raw)

    def test_tampering_is_detected(self):
        pg.create_vault(self.path, self.master)
        payload = json.loads(self.path.read_text())
        payload["data"] = payload["data"][:-4] + "AAAA"
        self.path.write_text(json.dumps(payload))
        with self.assertRaises(pg.VaultError):
            pg.load_vault(self.path, self.master)

    def test_delete_entry(self):
        pg.create_vault(self.path, self.master)
        pg.add_entry(self.path, self.master, "site", "u", "p")
        pg.delete_entry(self.path, self.master, "site")
        entries, _, _ = pg.load_vault(self.path, self.master)
        self.assertEqual(entries, {})

    def test_cannot_overwrite_existing_vault(self):
        pg.create_vault(self.path, self.master)
        with self.assertRaises(pg.VaultError):
            pg.create_vault(self.path, self.master)


if __name__ == "__main__":
    unittest.main()
