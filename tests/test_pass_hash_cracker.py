#!/usr/bin/env python3
"""Tests for the Password Hash Tool (pass_hash_cracker)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pass_hash_cracker as ph

HERE = os.path.dirname(os.path.abspath(__file__))


class CryptVectors(unittest.TestCase):
    """SHA-crypt / MD5-crypt against the official spec vectors.

    The 1400-round 'anotherlongsaltstring' vectors use the post-errata values
    that current libxcrypt, passlib, and glibc produce.
    """

    SHA256_VECTORS = [
        ("Hello world!", "$5$saltstring",
         "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
        ("Hello world!", "$5$rounds=10000$saltstringsaltstring",
         "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"),
        ("This is just a test", "$5$rounds=5000$toolongsaltstring",
         "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"),
        ("a very much longer text to encrypt.  This one even stretches over more than one line.",
         "$5$rounds=1400$anotherlongsaltstring",
         "$5$rounds=1400$anotherlongsalts$epZZlHtH1tHOZ8DnGj41SJcfP6bNgf3t.hurPudKyU6"),
        ("we have a short salt string but not a short password",
         "$5$rounds=77777$short",
         "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"),
        ("a short string", "$5$rounds=123456$asaltof16chars..",
         "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"),
        ("the minimum number is still observed", "$5$rounds=10$roundstoolow",
         "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC"),
    ]

    SHA512_VECTORS = [
        ("Hello world!", "$6$saltstring",
         "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
        ("Hello world!", "$6$rounds=10000$saltstringsaltstring",
         "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
        ("This is just a test", "$6$rounds=5000$toolongsaltstring",
         "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"),
        ("a very much longer text to encrypt.  This one even stretches over more than one line.",
         "$6$rounds=1400$anotherlongsaltstring",
         "$6$rounds=1400$anotherlongsalts$WV8KW2lepsuKk13lXtVGnnEyZ.bCxFvSok6ZnkjRIa5iL0cAfvQyaZ2uA5CUvArDxyp3l9B/Z4D.HNqsIPpXk1"),
        ("we have a short salt string but not a short password",
         "$6$rounds=77777$short",
         "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"),
        ("a short string", "$6$rounds=123456$asaltof16chars..",
         "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
        ("the minimum number is still observed", "$6$rounds=10$roundstoolow",
         "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."),
    ]

    MD5_VECTORS = [
        ("password", "3azHgidD", "$1$3azHgidD$SrJPt7B.9rekpmwJwtON31"),
        ("password", "5pZSV9va", "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0"),
        ("password", "wu98", "$1$wu98$9UuD3hvrwehnqyF1D548N0"),
    ]

    def test_sha256_vectors(self):
        for pw, salt, expect in self.SHA256_VECTORS:
            self.assertEqual(ph.sha256_crypt(pw, salt), expect)

    def test_sha512_vectors(self):
        for pw, salt, expect in self.SHA512_VECTORS:
            self.assertEqual(ph.sha512_crypt(pw, salt), expect)

    def test_md5_vectors(self):
        for pw, salt, expect in self.MD5_VECTORS:
            self.assertEqual(ph.md5_crypt(pw, salt), expect)

    def test_crypt_hash_dispatch(self):
        h = ph.sha512_crypt("secret", "$6$saltsalt")
        self.assertTrue(ph.crypt_verify("secret", h))
        self.assertFalse(ph.crypt_verify("wrong", h))
        self.assertEqual(ph.crypt_hash("x", "$1$s$"),
                         ph.md5_crypt("x", "$1$s$"))
        with self.assertRaises(ValueError):
            ph.crypt_hash("x", "$apr1$abc/")
        self.assertTrue(ph.sha512_crypt("x", "plain").startswith("$6$plain$"))

    def test_rounds_default_omitted(self):
        h = ph.sha512_crypt("pw", "$6$saltsalt")
        self.assertTrue(h.startswith("$6$saltsalt$"))
        hc = ph.sha512_crypt("pw", "$6$rounds=1000$saltsalt")
        self.assertTrue(hc.startswith("$6$rounds=1000$saltsalt$"))

    def test_ct_compare(self):
        self.assertTrue(ph._ct_compare("abc", "abc"))
        self.assertFalse(ph._ct_compare("abc", "abd"))
        self.assertFalse(ph._ct_compare("ab", "abc"))  # length mismatch


class HashIdentifierTests(unittest.TestCase):
    def test_identify_hex(self):
        self.assertEqual(ph.HashIdentifier.identify("d41d8cd98f00b204e9800998ecf8427e")["type"], "md5")
        self.assertEqual(ph.HashIdentifier.identify("a" * 40)["type"], "sha1")
        self.assertEqual(ph.HashIdentifier.identify("a" * 64)["type"], "sha256")
        self.assertEqual(ph.HashIdentifier.identify("a" * 128)["type"], "sha512")
        self.assertEqual(ph.HashIdentifier.identify("zzzz")["type"], "unknown")

    def test_identify_crypt(self):
        self.assertEqual(ph.HashIdentifier.identify("$6$abc$def")["type"], "sha512crypt")
        self.assertEqual(ph.HashIdentifier.identify("$5$abc$def")["type"], "sha256crypt")
        self.assertEqual(ph.HashIdentifier.identify("$1$abc$def")["type"], "md5crypt")
        self.assertEqual(ph.HashIdentifier.identify("NT$abc")["type"], "ntlm")
        self.assertEqual(ph.HashIdentifier.identify("$2a$10$abc")["type"], "bcrypt")


class HashFunctionsTests(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(ph.HashFunctions.md5(""), "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(ph.HashFunctions.sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(ph.HashFunctions.sha256(""),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(ph.HashFunctions.ntlm(""), "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_compute(self):
        self.assertEqual(ph.HashFunctions.compute("abc", "md5"),
                         ph.HashFunctions.md5("abc"))
        with self.assertRaises(ValueError):
            ph.HashFunctions.compute("abc", "nope")

    def test_compute_crypt(self):
        h = ph.HashFunctions.compute_crypt("abc", "$6$saltsalt")
        self.assertEqual(h, ph.sha512_crypt("abc", "$6$saltsalt"))


class DictionaryAttackTests(unittest.TestCase):
    def test_crack_hex(self):
        attacker = ph.DictionaryAttack()
        attacker.set_wordlist(["password", "letmein"])
        h = ph.HashFunctions.md5("password")
        self.assertEqual(attacker.crack(h, "md5"), "password")
        self.assertEqual(attacker.attempts, 1)

    def test_crack_plain_missing(self):
        attacker = ph.DictionaryAttack()
        attacker.set_wordlist(["nope"])
        self.assertIsNone(attacker.crack(ph.HashFunctions.md5("password"), "md5"))

    def test_crack_crypt(self):
        attacker = ph.DictionaryAttack()
        h = ph.sha512_crypt("toor", "$6$rounds=1000$labsalt01")
        attacker.set_wordlist(["password", "toor", "letmein"])
        self.assertEqual(attacker.crack(h, "sha512crypt"), "toor")

    def test_crack_crypt_missing(self):
        attacker = ph.DictionaryAttack()
        h = ph.md5_crypt("secret", "labsalt")
        attacker.set_wordlist(["password", "letmein"])
        self.assertIsNone(attacker.crack(h, "md5crypt"))

    def test_crack_multiple(self):
        attacker = ph.DictionaryAttack()
        attacker.set_wordlist(["password", "toor"])
        hashes = {ph.HashFunctions.md5("password"): "md5",
                  ph.sha256_crypt("toor", "$5$labsalt"): "sha256crypt"}
        results = attacker.crack_multiple(hashes)
        self.assertEqual(results[list(hashes)[0]], "password")
        self.assertEqual(results[list(hashes)[1]], "toor")


class RainbowTableTests(unittest.TestCase):
    def test_generate_and_lookup(self):
        rt = ph.RainbowTable()
        rt.generate("ab", 1, 2, hash_type="md5")
        self.assertEqual(rt.lookup(ph.HashFunctions.md5("ab")), "ab")
        self.assertIsNone(rt.lookup(ph.HashFunctions.md5("c")))

    def test_save_load(self):
        rt = ph.RainbowTable()
        rt.from_wordlist(["alpha", "beta"], "md5")
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "table.json")
            rt.save(path)
            rt2 = ph.RainbowTable()
            rt2.load(path)
            self.assertEqual(rt2.lookup(ph.HashFunctions.md5("alpha")), "alpha")
            self.assertEqual(rt2.stats()["entries"], 2)


class RuleBasedGeneratorTests(unittest.TestCase):
    def test_rules(self):
        gen = ph.RuleBasedGenerator()
        results = gen.apply_rules(["pass"])
        joined = " ".join(results)
        for token in ("pass!", "pass1", "PASS", "Pass", "p455", "pa55"):
            self.assertTrue(token in results or token in joined, token)

    def test_deduplicated(self):
        gen = ph.RuleBasedGenerator()
        results = gen.apply_rules(["pass"])
        self.assertEqual(len(results), len(set(results)))


class RainbowCrackTests(unittest.TestCase):
    def test_rainbow_crack(self):
        cracker = ph.PasswordCracker()
        cracker.create_sample_table("abc", 2)
        target = ph.HashFunctions.md5("ab")
        res = cracker.crack(target, method="rainbow")
        self.assertTrue(res["cracked"])
        self.assertEqual(res["password"], "ab")


class PasswordPolicyTests(unittest.TestCase):
    def test_strong_accepts(self):
        a = ph.PasswordPolicy().analyze("Kx9#mPq2Lz@8fW")
        self.assertEqual(a["verdict"], "accept")
        self.assertGreaterEqual(a["estimated_bits"], 60)

    def test_weak_rejects(self):
        self.assertEqual(ph.PasswordPolicy().analyze("123456")["verdict"], "reject")
        a = ph.PasswordPolicy().analyze("password", wordlist=["password"])
        self.assertEqual(a["verdict"], "reject")
        self.assertTrue(a["common_word"])

    def test_entropy_sanity(self):
        policy = ph.PasswordPolicy()
        self.assertGreater(policy.shannon_entropy("abcdefghijkl"),
                           policy.shannon_entropy("aaaaaaaaaaaa"))
        self.assertEqual(policy.estimated_bits("", []), 0.0)


class OrchestratorTests(unittest.TestCase):
    def test_auto_crack_dictionary(self):
        cracker = ph.PasswordCracker()
        words = ["password", "letmein", "toor"]
        res = cracker.crack(ph.HashFunctions.md5("password"), wordlist=words)
        self.assertTrue(res["cracked"])
        self.assertEqual(res["password"], "password")
        self.assertEqual(res["hash_type"], "md5")

    def test_auto_crack_crypt(self):
        cracker = ph.PasswordCracker()
        words = ["password", "demo123", "trustno1"]
        h = ph.sha256_crypt("demo123", "$5$labsalt02")
        res = cracker.crack(h, wordlist=words)
        self.assertTrue(res["cracked"])
        self.assertEqual(res["password"], "demo123")
        self.assertEqual(res["hash_type"], "sha256crypt")


class DemoAndFixturesTests(unittest.TestCase):
    def test_fixtures_created(self):
        with tempfile.TemporaryDirectory() as td:
            base = ph.build_fixtures(td)
            self.assertTrue(os.path.exists(os.path.join(base, "wordlist.txt")))
            with open(os.path.join(base, "shadow.txt")) as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            self.assertEqual(len(lines), 5)

    def test_demo_cracks_all(self):
        out = ph.run_demo()
        self.assertEqual(out["totals"]["entries"], 5)
        self.assertEqual(out["totals"]["cracked"], 5)

    def test_cli_demo_subprocess(self):
        script = os.path.join(HERE, "..", "pass_hash_cracker.py")
        r = (subprocess.run([sys.executable, script, "demo"],
                            capture_output=True, text=True))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cracked", r.stdout)

    def test_cli_demo_roundtrip_json(self):
        script = os.path.join(HERE, "..", "pass_hash_cracker.py")
        r = subprocess.run([sys.executable, script, "demo", "--json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["totals"]["cracked"], 5)


if __name__ == "__main__":
    unittest.main()