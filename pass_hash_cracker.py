#!/usr/bin/env python3
"""Password Hash Tool - identification, hashing, cracking, and entropy policy."""

import argparse
import hashlib
import json
import itertools
import math
import os
import re
import string
import sys
from typing import Dict, List, Optional, Set, Tuple

B64T = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def _b64_from_24bit(b2: int, b1: int, b0: int, n: int) -> str:
    """Encode 24 bits (3 bytes) into n base-64 characters, low bits first."""
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(B64T[w & 0x3f])
        w >>= 6
    return ''.join(out)


# Group byte indices (b2, b1, b0) and char counts, per the crypt(5) spec.
_SHA256_GROUPS = [
    (0, 10, 20, 4), (21, 1, 11, 4), (12, 22, 2, 4), (3, 13, 23, 4),
    (24, 4, 14, 4), (15, 25, 5, 4), (6, 16, 26, 4), (27, 7, 17, 4),
    (18, 28, 8, 4), (9, 19, 29, 4), (None, 31, 30, 3),
]
_SHA512_GROUPS = [
    (0, 21, 42, 4), (22, 43, 1, 4), (44, 2, 23, 4), (3, 24, 45, 4),
    (25, 46, 4, 4), (47, 5, 26, 4), (6, 27, 48, 4), (28, 49, 7, 4),
    (50, 8, 29, 4), (9, 30, 51, 4), (31, 52, 10, 4), (53, 11, 32, 4),
    (12, 33, 54, 4), (34, 55, 13, 4), (56, 14, 35, 4), (15, 36, 57, 4),
    (37, 58, 16, 4), (59, 17, 38, 4), (18, 39, 60, 4), (40, 61, 19, 4),
    (62, 20, 41, 4), (None, None, 63, 2),
]
_MD5_GROUPS = [
    (0, 6, 12, 4), (1, 7, 13, 4), (2, 8, 14, 4),
    (3, 9, 15, 4), (4, 10, 5, 4), (None, None, 11, 2),
]

_ROUNDS_DEFAULT = 5000
_ROUNDS_MIN = 1000
_ROUNDS_MAX = 999999999

SALTED_CRYPT = {'sha512crypt', 'sha256crypt', 'md5crypt'}


def _repeat_digest(digest: bytes, length: int, block: int) -> bytes:
    """Expand digest into a byte sequence of the given length (P/S bytes)."""
    out = bytearray()
    cnt = length
    while cnt >= block:
        out += digest
        cnt -= block
    out += digest[:cnt]
    return bytes(out)


def _sha_crypt(password: str, salt_spec: str, hash_fn, digest_size: int,
               prefix: str, groups: List[Tuple[int, ...]]) -> str:
    """Generic SHA-crypt ($5$/$6$) per Donald Ulrich Drepper's spec."""
    key = password.encode()
    key_len = len(key)
    salt = salt_spec
    rounds = _ROUNDS_DEFAULT
    rounds_custom = False

    if salt.startswith(prefix):
        salt = salt[len(prefix):]
    if salt.startswith('rounds='):
        idx = salt.find('$')
        digits = salt[len('rounds='):idx if idx != -1 else None]
        try:
            srounds = int(digits)
        except (ValueError, TypeError):
            srounds = _ROUNDS_DEFAULT
        salt = salt[idx + 1:] if idx != -1 else ''
        rounds = max(_ROUNDS_MIN, min(srounds, _ROUNDS_MAX))
        rounds_custom = True
    salt = salt.split('$', 1)[0][:16]
    salt_bytes = salt.encode()
    salt_len = len(salt_bytes)

    # digests A and B per the spec
    alt = hash_fn()
    alt.update(key)
    alt.update(salt_bytes)
    alt.update(key)
    alt_result = alt.digest()

    ctx = hash_fn()
    ctx.update(key)
    ctx.update(salt_bytes)
    cnt = key_len
    while cnt > digest_size:
        ctx.update(alt_result)
        cnt -= digest_size
    ctx.update(alt_result[:cnt])
    cnt = key_len
    while cnt > 0:
        if cnt & 1:
            ctx.update(alt_result)
        else:
            ctx.update(key)
        cnt >>= 1
    alt_result = ctx.digest()

    # P byte sequence
    dp = hash_fn()
    for _ in range(key_len):
        dp.update(key)
    temp = dp.digest()
    p_bytes = _repeat_digest(temp, key_len, digest_size)

    # S byte sequence
    ds = hash_fn()
    for _ in range(16 + alt_result[0]):
        ds.update(salt_bytes)
    temp = ds.digest()
    s_bytes = _repeat_digest(temp, salt_len, digest_size)

    # rounds loop
    for i in range(rounds):
        rc = hash_fn()
        if i & 1:
            rc.update(p_bytes)
        else:
            rc.update(alt_result)
        if i % 3:
            rc.update(s_bytes)
        if i % 7:
            rc.update(p_bytes)
        if i & 1:
            rc.update(alt_result)
        else:
            rc.update(p_bytes)
        alt_result = rc.digest()

    out = prefix
    if rounds_custom:
        out += 'rounds=%d$' % rounds
    out += salt + '$'
    for (b2, b1, b0, n) in groups:
        out += _b64_from_24bit(alt_result[b2] if b2 is not None else 0,
                               alt_result[b1] if b1 is not None else 0,
                               alt_result[b0] if b0 is not None else 0, n)
    return out


def sha256_crypt(password: str, salt: str) -> str:
    """Compute $5$ (SHA-256 crypt). Salt may include '$5$'/'rounds='."""
    return _sha_crypt(password, salt, hashlib.sha256, 32, '$5$', _SHA256_GROUPS)


def sha512_crypt(password: str, salt: str) -> str:
    """Compute $6$ (SHA-512 crypt). Salt may include '$6$'/'rounds='."""
    return _sha_crypt(password, salt, hashlib.sha512, 64, '$6$', _SHA512_GROUPS)


def md5_crypt(password: str, salt: str) -> str:
    """Compute $1$ (FreeBSD MD5 crypt)."""
    pw = password.encode()
    if salt.startswith('$1$'):
        salt = salt[len('$1$'):]
    salt = salt.split('$', 1)[0][:8].encode()

    m = hashlib.md5()
    m.update(pw + b'$1$' + salt)
    mixin = hashlib.md5(pw + salt + pw).digest()
    for i in range(len(pw)):
        m.update(mixin[i % 16:i % 16 + 1])
    i = len(pw)
    while i:
        if i & 1:
            m.update(b'\x00')
        else:
            m.update(pw[:1])
        i >>= 1
    final = m.digest()

    for i in range(1000):
        m2 = hashlib.md5()
        if i & 1:
            m2.update(pw)
        else:
            m2.update(final)
        if i % 3:
            m2.update(salt)
        if i % 7:
            m2.update(pw)
        if i & 1:
            m2.update(final)
        else:
            m2.update(pw)
        final = m2.digest()

    out = '$1$' + salt.decode() + '$'
    for (b2, b1, b0, n) in _MD5_GROUPS:
        out += _b64_from_24bit(final[b2] if b2 is not None else 0,
                               final[b1] if b1 is not None else 0,
                               final[b0] if b0 is not None else 0, n)
    return out


def crypt_hash(password: str, salt_spec: str) -> str:
    """Dispatch to the right crypt scheme based on the salt's prefix."""
    spec = salt_spec
    if spec.startswith('$6$'):
        return sha512_crypt(password, spec)
    if spec.startswith('$5$'):
        return sha256_crypt(password, spec)
    if spec.startswith('$1$'):
        return md5_crypt(password, spec)
    if spec.startswith('$apr1$'):
        raise ValueError('apr1 hashing is not supported')
    # default: SHA-512 with the given salt
    return sha512_crypt(password, spec)


def crypt_verify(password: str, stored: str) -> bool:
    """Verify a password against a stored $1$/$5$/$6$ shadow entry."""
    computed = crypt_hash(password, stored)
    return len(computed) == len(stored) and _ct_compare(computed, stored)


def _ct_compare(a: str, b: str) -> bool:
    """Constant-time-ish string comparison."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


_MD4_MASK = 0xFFFFFFFF


def _md4_lrot(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MD4_MASK


def md4(data: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320); used for NTLM where hashlib lacks md4.

    OpenSSL 3 builds typically disable the legacy MD4 digest, so this
    implementation keeps the tool dependency-free (stdlib only).
    """
    msg = bytearray(data)
    length = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += length.to_bytes(8, 'little')

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    r1 = [3, 7, 11, 19] * 4
    r2 = [3, 5, 9, 13] * 4
    r3 = [3, 9, 11, 15] * 4
    o2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    o3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    k2 = 0x5A827999
    k3 = 0x6ED9EBA1

    A0, B0, C0, D0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    for offset in range(0, len(msg), 64):
        x = [int.from_bytes(msg[offset + 4 * i:offset + 4 * i + 4], 'little')
             for i in range(16)]
        a, b, c, d = A0, B0, C0, D0

        for s in range(0, 16, 4):
            a = _md4_lrot((a + f(b, c, d) + x[s]) & _MD4_MASK, r1[s])
            d = _md4_lrot((d + f(a, b, c) + x[s + 1]) & _MD4_MASK, r1[s + 1])
            c = _md4_lrot((c + f(d, a, b) + x[s + 2]) & _MD4_MASK, r1[s + 2])
            b = _md4_lrot((b + f(c, d, a) + x[s + 3]) & _MD4_MASK, r1[s + 3])

        for s in range(0, 16, 4):
            a = _md4_lrot((a + g(b, c, d) + x[o2[s]] + k2) & _MD4_MASK, r2[s])
            d = _md4_lrot((d + g(a, b, c) + x[o2[s + 1]] + k2) & _MD4_MASK, r2[s + 1])
            c = _md4_lrot((c + g(d, a, b) + x[o2[s + 2]] + k2) & _MD4_MASK, r2[s + 2])
            b = _md4_lrot((b + g(c, d, a) + x[o2[s + 3]] + k2) & _MD4_MASK, r2[s + 3])

        for s in range(0, 16, 4):
            a = _md4_lrot((a + h(b, c, d) + x[o3[s]] + k3) & _MD4_MASK, r3[s])
            d = _md4_lrot((d + h(a, b, c) + x[o3[s + 1]] + k3) & _MD4_MASK, r3[s + 1])
            c = _md4_lrot((c + h(d, a, b) + x[o3[s + 2]] + k3) & _MD4_MASK, r3[s + 2])
            b = _md4_lrot((b + h(c, d, a) + x[o3[s + 3]] + k3) & _MD4_MASK, r3[s + 3])

        A0 = (A0 + a) & _MD4_MASK
        B0 = (B0 + b) & _MD4_MASK
        C0 = (C0 + c) & _MD4_MASK
        D0 = (D0 + d) & _MD4_MASK

    return (A0.to_bytes(4, 'little') + B0.to_bytes(4, 'little')
            + C0.to_bytes(4, 'little') + D0.to_bytes(4, 'little'))


class HashIdentifier:
    """Identify hash type from a hash string."""

    HASH_LENGTHS = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512',
    }

    HASH_PATTERNS = {
        r'^\$2[aby]?\$': 'bcrypt',
        r'^\$6\$': 'sha512crypt',
        r'^\$5\$': 'sha256crypt',
        r'^\$1\$': 'md5crypt',
        r'^NT\$': 'ntlm',
        r'^[0-9a-fA-F]{32}$': 'md5',
        r'^[0-9a-fA-F]{40}$': 'sha1',
        r'^[0-9a-fA-F]{64}$': 'sha256',
        r'^[0-9a-fA-F]{96}$': 'sha384',
        r'^[0-9a-fA-F]{128}$': 'sha512',
    }

    @classmethod
    def identify(cls, hash_str: str) -> Dict:
        """Identify the hash type."""
        import re
        hash_str = hash_str.strip()

        for pattern, hash_type in cls.HASH_PATTERNS.items():
            if re.match(pattern, hash_str):
                return {
                    'hash': hash_str,
                    'type': hash_type,
                    'length': len(hash_str)
                }

        length = len(hash_str)
        if length in cls.HASH_LENGTHS:
            return {
                'hash': hash_str,
                'type': cls.HASH_LENGTHS[length],
                'length': length
            }

        return {
            'hash': hash_str,
            'type': 'unknown',
            'length': length
        }


class HashFunctions:
    """Compute hashes in various algorithms."""

    @staticmethod
    def md5(plaintext: str) -> str:
        return hashlib.md5(plaintext.encode()).hexdigest()

    @staticmethod
    def sha1(plaintext: str) -> str:
        return hashlib.sha1(plaintext.encode()).hexdigest()

    @staticmethod
    def sha256(plaintext: str) -> str:
        return hashlib.sha256(plaintext.encode()).hexdigest()

    @staticmethod
    def ntlm(plaintext: str) -> str:
        return md4(plaintext.encode('utf-16-le')).hex()

    @staticmethod
    def compute(plaintext: str, hash_type: str) -> str:
        funcs = {
            'md5': HashFunctions.md5,
            'sha1': HashFunctions.sha1,
            'sha256': HashFunctions.sha256,
            'ntlm': HashFunctions.ntlm,
        }
        func = funcs.get(hash_type.lower())
        if func:
            return func(plaintext)
        raise ValueError(f"Unsupported hash type: {hash_type}")

    @staticmethod
    def compute_crypt(plaintext: str, salt_or_hash: str) -> str:
        """Compute a $1$/$5$/$6$ crypt hash (pure-Python, stdlib only)."""
        return crypt_hash(plaintext, salt_or_hash)


class DictionaryAttack:
    """Dictionary-based password cracking."""

    def __init__(self, wordlist_path: str = None):
        self.wordlist: List[str] = []
        self.attempts = 0
        self.found_passwords: Dict[str, str] = {}
        if wordlist_path:
            self.load_wordlist(wordlist_path)

    def load_wordlist(self, path: str) -> None:
        """Load wordlist from file."""
        try:
            with open(path, 'r', errors='ignore') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.wordlist = []

    def set_wordlist(self, words: List[str]) -> None:
        self.wordlist = words

    def crack(self, target_hash: str, hash_type: str = 'md5') -> Optional[str]:
        """Try dictionary words against target hash."""
        self.attempts = 0

        if hash_type in SALTED_CRYPT:
            for word in self.wordlist:
                self.attempts += 1
                if crypt_verify(word, target_hash):
                    self.found_passwords[target_hash] = word
                    return word
            return None

        target_lower = target_hash.lower()

        for word in self.wordlist:
            self.attempts += 1
            computed = HashFunctions.compute(word, hash_type)
            if computed == target_lower:
                self.found_passwords[target_hash] = word
                return word
        return None

    def crack_multiple(self, targets: Dict[str, str]) -> Dict[str, Optional[str]]:
        """Crack multiple hashes at once."""
        results = {}
        for target_hash, hash_type in targets.items():
            results[target_hash] = self.crack(target_hash, hash_type)
        return results


class RuleBasedGenerator:
    """Generate password variations using rules."""

    SUFFIXES = ['!', '1', '12', '123', '@', '#', '!', '2024', '2025']
    PREFIXES = ['', 'My', 'The', 'a', 'A']
    LEET_MAP = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}

    def __init__(self):
        self.generated: List[str] = []
        self.rules_applied: List[str] = []

    def apply_rules(self, base_words: List[str]) -> List[str]:
        """Apply transformation rules to base words."""
        results = []
        for word in base_words:
            results.extend(self._capitalize(word))
            results.extend(self._add_suffixes(word))
            results.extend(self._leet_speak(word))
            results.extend(self._reversed(word))
            results.extend(self._duplicated(word))
            results.extend(self._insert_numbers(word))
            results.extend(self._leetspeak_variations(word))
        self.generated = list(set(results))
        return self.generated

    def _capitalize(self, word: str) -> List[str]:
        return [
            word.upper(),
            word.capitalize(),
            word.title(),
            word.lower()
        ]

    def _add_suffixes(self, word: str) -> List[str]:
        return [word + s for s in self.SUFFIXES]

    def _leet_speak(self, word: str) -> List[str]:
        leet = ''
        for c in word.lower():
            leet += self.LEET_MAP.get(c, c)
        return [leet]

    def _reversed(self, word: str) -> List[str]:
        return [word[::-1]]

    def _duplicated(self, word: str) -> List[str]:
        return [word + word]

    def _insert_numbers(self, word: str) -> List[str]:
        return [f"{word}{i}" for i in range(10)]

    def _leetspeak_variations(self, word: str) -> List[str]:
        variations = []
        lower = word.lower()
        for char, replacement in self.LEET_MAP.items():
            if char in lower:
                variations.append(lower.replace(char, replacement))
        return variations


class RainbowTable:
    """Rainbow table for hash lookup."""

    def __init__(self):
        self.table: Dict[str, str] = {}
        self.hash_type = 'md5'

    def generate(self, charset: str, min_len: int, max_len: int,
                 hash_type: str = 'md5', max_entries: int = 100000) -> None:
        """Generate rainbow table entries."""
        self.hash_type = hash_type
        count = 0
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if count >= max_entries:
                    return
                password = ''.join(combo)
                h = HashFunctions.compute(password, hash_type)
                self.table[h] = password
                count += 1

    def from_wordlist(self, words: List[str], hash_type: str = 'md5') -> None:
        """Build table from wordlist."""
        self.hash_type = hash_type
        for word in words:
            h = HashFunctions.compute(word, hash_type)
            self.table[h] = word

    def lookup(self, hash_str: str) -> Optional[str]:
        """Look up hash in table."""
        return self.table.get(hash_str.lower())

    def lookup_batch(self, hashes: List[str]) -> Dict[str, Optional[str]]:
        """Look up multiple hashes."""
        return {h: self.lookup(h) for h in hashes}

    def save(self, filepath: str) -> None:
        """Save table to file."""
        with open(filepath, 'w') as f:
            json.dump(self.table, f)

    def load(self, filepath: str) -> None:
        """Load table from file."""
        with open(filepath, 'r') as f:
            self.table = json.load(f)

    def stats(self) -> Dict:
        return {
            'hash_type': self.hash_type,
            'entries': len(self.table),
            'sample_keys': list(self.table.keys())[:5]
        }


class PasswordPolicy:
    """Estimate password strength from Shannon entropy and character variety."""

    CLASSES = {
        'lowercase': lambda p: any(c.islower() for c in p),
        'uppercase': lambda p: any(c.isupper() for c in p),
        'digits': lambda p: any(c.isdigit() for c in p),
        'symbols': lambda p: any(not c.isalnum() for c in p),
    }

    STRENGTHS = [
        (90, 'very strong'),
        (60, 'strong'),
        (40, 'moderate'),
        (24, 'weak'),
        (0, 'very weak'),
    ]

    POOL_SIZES = {'lowercase': 26, 'uppercase': 26, 'digits': 10, 'symbols': 33}

    @classmethod
    def shannon_entropy(cls, password: str) -> float:
        """Bits of Shannon entropy over the password's character frequency."""
        from collections import Counter
        counts = Counter(password)
        length = len(password) or 1
        bits = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                bits -= p * math.log2(p)
        return round(bits, 4)

    @classmethod
    def estimated_bits(cls, password: str, classes: List[str]) -> float:
        """Estimated entropy from length and the effective character pool."""
        if not password:
            return 0.0
        pool = sum(cls.POOL_SIZES[name] for name in classes) or 1
        return round(len(password) * math.log2(pool), 2)

    def analyze(self, password: str, min_length: int = 8,
                wordlist: Optional[List[str]] = None) -> Dict:
        """Return a full strength assessment for one password."""
        present = [name for name, test in self.CLASSES.items() if test(password)]
        entropy = self.shannon_entropy(password)
        est_bits = self.estimated_bits(password, present)

        if entropy > 0:
            guess = round(2 ** entropy)
        else:
            guess = 1

        checks = [
            {'ok': len(password) >= min_length, 'name': 'length',
             'detail': '%d chars (min %d)' % (len(password), min_length)},
            {'ok': len(present) >= 3, 'name': 'variety',
             'detail': ', '.join(present) or 'none'},
            {'ok': est_bits >= 60, 'name': 'entropy',
             'detail': '%.2f estimated bits' % est_bits},
        ]

        score = 0
        for threshold, label in self.STRENGTHS:
            if est_bits >= threshold:
                score = threshold
                strength = label
                break
        else:
            score, strength = 0, 'very weak'

        common = False
        if wordlist:
            common = password.lower() in {w.lower() for w in wordlist}

        verdict = 'reject'
        if (len(password) >= min_length and len(present) >= 3
                and est_bits >= 60 and not common):
            verdict = 'accept'

        return {
            'password': password,
            'length': len(password),
            'classes': present,
            'shannon_bits': float(entropy),
            'estimated_bits': est_bits,
            'estimated_guesses': guess,
            'strength': strength,
            'common_word': common,
            'checks': checks,
            'score': score,
            'verdict': verdict,
        }


class PasswordCracker:
    """Main password cracking orchestrator."""

    def __init__(self):
        self.identifier = HashIdentifier()
        self.hash_func = HashFunctions()
        self.dictionary = DictionaryAttack()
        self.generator = RuleBasedGenerator()
        self.rainbow = RainbowTable()
        self.results: List[Dict] = []

    def crack(self, target_hash: str, method: str = 'auto',
              wordlist: List[str] = None) -> Optional[Dict]:
        """Crack a hash using specified or auto-detected method."""
        info = self.identifier.identify(target_hash)
        hash_type = info['type']

        if hash_type == 'unknown':
            hash_type = 'md5'

        password = None
        method_used = method

        if method in ('auto', 'rainbow'):
            password = self.rainbow.lookup(target_hash)
            method_used = 'rainbow'

        if not password and method in ('auto', 'dictionary') and wordlist:
            self.dictionary.set_wordlist(wordlist)
            password = self.dictionary.crack(target_hash, hash_type)
            method_used = 'dictionary'

        if not password and method in ('auto', 'rules') and wordlist:
            variations = self.generator.apply_rules(wordlist[:50])
            self.dictionary.set_wordlist(variations)
            password = self.dictionary.crack(target_hash, hash_type)
            method_used = 'rule_based'

        result = {
            'hash': target_hash,
            'hash_type': hash_type,
            'password': password,
            'method': method_used,
            'cracked': password is not None
        }
        self.results.append(result)
        return result

    def analyze_hash(self, hash_str: str) -> Dict:
        """Analyze and identify a hash."""
        return self.identifier.identify(hash_str)

    def batch_crack(self, hashes: List[str],
                    wordlist: List[str] = None) -> List[Dict]:
        """Crack multiple hashes."""
        return [self.crack(h, wordlist=wordlist) for h in hashes]

    def create_sample_table(self, charset: str = 'abc',
                            length: int = 3) -> None:
        """Create a small sample rainbow table."""
        words = [''.join(c) for c in itertools.product(charset, repeat=length)]
        self.rainbow.from_wordlist(words, 'md5')

    def summary(self) -> Dict:
        return {
            'total_attempts': self.dictionary.attempts,
            'results': self.results,
            'rainbow_stats': self.rainbow.stats()
        }


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
REPORTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')


def build_fixtures(base_dir: str = None) -> str:
    """Write the small authorized lab dataset (wordlist + shadow entries)."""
    base = base_dir or FIXTURES
    os.makedirs(base, exist_ok=True)
    words = ['password', 'Password', 'letmein', 'admin', 'iloveyou', 'monkey',
             'dragon', '123456', 'qwerty', 'sunshine', 'princess', 'welcome',
             'toor', 'demo123', 'trustno1']
    entries = [
        'root:' + sha512_crypt('toor', '$6$rounds=1000$labsalt01'),
        'app:' + sha256_crypt('demo123', '$5$labsalt02'),
        'dev:' + md5_crypt('trustno1', 'uTsalT01'),
        'hash-md5:' + HashFunctions.md5('password'),
        'hash-sha1:' + HashFunctions.sha1('password'),
    ]
    with open(os.path.join(base, 'wordlist.txt'), 'w') as f:
        f.write('\n'.join(words) + '\n')
    with open(os.path.join(base, 'shadow.txt'), 'w') as f:
        f.write('\n'.join(entries) + '\n')
    return base


def _load_words(path: str) -> List[str]:
    words = []
    try:
        with open(path, 'r', errors='ignore') as f:
            words = [w.strip() for w in f if w.strip()]
    except OSError:
        words = []
    return words


def _save_report(result, path):
    with open(path, 'w') as f:
        json.dump(result, f, indent=2)
    return os.path.abspath(path)


def _render_hash(result, args) -> str:
    out = []
    for h in result['hashes']:
        out.append('%s = %s' % (h['algorithm'], h['value']))
    return '\n'.join(out)


def _render_crack(result, args) -> str:
    out = []
    for r in result['cracked']:
        status = 'CRACKED' if r['cracked'] else 'not found'
        out.append('%s %s -> %s [%s]' % (r['hash_type'], r['hash'], r['password'] or '-', status))
        out.append('  method=%s attempts=%d' % (r['method_used'], r['attempts']))
    return '\n'.join(out)


def _render_analysis(result, args) -> str:
    return '\n'.join('%s: %s' % (k, v) for k, v in result['analysis'].items())


def _render_policy(result, args) -> str:
    a = result['policy']
    out = ['password: %s' % a['password'],
           'length: %d  classes: %s  est. entropy: %.2f bits' % (
               a['length'], ', '.join(a['classes']) or 'none', a['estimated_bits']),
           'strength: %s  common_word: %s  verdict: %s' % (
               a['strength'], a['common_word'], a['verdict'])]
    for c in a['checks']:
        out.append('  [%s] %s: %s' % ('PASS' if c['ok'] else 'FAIL', c['name'], c['detail']))
    return '\n'.join(out)


def _render_demo(result, args) -> str:
    out = ['=== Password Hash Tool demo ===',
           'fixtures: %s' % result['fixtures']]
    for a in result['analyses']:
        out.append('%s: %s -> %s [%s]' % (a['user'], a['hash_type'], a['password'] or '-',
                                          'cracked' if a['cracked'] else 'uncracked'))
    out.append('totals: %d entries, %d cracked' % (result['totals']['entries'], result['totals']['cracked']))
    for p in result['policies']:
        out.append('policy[%s] = %s (%s, %.1f bits)' % (p['password'], p['verdict'], p['strength'], p['estimated_bits']))
    return '\n'.join(out)


def _emit(result, args, default_name) -> int:
    rendered = _renderers[args.command](result, args)
    if args.output:
        saved = _save_report(result, args.output)
        rendered += '\nreport: %s' % saved
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(rendered)
    return 0


def run_demo() -> Dict:
    """Offline, deterministic end-to-end demonstration."""
    build_fixtures()
    words = _load_words(os.path.join(FIXTURES, 'wordlist.txt'))
    cracker = PasswordCracker()
    cracker.dictionary.set_wordlist(words)
    policy = PasswordPolicy()
    results = []
    with open(os.path.join(FIXTURES, 'shadow.txt')) as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    for line in lines:
        user, h = line.split(':', 1)
        info = cracker.analyze_hash(h)
        res = cracker.crack(h, wordlist=words)
        res['user'] = user
        res['hash_type'] = info['type']
        results.append(res)
    policies = [policy.analyze('Kx9#mPq2Lz@8fW'),
                policy.analyze('password'),
                policy.analyze('123456')]
    return {
        'fixtures': FIXTURES,
        'analyses': [{'user': r['user'], 'hash_type': r['hash_type'],
                      'cracked': r['cracked'], 'password': r['password'],
                      'method': r['method']} for r in results],
        'policies': policies,
        'totals': {'entries': len(results),
                   'cracked': sum(1 for r in results if r['cracked'])},
    }


def run_hash(args, cracker) -> Dict:
    algo = args.algorithm
    salt = args.salt
    if algo in SALTED_CRYPT and not salt:
        salt = {'sha512crypt': '$6$labsalt00',
                'sha256crypt': '$5$labsalt00',
                'md5crypt': 'laBsaLt0'}[algo]
    value = HashFunctions.compute_crypt(args.password, salt) if algo in SALTED_CRYPT \
        else HashFunctions.compute(args.password, algo)
    return {'hashes': [{'algorithm': algo, 'value': value}]}


def run_crack(args, cracker) -> Dict:
    words = _load_words(args.wordlist or os.path.join(FIXTURES, 'wordlist.txt'))
    res = cracker.crack(args.hash, method=args.method, wordlist=words)
    if args.method != 'auto' and res.get('method') is None:
        res['method'] = args.method
    from_rainbow = res.get('method') == 'rainbow'
    return {'cracked': [{
        'hash': args.hash,
        'hash_type': res['hash_type'],
        'password': res['password'],
        'cracked': res['cracked'],
        'method_used': res['method'],
        'attempts': cracker.dictionary.attempts if not from_rainbow else 0,
    }]}


def run_analysis(args, cracker) -> Dict:
    return {'analysis': cracker.analyze_hash(args.hash)}


def run_policy(args, cracker) -> Dict:
    words = _load_words(args.wordlist) if args.wordlist else None
    policy = PasswordPolicy()
    return {'policy': policy.analyze(args.password, min_length=args.min_length,
                                     wordlist=words)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog='pass_hash_cracker',
        description='Password Hash Tool - identify, hash, crack, and score '
                    'passwords (authorized/educational use only).')
    sub = parser.add_subparsers(dest='command', required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--json', action='store_true',
                        help='emit the result as raw JSON')
    common.add_argument('--output', metavar='FILE',
                        help='also write the full JSON report to FILE')

    ph = sub.add_parser('hash', parents=[common], help='hash a password')
    ph.add_argument('password')
    ph.add_argument('-a', '--algorithm', default='sha512',
                    choices=['md5', 'sha1', 'sha256', 'ntlm',
                             'md5crypt', 'sha256crypt', 'sha512crypt'])
    ph.add_argument('--salt', default=None,
                    help='salt (or full $prefix$salt string) for crypt algos')
    ph.set_defaults(func=lambda a, c: run_hash(a, c))

    pc = sub.add_parser('crack', parents=[common], help='crack a hash')
    pc.add_argument('hash')
    pc.add_argument('-m', '--method', default='auto',
                    choices=['auto', 'dictionary', 'rules', 'rainbow'])
    pc.add_argument('-w', '--wordlist', default=None, metavar='FILE')
    pc.set_defaults(func=lambda a, c: run_crack(a, c))

    pa = sub.add_parser('analyze', parents=[common], help='identify a hash')
    pa.add_argument('hash')
    pa.set_defaults(func=lambda a, c: run_analysis(a, c))

    pp = sub.add_parser('policy', parents=[common], help='score a password')
    pp.add_argument('password')
    pp.add_argument('--min-length', type=int, default=8)
    pp.add_argument('--wordlist', default=None, metavar='FILE')
    pp.set_defaults(func=lambda a, c: run_policy(a, c))

    pd = sub.add_parser('demo', parents=[common], help='run the offline demo')
    pd.set_defaults(func=lambda a, c: run_demo())

    args = parser.parse_args(argv)
    return _emit(args.func(args, PasswordCracker()), args,
                 '%s-report.json' % args.command)


_renderers = {
    'hash': _render_hash,
    'crack': _render_crack,
    'analyze': _render_analysis,
    'policy': _render_policy,
    'demo': _render_demo,
}


if __name__ == "__main__":
    sys.exit(main())
