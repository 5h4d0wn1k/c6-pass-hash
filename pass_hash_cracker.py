#!/usr/bin/env python3
"""Password Hash Cracker - MD5/SHA1/SHA256/NTLM cracking with rainbow tables."""

import hashlib
import json
import itertools
import string
from typing import Dict, List, Optional, Set, Tuple


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
        return hashlib.new('md4', plaintext.encode('utf-16-le')).hexdigest()

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


if __name__ == "__main__":
    print("=== Password Hash Cracker ===")
    cracker = PasswordCracker()

    cracker.create_sample_table('abc', 2)
    print("Rainbow table:", cracker.rainbow.stats())

    target = HashFunctions.md5('abc')
    print(f"\nTarget hash: {target}")
    result = cracker.crack(target)
    print(f"Result: {json.dumps(result, indent=2)}")

    test_hash = HashFunctions.sha256('password')
    print(f"\nSHA256 analysis:")
    print(json.dumps(cracker.analyze_hash(test_hash), indent=2))
