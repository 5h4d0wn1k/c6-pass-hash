> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C6 — Password Hash Tool

Pure-Python **password hashing and cracking** utility: automatic hash-format
detection, dictionary and rule-based wordlist attacks, rainbow tables, and
policy scoring — MD5/SHA-1/SHA-256/NTLM plus `$1$`/`$5$`/`$6$` Unix crypt with
**zero dependencies**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/c6-pass-hash)](https://github.com/5h4d0wn1k/c6-pass-hash)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/c6-pass-hash)](https://github.com/5h4d0wn1k/c6-pass-hash/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c6-pass-hash)](https://github.com/5h4d0wn1k/c6-pass-hash)

## Why

Weak, reused, and predictable passwords are the most common root cause in
breaches — which is exactly why defenders need to understand how they get
recovered. C6 is an educational and authorized-testing implementation of the
full password-offense pipeline: identify a hash by its format, try a dictionary
attack, apply rule-based variations (capitalization, suffixes, leet-speak,
reversal), or fall back to pre-computed rainbow tables, and finally score
candidate policies. Its distinguisher: the Unix crypt algorithms
(`$1$`, `$5$`, `$6$`) are re-implemented from the RFC-1320/FreeBSD MD5-crypt and
Drepper SHA-crypt specifications — no `crypt` module, no third-party packages —
and validated against official spec vectors plus hundreds of randomized
libxcrypt comparisons. Use it on hashes you own, in password-audit drives over
your own shadow files, and in security training labs.

## Features

- **Hash identification** — auto-detect MD5, SHA-1, SHA-256, NTLM, and Unix crypt formats
- **Hashing** — `hash` subcommand across all supported algorithms, with custom salts
- **Dictionary attack** — hex and salted-crypt targets from a wordlist
- **Rule-based generation** — capitalization, suffixes, leet-speak, reversal, duplication
- **Rainbow tables** — generate from charset or wordlist, save/load JSON
- **Policy scoring** — Shannon + effective-alphabet entropy with accept/reject verdicts
- **Batch processing** — crack multiple hashes at once
- **Offline demo** — `demo` recovers all 5 planted shadow hashes and exits 0

## Quickstart

Python standard library only.

```bash
# Hash a password (plain and sha512crypt)
python3 pass_hash_cracker.py hash 'hello' -a sha512 --salt '$6$labsalt00'
python3 pass_hash_cracker.py hash 'hello' -a sha512crypt --salt '$6$rounds=1000$labsalt00'

# Crack a hash (auto method: rainbow -> dictionary -> rules)
python3 pass_hash_cracker.py crack '$6$rounds=1000$labsalt01$KKg74l1U...' -w fixtures/wordlist.txt

# Identify and score
python3 pass_hash_cracker.py analyze '5f4dcc3b5aa765d61d8327deb882cf99'
python3 pass_hash_cracker.py policy 'Kx9#mPq2Lz@8fW'

# Offline demo (cracks 5 planted shadow hashes, exit 0) + JSON report
python3 pass_hash_cracker.py demo
python3 pass_hash_cracker.py demo --json --output reports/demo.json

# Unit tests (30 cases)
python3 -m unittest discover -s tests
```

## Project structure

- `pass_hash_cracker.py` — CLI entry point (subcommands: `hash`, `crack`, `analyze`, `policy`, `demo`)
- `fixtures/` — wordlist and demo shadow fixtures
- `tests/` — 30 unit tests

## Legal & authorized use

For **educational and authorized security testing purposes only**. Only crack
hashes you own — e.g. passwords from your own password-audit drives or lab
shadow files — or targets covered by written authorization. See
[ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md), and [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).