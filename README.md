# C6 — Password Hash Tool

Identify, hash, crack, and strength-check passwords — MD5/SHA1/SHA256/NTLM hex
hashes plus $1$/$5$/$6$ Unix crypt (MD5/SHA-256/SHA-512 crypt), implemented in
pure Python with **zero dependencies**.

## Overview

This project implements a password hashing/cracking toolkit that:

- **Identifies** hash types automatically (`analyze`)
- **Hashes** passwords with MD5, SHA1, SHA256, NTLM (MD4), and `$1$`/`$5$`/`$6$` crypt
- **Cracks** hashes with dictionary attacks, rule-based variations, and rainbow tables
- **Scores** passwords with a policy engine (length, variety, estimated entropy,
  common-word list)

The crypt algorithms (`$1$`, `$5$`, `$6$`) are re-implemented from the RFC-1320 /
FreeBSD MD5-crypt and the Drepper SHA-crypt specifications **without** the `crypt`
module (unavailable on Python 3.13 builds). The implementation is validated against
the official test vectors and cross-checked against libxcrypt (`mkpasswd`) on
hundreds of randomized inputs.

## Features

- **Hash identification**: auto-detect hash algorithm from length/pattern
- **Dictionary attack**: wordlist-based cracking, hex and salted-crypt targets
- **Rule-based generation**: capitalization, suffixes, leet speak, reversal, duplication
- **Rainbow tables**: generate from charset or wordlist, save/load JSON
- **Password policy**: Shannon + effective-alphabet entropy, strength verdicts
- **Batch processing**: crack multiple hashes at once

## Installation

```bash
# No external dependencies required
# Uses only Python standard library
```

## Usage

```bash
# Hash a password
python3 pass_hash_cracker.py hash 'hello' -a sha512 --salt '$6$labsalt00'
python3 pass_hash_cracker.py hash 'hello' -a sha512crypt --salt '$6$rounds=1000$labsalt00'

# Crack a hash (auto method: rainbow -> dictionary -> rules)
python3 pass_hash_cracker.py crack '$6$rounds=1000$labsalt01$KKg74l1U...' -w fixtures/wordlist.txt

# Identify a hash
python3 pass_hash_cracker.py analyze '5f4dcc3b5aa765d61d8327deb882cf99'

# Score a password against policy
python3 pass_hash_cracker.py policy 'Kx9#mPq2Lz@8fW'

# Offline, deterministic demonstration (writes fixtures/, crackable shadow file)
python3 pass_hash_cracker.py demo

# JSON output / file reports
python3 pass_hash_cracker.py demo --json --output reports/demo.json

# Run the unit tests
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

| Step | Command | Expected result |
|------|---------|-----------------|
| 1 | `python3 pass_hash_cracker.py hash 'hello' -a sha512` | `$6$…` hash printed |
| 2 | `python3 pass_hash_cracker.py hash 'hello' -a sha512crypt --salt '$6$rounds=1000$labsalt00'` | hash contains `rounds=1000` |
| 3 | `python3 pass_hash_cracker.py analyze '$6$…'` | type `sha512crypt` |
| 4 | `python3 pass_hash_cracker.py analyze 5f4dcc3b5aa765d61d8327deb882cf99` | type `md5` |
| 5 | `python3 pass_hash_cracker.py hash 'password' -a md5 \| …` then `crack` that hash with `-w fixtures/wordlist.txt` | `password` recovered |
| 6 | `python3 pass_hash_cracker.py policy '123456'` | verdict `reject` |
| 7 | `python3 pass_hash_cracker.py policy 'Kx9#mPq2Lz@8fW'` | verdict `accept` |
| 8 | `python3 pass_hash_cracker.py demo` | 5/5 shadow entries cracked, exit 0 |
| 9 | `python3 pass_hash_cracker.py demo --json --output reports/demo.json` | valid JSON report file |
| 10 | `python3 -m unittest discover -s tests` | 30 tests pass |

## Metrics

- 30 unit tests, all passing (`python3 -m unittest discover -s tests`).
- Crypt engine reproduces 7/7 SHA-256 and 7/7 SHA-512 official spec vectors
  (errata-corrected 1400-round `anotherlongsalts` cases) and 3 MD5-crypt vectors,
  plus 192 randomized SHA + 56 randomized MD5 checks against libxcrypt.
- `demo` exits 0 and recovers all 5 planted shadow passwords offline.
- Pure standard-library implementation (no `crypt`, no third-party packages).

## Example Output

```
$ python3 pass_hash_cracker.py demo
=== Password Hash Tool demo ===
fixtures: .../c6-pass-hash/fixtures
root: sha512crypt -> toor [cracked]
app: sha256crypt -> demo123 [cracked]
dev: md5crypt -> trustno1 [cracked]
hash-md5: md5 -> password [cracked]
hash-sha1: sha1 -> password [cracked]
totals: 5 entries, 5 cracked
policy[Kx9#mPq2Lz@8fW] = accept (very strong, 92.0 bits)
policy[password] = reject (weak, 37.6 bits)
policy[123456] = reject (very weak, 19.9 bits)
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT