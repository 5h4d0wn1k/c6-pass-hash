# C6 — Password Hash Cracker

MD5/SHA1/SHA256/NTLM hash cracking with rainbow table lookup, rule-based generation, and hash identification.

## Overview

This project implements a password hash cracking toolkit that:
- Identifies hash types automatically
- Cracks hashes using dictionary attacks
- Generates password variations with rule-based transformation
- Builds and queries rainbow tables
- Supports MD5, SHA1, SHA256, and NTLM algorithms

## Features

- **Hash identification**: Auto-detect hash algorithm from length/pattern
- **Dictionary attack**: Wordlist-based cracking
- **Rule-based generation**: Capitalization, suffixes, leet speak, reversal
- **Rainbow tables**: Pre-computed hash lookup
- **Batch processing**: Crack multiple hashes at once

## Installation

```bash
# No external dependencies required
# Uses only Python standard library
```

## Usage

```bash
# Run the cracker
python3 pass_hash_cracker.py

# Use in code
from pass_hash_cracker import PasswordCracker, HashFunctions

cracker = PasswordCracker()
cracker.create_sample_table('abc', 2)
target = HashFunctions.md5('abc')
result = cracker.crack(target)
print(result)
```

## Example Output

```
=== Password Hash Cracker ===
Rainbow table: {'hash_type': 'md5', 'entries': 9, 'sample_keys': [...]}

Target hash: 900150983cd24fb0d6963f7d28e17f72
Result: {
  "hash": "900150983cd24fb0d6963f7d28e17f72",
  "hash_type": "md5",
  "password": "abc",
  "method": "rainbow",
  "cracked": true
}

SHA256 analysis: {
  "hash": "...",
  "type": "sha256",
  "length": 64
}
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
