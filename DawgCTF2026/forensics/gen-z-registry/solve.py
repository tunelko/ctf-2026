#!/usr/bin/env python3
"""
Gen-Z found my registry - DawgCTF 2026
Windows .reg file with hidden flag data.

Attack: injected 26 single-char values with numeric keys (1-26) spread across
different service entries. Two fake services (+7 and -6) encode the cipher:
- +7 service, "evens" param → even-numbered keys were shifted by +7
- -6 service, "odds" param → odd-numbered keys were shifted by -6

To decode: even keys +7, odd keys -6 (reverse of encoding)
"""
import re

REG_FILE = "files/chal.reg"

# Read UTF-16LE registry file
with open(REG_FILE, 'rb') as f:
    raw = f.read()
text = raw[2:].decode('utf-16-le', errors='replace') if raw[:2] == b'\xff\xfe' else raw.decode('utf-16-le')

# Extract all "NUMBER"="CHAR" entries (numeric key, 1-3 char value)
entries = []
for m in re.finditer(r'"(\d+)"="([^"]{1,3})"', text):
    entries.append((int(m.group(1)), m.group(2)))

entries.sort(key=lambda x: x[0])

# Decode: even-numbered keys shifted +7, odd-numbered keys shifted -6
flag = ''
for num, c in entries:
    if num % 2 == 0:
        flag += chr(ord(c) + 7)
    else:
        flag += chr(ord(c) - 6)

print(f"[+] FLAG: {flag}")
