#!/usr/bin/env python3
"""
I Hate Physics! - DawgCTF 2026
Category: crypto

Physics study notes with the flag hidden steganographically.
Each line's FIRST and LAST character combine to spell the flag.
Line 1: D...a → "Da", Line 2: w...g → "wg", etc.
→ DawgCTF{therm0dyn4mic5sucks!}
"""

with open('files/STUDYME.txt') as f:
    lines = f.read().split('\n')

flag = ''
for line in lines:
    if not line.strip():
        continue
    flag += line[0] + line[-1]
    if '}' in flag:
        break

# Trim anything after the closing brace
flag = flag[:flag.index('}') + 1]
print(f"[+] FLAG: {flag}")
