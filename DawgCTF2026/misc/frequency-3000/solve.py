#!/usr/bin/env python3
"""DawgCTF 2026 - Frequency 3000 (misc) - Letter frequency in Futurama transcript"""
from collections import Counter

with open("Space Pilot 3000 Transcript.txt") as f:
    text = f.read()

# Decode flag.txt hex → numbers
encoded = "44 61 77 67 43 54 46 7b 20 33 39 30 20 31 30 30 32 20 35 38 30 20 31 33 31 34 20 31 39 31 20 31 35 38 39 20 33 33 20 31 35 32 36 20 31 34 31 20 37 36 32 20 33 35 32 20 38 38 20 31 32 39 33 20 33 37 39 20 35 30 20 7d"
decoded = bytes.fromhex(encoded.replace(" ", "")).decode()
# → DawgCTF{ 390 1002 580 1314 191 1589 33 1526 141 762 352 88 1293 379 50 }

import re
nums = list(map(int, re.findall(r'\d+', decoded)))

# Count character frequencies (case-insensitive for letters, exact for digits/punct)
# Build combined lookup: case-insensitive letters + case-sensitive non-letters
letter_freq = Counter(c.lower() for c in text if c.isalpha())
char_freq = Counter(c for c in text if not c.isalpha())

freq_map = {}
for ch, cnt in {**letter_freq, **char_freq}.items():
    freq_map[cnt] = freq_map.get(cnt, []) + [ch]

# Exact matches for leet chars (0, I, 3, ?)
# Close matches for letters (within 2 of target)
result = []
for n in nums:
    if n in freq_map:
        result.append(freq_map[n][0])
    else:
        best = min(freq_map.keys(), key=lambda k: abs(k - n))
        result.append(freq_map[best][0])

flag = "DawgCTF{" + "".join(result) + "}"
print(flag)
# DawgCTF{whyn0tz0Idb3rg?}  — "why not zoidberg?"
