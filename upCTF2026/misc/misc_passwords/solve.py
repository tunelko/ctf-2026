#!/usr/bin/env python3
"""
Challenge: Leaked Password Database — upCTF 2026
Category:  misc (steganography / statistics)
Flag:      upCTF{m4rk0v_w4s_h3r3_4ll_4l0ng}

4000 lines of uppercase noise with a 25-char contiguous signal block per line.
Signal chars (a-z, 0-9, _) are biased per column — most frequent char per column
spells the flag.
"""

from collections import Counter

with open("passwords.txt") as f:
    lines = f.readlines()

# Extract the 25 signal characters from each line
signals = []
for line in lines:
    line = line.strip()
    sig = [c for c in line if c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    signals.append(sig)

# Most frequent character per column → flag
flag = ""
for col in range(25):
    column = [s[col] for s in signals]
    most_common = Counter(column).most_common(1)[0][0]
    flag += most_common

print(f"upCTF{{{flag}}}")
