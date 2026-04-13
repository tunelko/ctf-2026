#!/usr/bin/env python3
"""Brick by Brick — UMassCTF 2026 (hwrf)
UART 8N1 decode from CSV logic analyzer capture.
1 sample = 1 bit, flag in hex in kernel boot log."""
import csv, re

levels = []
with open('code.csv') as f:
    for row in csv.DictReader(f):
        levels.append(int(row['logic_level']))

# Decode UART 8N1: idle=1, start=0, 8 data bits LSB-first, stop=1
chars = []
i = 0
while i < len(levels) - 10:
    if levels[i] == 1 and levels[i+1] == 0:  # falling edge = start bit
        start = i + 1
        byte_val = 0
        for bit in range(8):
            byte_val |= (levels[start + 1 + bit] << bit)
        if levels[start + 9] == 1:  # valid stop bit
            chars.append(byte_val)
        i = start + 10
        continue
    i += 1

text = bytes(chars).decode('ascii', errors='replace')

# Extract hex-encoded flag from "secretflag: <hex>"
m = re.search(r'secretflag:\s*([0-9a-f]+)', text)
if m:
    flag = bytes.fromhex(m.group(1)).decode()
    print(f"[+] FLAG: {flag}")
else:
    print(text)
