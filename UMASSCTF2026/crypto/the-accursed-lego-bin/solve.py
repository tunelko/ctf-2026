#!/usr/bin/env python3
"""The Accursed Lego Bin — UMassCTF 2026 (crypto, 100pts)
plain^49 < n (3920 < 4096 bits) → no mod reduction → seed = plain^7 directly.
Reverse 10 random.shuffle operations to recover flag."""
import random

plain = int.from_bytes(b"I_LOVE_RNG", "big")
seed = pow(plain, 7)
flag_hex = "a9fa3c5e51d4cea498554399848ad14aa0764e15a6a2110b6613f5dc87fa70f17fafbba7eb5a2a5179"

bits = []
for b in bytes.fromhex(flag_hex):
    bits.extend(list(bin(b)[2:].zfill(8)))

for i in range(9, -1, -1):
    random.seed(seed * (i + 1))
    idx = list(range(len(bits)))
    random.seed(seed * (i + 1))
    random.shuffle(idx)
    tmp = [''] * len(bits)
    for j, k in enumerate(idx):
        tmp[k] = bits[j]
    bits = tmp

print(''.join(chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)))
