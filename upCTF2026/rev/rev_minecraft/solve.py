#!/usr/bin/env python3
"""
Challenge: Minecraft Enterprise — upCTF 2026
Category:  rev (keygen)
Flag:      upCTF{m1n3cr4ft_0n_th3_b4nks-QEbqBNzJ0f64bd0c}

Key format: XXXXX-XXXXX-XXXXX-XXXXX (20 alphanumeric chars)
Validation: parse → permute (swap halves + swap pairs) → HMAC-SHA256 first 10 chars
            with key "IMNOTTHEKEY" → base32 encode 50 bits → must match last 10 chars.
"""

import hmac, hashlib
from pwn import *

BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def compute_second_half(first10):
    """HMAC-SHA256 → take 7 bytes → >>6 → base32 encode 50 bits → 10 chars"""
    h = hmac.new(b"IMNOTTHEKEY", first10.encode(), hashlib.sha256).digest()
    val = int.from_bytes(h[:7], 'big') >> 6
    result = [''] * 10
    for i in range(9, -1, -1):  # binary writes backwards
        result[i] = BASE32[val & 0x1f]
        val >>= 5
    return ''.join(result)

def keygen():
    # Choose any 10 chars for HMAC input (permuted first half)
    first_half = "AAAAAAAAAA"
    second_half = compute_second_half(first_half)

    # Reverse permutation: step2 (swap adjacent), step1 (swap halves)
    permuted = list(first_half + second_half)
    for i in range(0, 20, 2):
        permuted[i], permuted[i+1] = permuted[i+1], permuted[i]
    original = permuted[10:] + permuted[:10]

    k = ''.join(original)
    return f"{k[0:5]}-{k[5:10]}-{k[10:15]}-{k[15:20]}"

key = keygen()
log.info(f"Generated key: {key}")

r = remote("46.225.117.62", 30023)
r.sendlineafter(b"): ", key.encode())
print(r.recvall(timeout=3).decode())
