#!/usr/bin/env python3
"""
Solver for Nanom-dinam???itee?
Character-by-character brute force against modified FNV-1a hashes.
"""
import struct

FNV_OFFSET_BASIS = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = 0xFFFFFFFFFFFFFFFF


def fnv_step(prev_hash, byte_val):
    """One step of the modified FNV-1a hash (with 32-bit fold)"""
    h = prev_hash ^ byte_val
    h = (h * FNV_PRIME) & MASK64
    h ^= h >> 32
    return h & MASK64


# Extract 40 hashes from binary
with open("nanom-dinam-ite__iteee", "rb") as f:
    f.seek(0x20A0)
    expected = struct.unpack("<40Q", f.read(320))

# Brute force
current_hash = FNV_OFFSET_BASIS
flag = ""

for i in range(40):
    for c in range(0x20, 0x7F):
        if fnv_step(current_hash, c) == expected[i]:
            flag += chr(c)
            current_hash = expected[i]
            break
    else:
        print(f"[-] No match at position {i}")
        break

print(f"[+] Flag: {flag}")
