#!/usr/bin/env python3
"""
Challenge: webd-art (Cobweb Printer)
Category:  reversing
Platform:  UNbreakable 2026

Dart2Wasm WebAssembly binary with WasmGC + js-string builtins.
Validation: Weyl sequence PRNG with MurmurHash3 finalizer, XOR-decryption.
"""

def prng_byte(state):
    """MurmurHash3 32-bit finalizer applied to Weyl sequence state"""
    m = state ^ (state >> 16)
    m = (m * 0x85EBCA6B) & 0xFFFFFFFF
    m ^= (m >> 13)
    m = (m * 0xC2B2AE35) & 0xFFFFFFFF
    m ^= (m >> 16)
    return m & 0xFF

# Stored XOR array (40 elements), extracted from WASM section 65 at offset 0x4e42
# Unknown globals filled via constraint solving: g530=70, g531=4, g532=198, g533=150
STORED = [
    218, 78, 141, 70, 79, 33, 46, 234, 174, 75,
    4, 130, 143, 169, 189, 93, 127, 4, 198, 150,
    239, 47, 94, 136, 89, 231, 203, 209, 88, 150,
    122, 147, 60, 167, 251, 224, 198, 100, 50, 163
]

# Brute-force the 32-bit PRNG seed using known flag prefix CTF{ and suffix }
WEYL = 0x9E3779B9

target = [0x43 ^ 218, 0x54 ^ 78, 0x46 ^ 141]  # prng bytes for C, T, F
target_last = 0x7D ^ 163  # prng byte for }

print("[*] Brute-forcing 32-bit PRNG seed...")
for seed64 in range(0x100000000):
    seed = seed64
    s = (seed + WEYL) & 0xFFFFFFFF
    if prng_byte(s) != target[0]: continue
    s = (s + WEYL) & 0xFFFFFFFF
    if prng_byte(s) != target[1]: continue
    s = (s + WEYL) & 0xFFFFFFFF
    if prng_byte(s) != target[2]: continue
    s39 = (seed + 40 * WEYL) & 0xFFFFFFFF
    if prng_byte(s39) != target_last: continue

    # Generate full flag
    state = seed
    flag = []
    for i in range(40):
        state = (state + WEYL) & 0xFFFFFFFF
        flag.append(chr(prng_byte(state) ^ STORED[i]))

    flag_str = ''.join(flag)
    if all(0x20 <= ord(c) <= 0x7e for c in flag_str[4:-1]):
        print(f"[+] Seed: 0x{seed:08x}")
        print(f"[+] Flag: {flag_str}")
        break
else:
    print("[-] No seed found")
