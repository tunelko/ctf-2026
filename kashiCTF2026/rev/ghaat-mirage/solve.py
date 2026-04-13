#!/usr/bin/env python3
"""
Ghaat Mirage — MITM crack of polynomial hash validator
Binary: UPX-packed, decompressed code validates 32-byte input via 4 accumulators
Hash: acc[pos%4] = acc[pos%4] * 0x83 + byte (mod 2^64)
"""

TARGETS = [0x00fd91b66d4b8b11, 0x00e661491544fdb8, 0x010fc69e6442ef55, 0x00f680346b31a222]
MOD = 1 << 64
MULT = 0x83
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_{}ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#"

def mod_inv(a, m=MOD):
    """Modular inverse via extended Euclidean"""
    g, x, _ = extended_gcd(a % m, m)
    assert g == 1
    return x % m

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def power(base, exp, mod=MOD):
    r = 1
    for _ in range(exp):
        r = (r * base) % mod
    return r

def mitm_crack(prefix_bytes, n_unknown, target):
    """Meet-in-the-middle: split unknowns, build table for left, search from right"""
    # Compute prefix hash
    h = 0
    for b in prefix_bytes:
        h = (h * MULT + b) % MOD

    left_n = n_unknown // 2
    right_n = n_unknown - left_n

    C = power(MULT, right_n)
    C_inv = mod_inv(C)

    # Build left table
    from itertools import product
    table = {}
    for combo in product(CHARSET, repeat=left_n):
        lh = h
        for ch in combo:
            lh = (lh * MULT + ord(ch)) % MOD
        table[lh] = combo

    # Search right
    for combo in product(CHARSET, repeat=right_n):
        suffix = 0
        for ch in combo:
            suffix = (suffix * MULT + ord(ch)) % MOD
        needed = ((target - suffix) * C_inv) % MOD
        if needed in table:
            return list(table[needed]) + list(combo)
    return None

# Known: kashi{...} (32 bytes)
# pos 0='k',1='a',2='s',3='h',4='i',5='{',...,31='}'

# acc[0]: init=ord('k'), known=[ord('i')], 6 unknowns (pos 8,12,16,20,24,28)
r0 = mitm_crack([ord('k'), ord('i')], 6, TARGETS[0])
print(f"acc[0]: {''.join(r0)}")

# acc[1]: init=0, known=[ord('a'),ord('{')], 6 unknowns (pos 9,13,17,21,25,29)
r1 = mitm_crack([0, ord('a'), ord('{')], 6, TARGETS[1])
print(f"acc[1]: {''.join(r1)}")

# acc[2]: init=0, known=[ord('s')], 7 unknowns (pos 6,10,14,18,22,26,30)
r2 = mitm_crack([0, ord('s')], 7, TARGETS[2])
print(f"acc[2]: {''.join(r2)}")

# acc[3]: init=0, known=[ord('h')], 6 unknowns (pos 7,11,15,19,23,27), then '}'
# Adjust target: (target - ord('}')) * inv(0x83) = hash before last byte
adj = ((TARGETS[3] - ord('}')) * mod_inv(MULT)) % MOD
r3 = mitm_crack([0, ord('h')], 6, adj)
print(f"acc[3]: {''.join(r3)}")

# Reconstruct flag
flag = ['?'] * 32
flag[0]='k'; flag[1]='a'; flag[2]='s'; flag[3]='h'; flag[4]='i'; flag[5]='{'; flag[31]='}'

for i, p in enumerate([8,12,16,20,24,28]): flag[p] = r0[i]
for i, p in enumerate([9,13,17,21,25,29]): flag[p] = r1[i]
for i, p in enumerate([6,10,14,18,22,26,30]): flag[p] = r2[i]
for i, p in enumerate([7,11,15,19,23,27]): flag[p] = r3[i]

print(f"\n[+] FLAG: {''.join(flag)}")
