#!/usr/bin/env python3
"""solve.py — meh-yet-another-crackme solver"""
from itertools import product

# Check 1: XOR decode (FUN_000105cc)
# Each byte: decoded[i] = xor_data[i] ^ key ^ 0xa5, key starts at 0, increments by 7
xor_data = [224, 234, 159, 232, 194, 255, 191, 225, 194, 253, 150, 219, 130, 141, 244, 168, 138, 166, 179, 20, 93, 105, 77, 53, 126, 105, 76, 123, 19, 90, 20, 23, 40, 113, 54]

decoded = []
key = 0
for b in xor_data:
    decoded.append(b ^ key ^ 0xa5)
    key = (key + 7) & 0xff
print("Check1 decoded:", bytes(decoded))

# Check 2 (FUN_00010622):
# - flag[0] = 'E' (0x45), flag[1]='H'(0x48), flag[2]='4'(0x34), flag[3]='X'(0x58), flag[4]='{'(0x7b), flag[34]='}'(0x7d)
# - sum of all 35 bytes = 0xcab = 3243
# - product of flag[5]*flag[10]*flag[15]*flag[20]*flag[25]*flag[30] % 0x3b9aca07 == 0x1fb53791
# Wait, let me re-read the indices: local_18 = 0xa00000005 means two ints: [5, 0xa]
# uStack_10 = 0x140000000f -> [0xf, 0x14]
# uStack_8 = 0x1e00000019 -> [0x19, 0x1e]
# So indices are: 5, 10, 15, 20, 25, 30
# Product of param_1[5]*param_1[10]*param_1[15]*param_1[20]*param_1[25]*param_1[30] % 0x3b9aca07 == 0x1fb53791

# Check 3 (FUN_00010700 -> FUN_00010574 -> FUN_00010516):
# Custom hash of all 35 bytes must equal 0x81cf06f4a08cb5ef (unsigned of -0x7e30f90b5f734a11)

target_hash = (-0x7e30f90b5f734a11) & 0xffffffffffffffff  # = 0x81cf06f4a08cb5ef

def mix(val, idx):
    val = (0x5851f42d4c957f2d >> (idx & 0x3f)) ^ val
    val &= 0xffffffffffffffff
    result = ((val >> 0x33) + ((val * 0x2000) & 0xffffffffffffffff)) ^ 0xebfa848108987eb0
    return result & 0xffffffffffffffff

def compute_hash(data):
    h = 0xdeadbeef
    for i, b in enumerate(data):
        h = mix(h ^ (b << ((i & 7) * 8)), i)
    return h

# The decoded XOR gives us the flag directly if check1 passes
flag_candidate = bytes(decoded)
print(f"Flag candidate: {flag_candidate}")
print(f"Length: {len(flag_candidate)}")

# Verify check 2
if flag_candidate[0] == 0x45 and flag_candidate[1] == 0x48:
    print("Check2 prefix: OK")
    s = sum(flag_candidate)
    print(f"Sum: {s} (need 0xcab={0xcab})")

    indices = [5, 10, 15, 20, 25, 30]
    prod = 1
    for idx in indices:
        prod = (prod * flag_candidate[idx]) % 0x3b9aca07
    print(f"Product mod: {hex(prod)} (need 0x1fb53791)")

# Verify check 3
h = compute_hash(flag_candidate)
print(f"Hash: {hex(h)} (need {hex(target_hash)})")

if h == target_hash:
    print(f"\nFlag: {flag_candidate.decode()}")
    with open("flag.txt", "w") as f:
        f.write(flag_candidate.decode())
else:
    print("\nHash mismatch - need to brute force remaining bytes")
