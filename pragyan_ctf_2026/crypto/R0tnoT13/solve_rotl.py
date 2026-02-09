#!/usr/bin/env python3
"""Try with ROTL instead of ROTR"""
import numpy as np
from Crypto.Cipher import AES
from itertools import product

states = {}
with open('challenge.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if line and line[0].isdigit():
            parts = line.split()
            if len(parts) == 2:
                states[int(parts[0])] = int(parts[1])

ciphertext = bytes.fromhex("477eb79b46ef667f16ddd94ca933c7c0")

STATE_SIZE = 128

def int_to_bits(n, size=STATE_SIZE):
    return [(n >> i) & 1 for i in range(size)]

def bits_to_int(bits):
    return sum(b << i for i, b in enumerate(bits))

# Try ROTL: ROTL(S, k)[i] = S[(i-k) mod n]
# No wait, ROTL rotates LEFT, so ROTL(S, k)[i] = S[(i+k) mod n]
equations = []
results = []

for k, result_int in states.items():
    result_bits = int_to_bits(result_int)
    for i in range(STATE_SIZE):
        equation = [0] * STATE_SIZE
        equation[i] = 1
        equation[(i + k) % STATE_SIZE] ^= 1  # ROTL
        equations.append(equation)
        results.append(result_bits[i])

A = np.array(equations, dtype=np.uint8)
b = np.array(results, dtype=np.uint8)

# Check consistency
def rank_gf2(M):
    M = M.copy()
    m, n = M.shape
    rank = 0
    for col in range(n):
        found = False
        for row in range(rank, m):
            if M[row, col] == 1:
                if row != rank:
                    M[[rank, row]] = M[[row, rank]]
                found = True
                break
        if not found:
            continue
        for row in range(m):
            if row != rank and M[row, col] == 1:
                M[row] = (M[row] + M[rank]) % 2
        rank += 1
    return rank

rank_A = rank_gf2(A)
rank_Ab = rank_gf2(np.column_stack([A, b]))

print(f"ROTL interpretation:")
print(f"  Rank A: {rank_A}")
print(f"  Rank [A|b]: {rank_Ab}")

if rank_A != rank_Ab:
    print(f"  ✗ INCONSISTENT")
else:
    print(f"  ✓ CONSISTENT! Free variables: {STATE_SIZE - rank_A}")

    # Solve it
    from solve_v2 import gauss_gf2_with_free, get_solution

    Ab_reduced, pivot_cols, free_vars = gauss_gf2_with_free(A, b)
    print(f"\n  Free variables: {free_vars}")

    # Try all combinations
    print(f"\n  Trying all {2**len(free_vars)} solutions...")

    for free_combo in product([0, 1], repeat=len(free_vars)):
        solution = get_solution(Ab_reduced, pivot_cols, free_vars, free_combo)

        # Verify with ROTL
        S = bits_to_int(solution)
        S_list = list(solution)

        valid = True
        for k, expected in states.items():
            # ROTL(S, k)[i] = S[(i+k) mod n]
            rotated = [S_list[(i + k) % STATE_SIZE] for i in range(STATE_SIZE)]
            xor_result = [S_list[i] ^ rotated[i] for i in range(STATE_SIZE)]
            computed = bits_to_int(xor_result)
            if computed != expected:
                valid = False
                break

        if valid:
            print(f"\n  ✓ Valid solution: S = {S}")
            print(f"    Hex: {S:032x}")

            # Try decryption
            for endian in ['little', 'big']:
                key_bytes = S.to_bytes(16, endian)
                print(f"\n    AES-ECB ({endian}):")
                try:
                    cipher = AES.new(key_bytes, AES.MODE_ECB)
                    plaintext = cipher.decrypt(ciphertext)
                    print(f"      {plaintext}")
                    if b'CTF' in plaintext or b'flag' in plaintext or b'prgy' in plaintext:
                        print(f"      🚩 FLAG: {plaintext.decode(errors='ignore')}")
                except Exception as e:
                    print(f"      Error: {e}")

                print(f"    XOR ({endian}):")
                xor_result = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
                print(f"      {xor_result}")
                if b'CTF' in xor_result or b'flag' in xor_result or b'prgy' in xor_result:
                    print(f"      🚩 FLAG: {xor_result.decode(errors='ignore')}")

