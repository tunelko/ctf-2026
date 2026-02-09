#!/usr/bin/env python3
"""
State Reconstruction - Try all solutions for free variables
"""
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from itertools import product

# Parse challenge data
states = {}
with open('challenge.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line.strip()
        if line and line[0].isdigit():
            parts = line.split()
            if len(parts) == 2:
                k = int(parts[0])
                value = int(parts[1])
                states[k] = value

ciphertext = bytes.fromhex("477eb79b46ef667f16ddd94ca933c7c0")

STATE_SIZE = 128

def int_to_bits(n, size=STATE_SIZE):
    return [(n >> i) & 1 for i in range(size)]

def bits_to_int(bits):
    return sum(b << i for i, b in enumerate(bits))

# Build linear system
# ROTR(S, k)[i] = S[(i-k) mod n]
# So: result[i] = S[i] XOR S[(i-k) mod n]
equations = []
results = []

for k, result_int in states.items():
    result_bits = int_to_bits(result_int)
    for i in range(STATE_SIZE):
        equation = [0] * STATE_SIZE
        equation[i] = 1  # S[i]
        equation[(i - k) % STATE_SIZE] ^= 1  # XOR S[(i-k) mod n]
        equations.append(equation)
        results.append(result_bits[i])

A = np.array(equations, dtype=np.uint8)
b = np.array(results, dtype=np.uint8)

print(f"System: {A.shape[0]} equations, {A.shape[1]} variables")

# Gaussian elimination to find free variables
def gauss_gf2_with_free(A, b):
    """Returns solution with free variables and their positions"""
    A = A.copy()
    b = b.copy()
    m, n = A.shape

    Ab = np.column_stack([A, b])
    pivot_row = 0
    pivot_cols = []

    for col in range(n):
        found = False
        for row in range(pivot_row, m):
            if Ab[row, col] == 1:
                if row != pivot_row:
                    Ab[[pivot_row, row]] = Ab[[row, pivot_row]]
                found = True
                break

        if not found:
            continue

        pivot_cols.append(col)

        for row in range(m):
            if row != pivot_row and Ab[row, col] == 1:
                Ab[row] = (Ab[row] + Ab[pivot_row]) % 2

        pivot_row += 1

    # Find free variables
    free_vars = [i for i in range(n) if i not in pivot_cols]

    return Ab, pivot_cols, free_vars

Ab_reduced, pivot_cols, free_vars = gauss_gf2_with_free(A, b)

print(f"Pivot columns: {len(pivot_cols)}")
print(f"Free variables: {free_vars}")

# Generate all solutions by trying all combinations of free variables
def get_solution(Ab, pivot_cols, free_vars, free_values):
    """Get solution for specific values of free variables"""
    n = Ab.shape[1] - 1
    solution = np.zeros(n, dtype=np.uint8)

    # Set free variables
    for i, var_idx in enumerate(free_vars):
        solution[var_idx] = free_values[i]

    # Solve for dependent variables
    for i in range(len(pivot_cols) - 1, -1, -1):
        col = pivot_cols[i]
        # Find row with pivot
        for row in range(Ab.shape[0]):
            if Ab[row, col] == 1:
                val = Ab[row, -1]
                for j in range(col + 1, n):
                    val = (val + Ab[row, j] * solution[j]) % 2
                solution[col] = val
                break

    return solution

# Verify a solution
def verify_solution(S_bits):
    S = bits_to_int(S_bits)
    S_list = list(S_bits) if isinstance(S_bits, np.ndarray) else S_bits

    for k, expected in states.items():
        # ROTR: rotate right by k
        # ROTR(S, k)[i] = S[(i-k) mod n]
        rotated = [S_list[(i - k) % STATE_SIZE] for i in range(STATE_SIZE)]
        xor_result = [S_list[i] ^ rotated[i] for i in range(STATE_SIZE)]
        computed = bits_to_int(xor_result)
        if computed != expected:
            return False, S
    return True, S

print(f"\n=== Trying all {2**len(free_vars)} possible solutions ===\n")

valid_solutions = []

for free_combo in product([0, 1], repeat=len(free_vars)):
    solution = get_solution(Ab_reduced, pivot_cols, free_vars, free_combo)
    valid, S = verify_solution(solution)

    if valid:
        print(f"✓ Valid solution found!")
        print(f"  Free variables: {dict(zip(free_vars, free_combo))}")
        print(f"  S = {S}")
        print(f"  S (hex) = {S:032x}")
        valid_solutions.append(S)

        # Try to decrypt
        print(f"\n  Attempting decryption...")

        # Method 1: AES ECB
        try:
            key_bytes = S.to_bytes(16, 'little')
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)
            print(f"    AES-ECB (little-endian): {plaintext}")
            if b'CTF' in plaintext or b'flag' in plaintext or b'prgy' in plaintext:
                print(f"    🚩 FLAG: {plaintext.decode(errors='ignore')}")
        except:
            pass

        try:
            key_bytes = S.to_bytes(16, 'big')
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)
            print(f"    AES-ECB (big-endian): {plaintext}")
            if b'CTF' in plaintext or b'flag' in plaintext or b'prgy' in plaintext:
                print(f"    🚩 FLAG: {plaintext.decode(errors='ignore')}")
        except:
            pass

        # Method 2: XOR
        key_bytes = S.to_bytes(16, 'little')
        xor_result = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
        print(f"    XOR (little-endian): {xor_result}")
        if b'CTF' in xor_result or b'flag' in xor_result or b'prgy' in xor_result:
            print(f"    🚩 FLAG: {xor_result.decode(errors='ignore')}")

        key_bytes = S.to_bytes(16, 'big')
        xor_result = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
        print(f"    XOR (big-endian): {xor_result}")
        if b'CTF' in xor_result or b'flag' in xor_result or b'prgy' in xor_result:
            print(f"    🚩 FLAG: {xor_result.decode(errors='ignore')}")

        print()

if not valid_solutions:
    print("✗ No valid solutions found!")
else:
    print(f"\nTotal valid solutions: {len(valid_solutions)}")
