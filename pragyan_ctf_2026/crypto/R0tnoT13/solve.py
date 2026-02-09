#!/usr/bin/env python3
"""
State Reconstruction from Rotation XOR values

Given: S ⊕ ROTR(S, k) for various k values
Goal: Reconstruct S (128-bit state)

This is a system of linear equations over GF(2).
For each bit position i:
    result[i] = S[i] ⊕ S[(i-k) mod 128]

We can represent this as a matrix equation: A * S = b (mod 2)
"""
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long

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

print("=== Challenge Data ===")
print(f"Rotation offsets: {sorted(states.keys())}")
print(f"Ciphertext: {ciphertext.hex()}")
print(f"Number of equations: {len(states)}")

# Build the linear system over GF(2)
STATE_SIZE = 128

def int_to_bits(n, size=STATE_SIZE):
    """Convert integer to bit array (LSB first)"""
    return [(n >> i) & 1 for i in range(size)]

def bits_to_int(bits):
    """Convert bit array to integer (LSB first)"""
    return sum(b << i for i, b in enumerate(bits))

def rotr(bits, k):
    """Rotate right by k positions
    ROTR moves bit at position i to position (i-k) mod n
    Or equivalently: ROTR[i] = S[(i+k) mod n]
    """
    k = k % len(bits)
    return bits[-k:] + bits[:-k] if k > 0 else bits

# Build matrix A and vector b
# Each equation S ⊕ ROTR(S, k) = result gives us 128 equations
equations = []
results = []

for k, result_int in states.items():
    result_bits = int_to_bits(result_int)

    # For each bit position i:
    # result[i] = S[i] ⊕ ROTR(S, k)[i]
    # ROTR(S, k)[i] = S[(i+k) mod 128]
    # So: result[i] = S[i] ⊕ S[(i+k) mod 128]

    for i in range(STATE_SIZE):
        equation = [0] * STATE_SIZE
        equation[i] = 1  # S[i]
        equation[(i + k) % STATE_SIZE] ^= 1  # ⊕ S[(i+k) mod 128]

        equations.append(equation)
        results.append(result_bits[i])

# Convert to numpy arrays
A = np.array(equations, dtype=np.uint8)
b = np.array(results, dtype=np.uint8)

print(f"\n=== Linear System ===")
print(f"Matrix A: {A.shape}")
print(f"Vector b: {b.shape}")
print(f"System: A * S = b (mod 2)")

# Solve using Gaussian elimination over GF(2)
def gauss_gf2(A, b):
    """Gaussian elimination over GF(2)"""
    A = A.copy()
    b = b.copy()
    m, n = A.shape

    # Augment matrix
    Ab = np.column_stack([A, b])

    # Forward elimination
    pivot_row = 0
    pivot_cols = []

    for col in range(n):
        # Find pivot
        found = False
        for row in range(pivot_row, m):
            if Ab[row, col] == 1:
                # Swap rows
                if row != pivot_row:
                    Ab[[pivot_row, row]] = Ab[[row, pivot_row]]
                found = True
                break

        if not found:
            continue

        pivot_cols.append(col)

        # Eliminate
        for row in range(m):
            if row != pivot_row and Ab[row, col] == 1:
                Ab[row] = (Ab[row] + Ab[pivot_row]) % 2

        pivot_row += 1

    # Back substitution
    solution = np.zeros(n, dtype=np.uint8)

    for i in range(len(pivot_cols) - 1, -1, -1):
        col = pivot_cols[i]
        # Find the row with pivot in this column
        for row in range(m):
            if Ab[row, col] == 1:
                # solution[col] = Ab[row, -1] - sum of other terms
                val = Ab[row, -1]
                for j in range(col + 1, n):
                    val = (val + Ab[row, j] * solution[j]) % 2
                solution[col] = val
                break

    return solution, pivot_cols

print("\n=== Solving system ===")
solution, pivot_cols = gauss_gf2(A, b)

print(f"Pivot columns: {len(pivot_cols)}")
print(f"Free variables: {STATE_SIZE - len(pivot_cols)}")

# Convert solution to integer
S = bits_to_int(solution)
print(f"\n=== Solution ===")
print(f"State S: {S}")
print(f"State S (hex): {S:032x}")

# Verify solution
print("\n=== Verification ===")
all_correct = True
for k, expected in states.items():
    S_bits = int_to_bits(S)
    rotated = rotr(S_bits, k)
    xor_result = [S_bits[i] ^ rotated[i] for i in range(STATE_SIZE)]
    computed = bits_to_int(xor_result)

    match = computed == expected
    print(f"k={k:2d}: {'✓' if match else '✗'} (expected {expected}, got {computed})")
    all_correct = all_correct and match

if all_correct:
    print("\n✓ All equations verified!")
else:
    print("\n✗ Some equations don't match - may need to try different solution")

# Try to decrypt ciphertext
print("\n=== Decryption Attempt ===")

# The state is 128-bit, which is perfect for AES key
key = long_to_bytes(S, 16)
print(f"Key: {key.hex()}")

try:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Plaintext: {plaintext}")
    print(f"Plaintext (hex): {plaintext.hex()}")

    # Check if it looks like a flag
    if b'CTF' in plaintext or b'flag' in plaintext or b'prgy' in plaintext or b'247' in plaintext:
        print(f"\n🚩 FLAG: {plaintext.decode(errors='ignore')}")
except Exception as e:
    print(f"Decryption error: {e}")

# If that doesn't work, try XOR decryption (stream cipher)
print("\n=== Alternative: XOR Stream Cipher ===")
key_bytes = long_to_bytes(S, 16)
xor_result = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
print(f"XOR result: {xor_result}")
print(f"XOR result (hex): {xor_result.hex()}")

if b'CTF' in xor_result or b'flag' in xor_result or b'prgy' in xor_result:
    print(f"\n🚩 FLAG: {xor_result.decode(errors='ignore')}")
