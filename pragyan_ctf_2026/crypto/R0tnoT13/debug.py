#!/usr/bin/env python3
"""Debug the system"""
import numpy as np

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

STATE_SIZE = 128

def int_to_bits(n, size=STATE_SIZE):
    return [(n >> i) & 1 for i in range(size)]

def bits_to_int(bits):
    return sum(b << i for i, b in enumerate(bits))

# Build linear system
equations = []
results = []

for k, result_int in states.items():
    result_bits = int_to_bits(result_int)
    for i in range(STATE_SIZE):
        equation = [0] * STATE_SIZE
        equation[i] = 1
        equation[(i - k) % STATE_SIZE] ^= 1
        equations.append(equation)
        results.append(result_bits[i])

A = np.array(equations, dtype=np.uint8)
b = np.array(results, dtype=np.uint8)

print(f"Matrix A shape: {A.shape}")
print(f"Vector b shape: {b.shape}")

# Check if system is consistent
# Compute rank of A and rank of [A|b]
def rank_gf2(M):
    M = M.copy()
    m, n = M.shape
    rank = 0

    for col in range(n):
        # Find pivot
        found = False
        for row in range(rank, m):
            if M[row, col] == 1:
                if row != rank:
                    M[[rank, row]] = M[[row, rank]]
                found = True
                break

        if not found:
            continue

        # Eliminate
        for row in range(m):
            if row != rank and M[row, col] == 1:
                M[row] = (M[row] + M[rank]) % 2

        rank += 1

    return rank

rank_A = rank_gf2(A)
rank_Ab = rank_gf2(np.column_stack([A, b]))

print(f"\nRank of A: {rank_A}")
print(f"Rank of [A|b]: {rank_Ab}")

if rank_A != rank_Ab:
    print("✗ System is INCONSISTENT! No solution exists.")
else:
    print(f"✓ System is consistent")
    print(f"  Free variables: {STATE_SIZE - rank_A}")

# Let me also check the first equation manually
k = 2
result_int = states[k]
result_bits = int_to_bits(result_int)

print(f"\n=== Checking first equation (k={k}) ===")
print(f"Result value: {result_int}")
print(f"First 10 result bits: {result_bits[:10]}")

# For i=0: S[0] XOR S[(0-2) mod 128] = S[0] XOR S[126]
print(f"\nEquation for bit 0: S[0] XOR S[126] = {result_bits[0]}")
print(f"Equation for bit 1: S[1] XOR S[127] = {result_bits[1]}")
print(f"Equation for bit 2: S[2] XOR S[0] = {result_bits[2]}")

# Check what our matrix looks like for first equation
print(f"\nFirst row of A: {A[0]}")
print(f"  Non-zero positions: {np.where(A[0] == 1)[0].tolist()}")
print(f"  Expected: [0, 126]")
print(f"  b[0] = {b[0]}, expected {result_bits[0]}")

