#!/usr/bin/env python3
"""
Find ALL solutions by trying all combinations of free variables
"""
from z3 import *
from Crypto.Cipher import AES

# Parse challenge data
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

# Find all solutions
solutions = []

for sol_num in range(10):  # Try to find up to 10 solutions
    S_bits = [Bool(f's_{i}_{sol_num}') for i in range(STATE_SIZE)]
    solver = Solver()

    # Add constraints
    for k, result_int in states.items():
        result_bits = int_to_bits(result_int)
        for i in range(STATE_SIZE):
            lhs = Xor(S_bits[i], S_bits[(i + k) % STATE_SIZE])
            rhs = BoolVal(bool(result_bits[i]))
            solver.add(lhs == rhs)

    # Exclude previous solutions
    for prev_S in solutions:
        prev_bits = int_to_bits(prev_S)
        # At least one bit must be different
        diff_constraint = Or([S_bits[i] != BoolVal(bool(prev_bits[i])) for i in range(STATE_SIZE)])
        solver.add(diff_constraint)

    if solver.check() == sat:
        model = solver.model()
        solution = []
        for i in range(STATE_SIZE):
            val = model.evaluate(S_bits[i])
            solution.append(1 if val else 0)

        S = bits_to_int(solution)
        solutions.append(S)
        print(f"\n=== Solution {len(solutions)} ===")
        print(f"S = {S}")
        print(f"S (hex) = {S:032x}")

        # Verify
        S_list = solution
        valid = True
        for k, expected in states.items():
            rotated = [S_list[(i + k) % STATE_SIZE] for i in range(STATE_SIZE)]
            xor_result = [S_list[i] ^ rotated[i] for i in range(STATE_SIZE)]
            computed = bits_to_int(xor_result)
            if computed != expected:
                valid = False
                print(f"  ✗ k={k} verification failed!")
                break

        if valid:
            print(f"  ✓ All equations verified!")

            # Try decryptions
            for endian in ['big', 'little']:
                key_bytes = S.to_bytes(16, endian)

                # AES-ECB
                try:
                    cipher = AES.new(key_bytes, AES.MODE_ECB)
                    plaintext = cipher.decrypt(ciphertext)
                    if plaintext.isprintable() or b'CTF' in plaintext or b'ctf' in plaintext:
                        print(f"  AES-ECB ({endian}): {plaintext}")
                except:
                    pass

                # XOR
                xor_result = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
                if all(32 <= b < 127 or b in [10, 13] for b in xor_result):
                    print(f"  XOR ({endian}): {xor_result}")
    else:
        break

print(f"\n\nTotal solutions found: {len(solutions)}")
