#!/usr/bin/env python3
"""
State Reconstruction using Z3 SMT solver
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

# Create Z3 variables for each bit
S_bits = [Bool(f's_{i}') for i in range(STATE_SIZE)]

solver = Solver()

# Add constraints for each rotation equation
# Using ROTL: S[i] XOR S[(i+k) mod n] = result[i]
for k, result_int in states.items():
    result_bits = int_to_bits(result_int)
    for i in range(STATE_SIZE):
        lhs = Xor(S_bits[i], S_bits[(i + k) % STATE_SIZE])
        # Convert Python int to Z3 Bool
        rhs = BoolVal(bool(result_bits[i]))
        solver.add(lhs == rhs)

print(f"Solving system with {len(states) * STATE_SIZE} constraints...")

if solver.check() == sat:
    print("✓ Solution found!\n")
    model = solver.model()

    # Extract solution
    solution = []
    for i in range(STATE_SIZE):
        val = model.evaluate(S_bits[i])
        solution.append(1 if val else 0)

    S = bits_to_int(solution)
    print(f"State S: {S}")
    print(f"State S (hex): {S:032x}")

    # Verify solution
    print("\n=== Verification ===")
    S_list = solution
    all_correct = True

    for k, expected in states.items():
        # ROTL: rotate left by k
        rotated = [S_list[(i + k) % STATE_SIZE] for i in range(STATE_SIZE)]
        xor_result = [S_list[i] ^ rotated[i] for i in range(STATE_SIZE)]
        computed = bits_to_int(xor_result)

        match = computed == expected
        print(f"k={k:2d}: {'✓' if match else '✗'} (expected {expected}, got {computed})")
        all_correct = all_correct and match

    if all_correct:
        print("\n✓ All equations verified!")

        # Try decryption
        print("\n=== Decryption Attempts ===")

        for endian in ['little', 'big']:
            key_bytes = S.to_bytes(16, endian)

            # AES-ECB
            try:
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                plaintext = cipher.decrypt(ciphertext)
                print(f"\nAES-ECB ({endian}): {plaintext}")
                if b'CTF' in plaintext or b'flag' in plaintext or b'prgy' in plaintext or b'247' in plaintext:
                    print(f"🚩 FLAG: {plaintext.decode(errors='ignore')}")
            except Exception as e:
                print(f"AES-ECB ({endian}): {e}")

            # XOR
            xor_result = bytes([ciphertext[i] ^ key_bytes[i] for i in range(16)])
            print(f"XOR ({endian}): {xor_result}")
            if b'CTF' in xor_result or b'flag' in xor_result or b'prgy' in xor_result:
                print(f"🚩 FLAG: {xor_result.decode(errors='ignore')}")
    else:
        print("\n✗ Verification failed!")
else:
    print("✗ No solution found!")
