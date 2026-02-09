#!/usr/bin/env python3
"""
Solve weak RSA - character-by-character encryption.
Simply compute c^e mod n for all ASCII values and build lookup table.
"""

# Parse the output file
with open('suspicious_caesar_cipher.out', 'r') as f:
    lines = f.read().strip().split('\n')

# Line 0: "Generated key:"
# Line 1: e
# Line 2: n
# Line 3: "Encrypted flag:"
# Line 4: [list of encrypted values]

e = int(lines[1])
n = int(lines[2])

# Parse the encrypted flag list
encrypted_line = lines[4]
# Remove 'L' suffix if present (Python 2 long), brackets, and split
encrypted_str = encrypted_line.strip('[]')
encrypted = [int(x.strip().rstrip('L')) for x in encrypted_str.split(',')]

print(f"e = {e}")
print(f"n = {n}")
print(f"Encrypted values: {len(encrypted)} characters")

# Build lookup table: for each ASCII char, compute c^e mod n
print("\nBuilding lookup table...")
lookup = {}
for c in range(256):
    ct = pow(c, e, n)
    lookup[ct] = chr(c)

# Decrypt
print("Decrypting...")
flag = ""
for ct in encrypted:
    if ct in lookup:
        flag += lookup[ct]
    else:
        flag += "?"
        print(f"Warning: unknown ciphertext {ct}")

print(f"\nFlag: {flag}")
