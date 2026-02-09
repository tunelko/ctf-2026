#!/usr/bin/env python3
"""
Solve the completely_turing Brainfuck challenge.
Focus on finding the key pattern.
"""

import re

# Read the Brainfuck code
with open('completely_turing', 'r') as f:
    code = f.read()

# Extract multiplication patterns and any following additions
pattern = r'(\+{1,})\[-<(\+{1,})>\]<(\+*)'
matches = re.findall(pattern, code)

encrypted_values = []
for mult, inc, extra in matches:
    val = len(mult) * len(inc) + len(extra)
    encrypted_values.append(val)

print(f"Total encrypted values: {len(encrypted_values)}")
print(f"First 40 values: {encrypted_values[:40]}")

# Key pattern analysis for "247CTF{"
print("\n=== Key pattern for '247CTF{' ===")
target = "247CTF{"
keys = []
for i, c in enumerate(target):
    enc = encrypted_values[i]
    key = enc - ord(c)
    keys.append(key)
    print(f"  [{i}] enc={enc} - '{c}'({ord(c)}) = key {key} -> digit {key-70}")

print(f"\nKey pattern (base 70 + digit): {[k-70 for k in keys]}")
print(f"Alternating pattern: 8, 5, 8, 5, 8, 5, 8")

# Now let's figure out the full flag
# The flag format is 247CTF{32 hex characters}
print("\n=== Attempting full flag decryption ===")

# First 7 characters use alternating 8, 5 pattern
# Let's see if this continues

def get_key_digit(index):
    """Determine the key digit for a given index."""
    # Pattern seems to alternate 8, 5
    return 8 if index % 2 == 0 else 5

flag = ""
for i in range(40):
    if i >= len(encrypted_values):
        break
    enc = encrypted_values[i]
    key_digit = get_key_digit(i)
    key = 70 + key_digit
    decrypted = enc - key
    if 0 <= decrypted < 256:
        char = chr(decrypted)
        flag += char
        print(f"[{i:2d}] enc={enc:3d} key={key} (digit {key_digit}) -> {decrypted:3d} '{char}'")
    else:
        print(f"[{i:2d}] enc={enc:3d} key={key} (digit {key_digit}) -> {decrypted:3d} (out of range)")

print(f"\nDecrypted so far: {flag}")

# That doesn't look right after position 7
# Let's analyze what happens after the '{'
print("\n=== Alternative: variable key formula ===")

# Maybe the key depends on the index in a different way
# Let's look at what keys would produce valid hex digits

print("\nSearching for keys that produce valid flag characters:")
for i in range(min(40, len(encrypted_values))):
    enc = encrypted_values[i]
    print(f"[{i:2d}] enc={enc:3d}: ", end="")
    valid_options = []
    for digit in range(10):
        key = 70 + digit
        result = enc - key
        if 0 <= result < 127:
            char = chr(result)
            if i < 7:  # First 7 chars should be "247CTF{"
                if char == "247CTF{"[i]:
                    valid_options.append(f"{digit}->'{char}'*")
                else:
                    valid_options.append(f"{digit}->'{char}'")
            elif char in "0123456789abcdef}":
                valid_options.append(f"{digit}->'{char}'*")
            else:
                valid_options.append(f"{digit}->'{char}'")
    print(" | ".join(valid_options[:5]))

# Let's try different key formulas
print("\n=== Trying key formula: key = 70 + (index % some_value) ===")
for mod_val in [2, 3, 4, 5, 6, 7, 8, 9, 10]:
    flag = ""
    valid = True
    for i in range(7):  # Just check first 7 characters
        enc = encrypted_values[i]
        key_digit = i % mod_val
        key = 70 + key_digit
        decrypted = enc - key
        if 0 <= decrypted < 256:
            flag += chr(decrypted)
        else:
            valid = False
            break
    if flag.startswith("247CTF{"):
        print(f"  mod {mod_val}: FOUND! key_digits = {[i % mod_val for i in range(7)]}")
    # else:
    #     print(f"  mod {mod_val}: {flag}")
