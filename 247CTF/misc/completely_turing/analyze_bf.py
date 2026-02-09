#!/usr/bin/env python3
"""
Analyze the completely_turing Brainfuck challenge.
Extract hardcoded encrypted values and determine the key scheme.
"""

import re

# Read the Brainfuck code
with open('completely_turing', 'r') as f:
    code = f.read()

# Pattern to find initialization sequences like:
# ++++++++[-<++++++++++++++++>]<
# This calculates multiplier * loops = value
pattern = r'\+{2,}\[-<\+{2,}>\]<'

# Find all multiplication patterns and calculate values
print("=== Extracting hardcoded encrypted values ===\n")

# Let's trace through the code more carefully
# The pattern for setting a cell value is: >[-]>[-]>[-]+++++++[-<++++++++++++++++>]<
# This means: clear cells, then multiply loops * increments

# Find all value-setting patterns
value_patterns = re.findall(r'(\+{1,})\[-<(\+{1,})>\]<', code[:5000])

print("Found multiplication patterns (multiplier * count):")
encrypted_values = []
for i, (mult, inc) in enumerate(value_patterns[:40]):
    val = len(mult) * len(inc)
    encrypted_values.append(val)
    print(f"  Position {i}: {len(mult)} * {len(inc)} = {val} ('{chr(val) if 32 <= val < 127 else '?'}')")

print(f"\n=== Total encrypted values found: {len(encrypted_values)} ===\n")

# The flag format is 247CTF{...}
target = "247CTF{"
print("Target flag prefix:", target)
print("Target ASCII:", [ord(c) for c in target])

# Calculate what keys would be needed
print("\n=== Key analysis ===")
for i, (enc, t) in enumerate(zip(encrypted_values, target)):
    key_sub = enc - ord(t)  # if enc - key = target
    key_xor = enc ^ ord(t)  # if enc XOR key = target
    print(f"  pos[{i}]: enc={enc} target={ord(t)}('{t}') key_sub={key_sub} key_xor={key_xor}")

# Check for patterns in required keys
print("\n=== Looking for key patterns ===")
if len(encrypted_values) >= 7:
    keys_sub = [encrypted_values[i] - ord(target[i]) for i in range(min(7, len(encrypted_values)))]
    print(f"Keys by subtraction: {keys_sub}")

    # Check if keys follow index pattern
    print(f"Keys mod 10: {[k % 10 for k in keys_sub]}")

    # Check differences between consecutive keys
    diffs = [keys_sub[i+1] - keys_sub[i] for i in range(len(keys_sub)-1)]
    print(f"Key differences: {diffs}")

# Now let's look for index-based patterns in the code
print("\n=== Looking for key[i] = f(index) patterns ===")
for i in range(min(10, len(encrypted_values))):
    enc = encrypted_values[i]
    # Try different formulas
    for key in range(0, 100):
        result = enc - key
        if result == ord("247CTF{}"[i] if i < 8 else 0):
            print(f"  Index {i}: key={key} produces '{chr(result)}'")
            break
