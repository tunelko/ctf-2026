#!/usr/bin/env python3
"""
Solve completely_turing - assuming 40 character flag format.
247CTF{32 hex chars} = 40 total characters
"""

import re

# Read the Brainfuck code
with open('completely_turing', 'r') as f:
    code = f.read()

# Extract ALL multiplication patterns
pattern = r'(\+{1,})\[-<(\+{1,})>\]<(\+*)'
matches = re.findall(pattern, code)

all_values = []
for mult, inc, extra in matches:
    val = len(mult) * len(inc) + len(extra)
    all_values.append(val)

print(f"Total values extracted: {len(all_values)}")
print(f"All values: {all_values}\n")

# Filter out small values (indices) - encrypted chars should be > 40
encrypted_values = [v for v in all_values if v > 40]
print(f"Encrypted values (>40): {encrypted_values}")
print(f"Count: {len(encrypted_values)}\n")

# Also extract values <= 40 separately (might be indices or small keys)
index_values = [v for v in all_values if v <= 40]
print(f"Small values (<=40, likely indices): {index_values[:30]}...\n")

# Now let's try to decrypt assuming different patterns
print("=== Attempting decryption ===\n")

# Method 1: Alternating 8,5 pattern with all encrypted values
print("Method 1: Alternating 8,5 on filtered encrypted values")
flag = ""
for i, enc in enumerate(encrypted_values[:40]):
    digit = 8 if i % 2 == 0 else 5
    key = 70 + digit
    result = enc - key
    if 0 <= result < 127:
        flag += chr(result)
    else:
        flag += "?"
print(f"Result: {flag}\n")

# Method 2: Sequential digits 0-9 repeating
print("Method 2: Sequential digits (i % 10)")
flag = ""
for i, enc in enumerate(encrypted_values[:40]):
    digit = i % 10
    key = 70 + digit
    result = enc - key
    if 0 <= result < 127:
        flag += chr(result)
    else:
        flag += "?"
print(f"Result: {flag}\n")

# Method 3: Find what digits produce valid flag chars for each position
print("Method 3: Per-position digit search")

def is_valid(char, pos):
    prefix = "247CTF{"
    if pos < 7:
        return char == prefix[pos]
    elif pos == 39:  # Closing brace for 40-char flag
        return char == '}'
    else:
        return char in "0123456789abcdef"

solution = []
for i in range(min(40, len(encrypted_values))):
    enc = encrypted_values[i]
    found = False
    for d in range(10):
        key = 70 + d
        result = enc - key
        if 0 <= result < 127:
            char = chr(result)
            if is_valid(char, i):
                solution.append((d, char))
                found = True
                break
    if not found:
        # Try without base 70
        for d in range(256):
            result = enc - d
            if 0 <= result < 127:
                char = chr(result)
                if is_valid(char, i):
                    solution.append((f"raw:{d}", char))
                    found = True
                    break
        if not found:
            solution.append((None, "?"))

print("Solution per position:")
flag = ""
digits = []
for i, (d, c) in enumerate(solution):
    print(f"  [{i:2d}] digit={d} -> '{c}'")
    flag += c
    digits.append(d)

print(f"\nFlag: {flag}")
print(f"Digits: {digits}")

# Check if there are exactly 40 encrypted values
print(f"\n=== Checking for 40 values ===")
print(f"Need 40, have {len(encrypted_values)}")

# Maybe the pattern uses the unfiltered values differently
# Let's look at the pattern more carefully
print("\n=== Analyzing value pattern ===")
for i in range(min(50, len(all_values))):
    v = all_values[i]
    marker = ""
    if v > 40:
        marker = " <-- encrypted"
    elif v < 40:
        marker = f" <-- small ({v})"
    print(f"[{i:2d}] value={v:3d}{marker}")
