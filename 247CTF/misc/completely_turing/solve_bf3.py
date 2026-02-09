#!/usr/bin/env python3
"""
Solve the completely_turing Brainfuck challenge.
Focus on the first 20 encrypted values which seem to be the actual data.
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

# The first 20 values appear to be the actual encrypted flag
enc_data = encrypted_values[:20]
print(f"Encrypted data (20 values): {enc_data}")

# The key pattern for "247CTF{" is alternating 8, 5
# Let's apply this pattern to decrypt
print("\n=== Decrypting with alternating 8, 5 pattern ===")

flag = ""
keys_used = []
for i, enc in enumerate(enc_data):
    key_digit = 8 if i % 2 == 0 else 5
    key = 70 + key_digit
    keys_used.append(key_digit)
    decrypted = enc - key
    if 0 <= decrypted < 256:
        char = chr(decrypted)
        flag += char
    else:
        flag += "?"

print(f"Decrypted flag: {flag}")
print(f"Key digits used: {keys_used}")

# This gives us 247CTF{dccadacea434d
# But we need a closing brace. Let's check if position 19 should have different key

print("\n=== Finding key for closing brace ===")
target_closing = ord('}')  # 125
enc_last = enc_data[19]
needed_key = enc_last - target_closing
print(f"Position 19: enc={enc_last}, need '{chr(target_closing)}' ({target_closing})")
print(f"Needed key: {needed_key}")
print(f"As digit (key - 70): {needed_key - 70}")

# The flag seems to only have 12 hex chars if ending with }
# Let's check: 247CTF{ + 12 hex + } = 20 chars
# But standard 247CTF flags have 32 hex chars...

# Maybe the actual flag has shorter hex content?
# Let's see what valid ending we can get

print("\n=== Checking all possible endings ===")
for i in [17, 18, 19]:  # Last few positions
    enc = enc_data[i]
    print(f"Position {i} (enc={enc}):")
    for d in range(10):
        key = 70 + d
        result = enc - key
        if 0 <= result < 127:
            char = chr(result)
            marker = "*" if char == '}' else ""
            print(f"  digit {d}: key={key} -> {result} '{char}' {marker}")

# Let's try a completely different approach - what if each position has its own key
# and the "valid characters" hint means we need to find which digit works for each position
print("\n=== Per-position key search for valid hex flag ===")

def is_valid_flag_char(char, position):
    """Check if char is valid for given position in 247CTF{...} format."""
    expected_prefix = "247CTF{"
    if position < 7:
        return char == expected_prefix[position]
    elif position == 19:  # Assuming 20 char flag with closing brace
        return char == '}'
    else:  # Hex content (0-9, a-f)
        return char in "0123456789abcdef"

print("Searching for valid digit at each position...")
solution_keys = []
for i in range(20):
    enc = enc_data[i]
    found = False
    for d in range(10):
        key = 70 + d
        result = enc - key
        if 0 <= result < 256:
            char = chr(result)
            if is_valid_flag_char(char, i):
                solution_keys.append(d)
                print(f"[{i:2d}] enc={enc:3d} digit={d} -> '{char}' ✓")
                found = True
                break
    if not found:
        solution_keys.append(-1)
        print(f"[{i:2d}] enc={enc:3d} No valid digit found!")

# Build final flag
print("\n=== Final solution ===")
flag = ""
for i in range(20):
    enc = enc_data[i]
    d = solution_keys[i]
    if d >= 0:
        key = 70 + d
        char = chr(enc - key)
        flag += char
    else:
        flag += "?"

print(f"Flag: {flag}")
print(f"Key sequence (digits to enter): {solution_keys}")
