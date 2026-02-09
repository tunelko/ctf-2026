#!/usr/bin/env python3
"""
Solve the completely_turing Brainfuck challenge.
"""

import re

# Read the Brainfuck code
with open('completely_turing', 'r') as f:
    code = f.read()

# Find all value-setting patterns: N[-<M>]< means N*M
# But we need to also capture patterns with +N after like: N[-<M>]<+P
# Full pattern: +N[-<+M>]<(+P)?
# Also patterns like: +N after a multiplication

# Let's be more precise - look for the encrypted array initialization
# Pattern: >[-]>[-]>[-]+++++++[-<++++++++++++++++>]<
# This sets a value of multiplier * count, possibly with additions

# Find all sequences that set up the encrypted values
# Looking for pattern: N+[-<M+>]< which computes N*M
# Sometimes followed by additional + signs

print("=== Analyzing Brainfuck encryption ===\n")

# Extract multiplication patterns and any following additions
pattern = r'(\+{1,})\[-<(\+{1,})>\]<(\+*)'
matches = re.findall(pattern, code)

encrypted_values = []
for mult, inc, extra in matches[:50]:  # Get first 50 values
    val = len(mult) * len(inc) + len(extra)
    encrypted_values.append(val)

print(f"Encrypted values ({len(encrypted_values)} found):")
print(encrypted_values[:40])

# Now let's determine the keys
# Assuming the key formula: actual_key = base + input_digit
# where input_digit is 0-9 and base might be position-dependent

# For "247CTF{..." we need:
target_start = "247CTF{32"  # Start of typical 247CTF flag format
print(f"\nTarget: {target_start}")
print(f"Target ASCII: {[ord(c) for c in target_start]}")

print("\n=== Calculating required keys ===")
keys = []
for i, enc in enumerate(encrypted_values[:len(target_start)]):
    if i < len(target_start):
        target_char = ord(target_start[i])
        key = enc - target_char
        keys.append(key)
        digit = key % 10 if key >= 0 else None
        print(f"  pos[{i}]: enc={enc} - target={target_char}('{target_start[i]}') = key {key} (digit: {digit})")

# Check if keys follow a pattern of 70 + digit
print("\n=== Checking key = 70 + digit pattern ===")
base = 70
for i, key in enumerate(keys):
    digit = key - base
    if 0 <= digit <= 9:
        print(f"  pos[{i}]: key={key} = {base} + {digit}")
    else:
        # Try other bases
        for b in [70, 71, 72, 73, 74, 75]:
            d = key - b
            if 0 <= d <= 9:
                print(f"  pos[{i}]: key={key} = {b} + {d}")
                break

# Let's verify with actual flag format
# Try to decrypt with the pattern
print("\n=== Attempting decryption with known flag format ===")
# We know the flag is 247CTF{32 hex chars}
# Let's try decrypting assuming key = 70 + i where i is position-dependent

# Actually, let me check what the actual key sequence looks like
print("\n=== Raw key sequence ===")
for i in range(min(20, len(encrypted_values))):
    enc = encrypted_values[i]
    for key in range(40, 90):
        result = enc - key
        if 32 <= result < 127:
            print(f"  enc[{i}]={enc}: key={key} -> {result} '{chr(result)}'", end="")
            if chr(result) in "0123456789abcdefABCDEF{}247CTF":
                print(" <-- valid flag char")
            else:
                print()
            break

# Let's try a different approach - brute force the key digits
print("\n=== Brute forcing key digits ===")
print("Assuming key = 70 + digit for each position")

result_chars = []
key_digits = []
for i, enc in enumerate(encrypted_values[:40]):
    found = False
    for digit in range(10):
        key = 70 + digit
        result = enc - key
        if 0 <= result < 256:
            char = chr(result)
            # Check if this could be a valid flag character
            if i < 7:  # "247CTF{"
                expected = "247CTF{"[i]
                if char == expected:
                    result_chars.append(char)
                    key_digits.append(digit)
                    found = True
                    break
            else:  # After '{', should be hex digit, and '}' at end
                if char in "0123456789abcdef}":
                    result_chars.append(char)
                    key_digits.append(digit)
                    found = True
                    break
    if not found:
        # Try all digits and see what we get
        for digit in range(10):
            key = 70 + digit
            result = enc - key
            if 0 <= result < 256:
                char = chr(result)
                if char.isprintable():
                    result_chars.append(f"[{char}?]")
                    key_digits.append(f"{digit}?")
                    break

print(f"\nDecrypted flag attempt: {''.join(str(c) for c in result_chars)}")
print(f"Key digits: {key_digits}")

# Let's try XOR decryption as well
print("\n=== Trying XOR decryption ===")
for base_key in [70, 80, 90, 100]:
    result = []
    for i, enc in enumerate(encrypted_values[:7]):
        target = ord("247CTF{"[i])
        key = enc ^ target
        result.append(key)
    print(f"Base consideration - XOR keys for '247CTF{{': {result}")
