#!/usr/bin/env python3
"""
Solver for 247CTF 'completely_turing' Brainfuck challenge.

Challenge: "We encoded the flag in a terse, but Turing complete programming language.
Can you identify the valid characters required to extract the flag?"

Analysis:
- The Brainfuck code stores encrypted flag characters using multiplication patterns
- Pattern: +N[-<+M>]<+P computes the value N*M+P
- Encryption formula: encrypted[i] = plaintext[i] + key[i]
- Key formula: key = 70 + digit, where digit alternates between 8 and 5
- The "valid characters" are digits 8 and 5, alternating for each position

Flag format: 247CTF{32 hex characters} = 40 total characters
"""

import re

def solve():
    # Read the Brainfuck code
    with open('completely_turing', 'r') as f:
        code = f.read()

    # Extract multiplication patterns: +N[-<+M>]<+P computes N*M+P
    pattern = r'(\+{1,})\[-<(\+{1,})>\]<(\+*)'
    matches = re.findall(pattern, code)

    # Calculate all values
    all_values = []
    for mult, inc, extra in matches:
        val = len(mult) * len(inc) + len(extra)
        all_values.append(val)

    # Filter to encrypted characters (values > 40, since ASCII printable starts at 32)
    # and take first 40 for the flag length
    encrypted = [v for v in all_values if v > 40][:40]

    # Decrypt using alternating key pattern
    # Key = 70 + digit, where digit = 8 for even positions, 5 for odd positions
    flag = ''
    key_digits = []

    for i, enc in enumerate(encrypted):
        digit = 8 if i % 2 == 0 else 5
        key = 70 + digit
        plaintext = enc - key
        flag += chr(plaintext)
        key_digits.append(digit)

    return flag, key_digits

if __name__ == '__main__':
    flag, keys = solve()
    print(f"Flag: {flag}")
    print(f"Key pattern (valid characters): alternating {keys[0]}, {keys[1]}")
    print(f"Full key sequence: {''.join(map(str, keys))}")
