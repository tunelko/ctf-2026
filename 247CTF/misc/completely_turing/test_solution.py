#!/usr/bin/env python3
"""
Test the solution for completely_turing by running the Brainfuck interpreter.
"""

import subprocess

# The key pattern is alternating 8, 5
# 40 characters means 40 keys
keys = []
for i in range(40):
    keys.append(8 if i % 2 == 0 else 5)

# Create input for the BF program
# Each key is entered as a single digit followed by newline
input_data = "\n".join(str(k) for k in keys) + "\n"

print("Key sequence:", keys)
print(f"Input data ({len(input_data)} bytes):")
print(repr(input_data[:50]) + "...")

# Run the BF interpreter
try:
    result = subprocess.run(
        ['/tmp/bf2', 'completely_turing'],
        input=input_data,
        capture_output=True,
        text=True,
        timeout=30
    )
    print("\n=== Stdout ===")
    print(result.stdout)
    print("\n=== Stderr ===")
    print(result.stderr)
except subprocess.TimeoutExpired:
    print("Timeout!")
except Exception as e:
    print(f"Error: {e}")
