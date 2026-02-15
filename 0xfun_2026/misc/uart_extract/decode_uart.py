#!/usr/bin/env python3
"""
Decode UART signal from Sigrok capture (.sr)
- Sample rate: 1 MHz
- 1 channel
- Format: 1 byte per sample (0x00=LOW, 0x01=HIGH)
"""

import zipfile
import os

# Extract data from capture
with zipfile.ZipFile('/home/ubuntu/0xfun/ctf/challenges/misc/uart.sr', 'r') as z:
    data = z.read('logic-1-1')

print(f"[*] Total samples: {len(data)}")
print(f"[*] Duration: {len(data)/1e6*1000:.2f} ms (at 1 MHz)")

# Convert to list of bits
bits = list(data)

# Find transitions to determine baud rate
transitions = []
for i in range(1, len(bits)):
    if bits[i] != bits[i-1]:
        transitions.append(i)

print(f"[*] Transitions: {len(transitions)}")

# Calculate distances between transitions
if len(transitions) > 1:
    distances = [transitions[i+1] - transitions[i] for i in range(len(transitions)-1)]
    min_dist = min(distances)
    print(f"[*] Minimum distance between transitions: {min_dist} samples")
    print(f"[*] First 20 distances: {distances[:20]}")

    # The bit period should be the GCD of the distances or the minimum distance
    from math import gcd
    from functools import reduce
    bit_period = reduce(gcd, distances)
    print(f"[*] GCD of distances: {bit_period}")

    # If GCD=1, look for the most common small distance
    from collections import Counter
    dist_counts = Counter(distances)
    print(f"[*] Most common distances: {dist_counts.most_common(10)}")

    # The bit period is probably the minimum distance rounded
    # Try common baud rates
    sample_rate = 1_000_000
    for baud in [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]:
        expected_period = sample_rate / baud
        print(f"  {baud:>7d} baud -> {expected_period:.1f} samples/bit")

# Decode UART with different baud rates
print("\n" + "=" * 60)
print("Decoding UART")
print("=" * 60)

def decode_uart(bits, bit_period, data_bits=8, parity=None, stop_bits=1):
    """Decode UART signal"""
    decoded = []
    i = 0
    n = len(bits)

    while i < n:
        # Look for start bit (HIGH->LOW transition)
        if bits[i] == 1:
            i += 1
            continue

        # Found a possible start bit (LOW)
        start = i

        # Verify it's a complete start bit
        # Sample at the center of the start bit
        center = start + bit_period // 2
        if center >= n:
            break

        if bits[int(center)] != 0:
            i += 1
            continue

        # Read data bits (LSB first)
        byte_val = 0
        valid = True
        for bit_idx in range(data_bits):
            sample_pos = int(start + bit_period * (1.5 + bit_idx))
            if sample_pos >= n:
                valid = False
                break
            bit_val = bits[sample_pos]
            byte_val |= (bit_val << bit_idx)

        if not valid:
            break

        # Verify stop bit
        stop_pos = int(start + bit_period * (1.5 + data_bits))
        if stop_pos < n and bits[stop_pos] == 1:
            decoded.append(byte_val)

        # Advance to the next byte
        i = int(start + bit_period * (1 + data_bits + stop_bits))

    return decoded

# Try different baud rates
sample_rate = 1_000_000
best_result = ""
best_baud = 0

for baud in [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400]:
    bit_period = sample_rate / baud

    for data_bits in [8, 7]:
        decoded = decode_uart(bits, bit_period, data_bits=data_bits)

        if decoded:
            text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded)
            raw = bytes(decoded)

            if len(decoded) > 2:
                printable_ratio = sum(1 for b in decoded if 32 <= b < 127) / len(decoded)
                print(f"\n  {baud} baud, {data_bits} data bits: {len(decoded)} bytes")
                print(f"  Hex: {raw.hex()}")
                print(f"  ASCII: {text}")
                print(f"  Raw: {decoded}")
                print(f"  Printable: {printable_ratio*100:.0f}%")

                if printable_ratio > 0.5 and len(text) > len(best_result):
                    best_result = text
                    best_baud = baud

if best_result:
    print(f"\n[+] Best result: {best_baud} baud")
    print(f"[+] Text: {best_result}")

# Search for flag
import re
all_text = best_result
flags = re.findall(r'0xfun\{[^}]+\}', all_text)
if flags:
    print(f"\n[+] FLAG: {flags[0]}")
