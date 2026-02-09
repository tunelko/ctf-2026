#!/usr/bin/env python3
"""
Solve XOR encryption by trying known file signatures.
"""

with open('exclusive_key', 'rb') as f:
    data = f.read()

print(f"File size: {len(data)} bytes")
print(f"First 16 bytes: {data[:16].hex()}")

# Common file signatures
signatures = {
    'PNG': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    'JPEG': bytes([0xFF, 0xD8, 0xFF, 0xE0]),
    'GIF89a': b'GIF89a',
    'GIF87a': b'GIF87a',
    'PDF': b'%PDF-1.',
    'ZIP': bytes([0x50, 0x4B, 0x03, 0x04]),
    'ELF': bytes([0x7F, 0x45, 0x4C, 0x46]),
    'BMP': b'BM',
}

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

print("\nTrying file signatures to recover key:")
for name, sig in signatures.items():
    key_fragment = xor_bytes(data[:len(sig)], sig)
    print(f"{name}: key fragment = {key_fragment.hex()} = {repr(key_fragment)}")

    # Check if it looks like printable ASCII
    if all(32 <= b < 127 for b in key_fragment):
        print(f"  ^ Printable ASCII!")

# Let's also check what the file might be by examining patterns
print("\n\nLooking for repeating patterns (key length analysis)...")

# Try to find key length using Kasiski-like examination
def find_key_length(data, max_len=32):
    """Find likely key lengths by looking at byte frequency in columns"""
    scores = {}
    for key_len in range(1, max_len + 1):
        # For each position in the key, count byte frequencies
        total_score = 0
        for pos in range(key_len):
            column = data[pos::key_len]
            # Count most common byte
            from collections import Counter
            freq = Counter(column)
            most_common_count = freq.most_common(1)[0][1]
            total_score += most_common_count
        scores[key_len] = total_score / key_len

    # Return top candidates
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return sorted_scores[:10]

likely_lengths = find_key_length(data)
print("Likely key lengths (by frequency analysis):")
for length, score in likely_lengths:
    print(f"  Length {length}: score {score:.2f}")
