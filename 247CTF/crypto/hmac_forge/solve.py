#!/usr/bin/env python3
"""
Hash Length Extension Attack - Manual Implementation
"""

import struct
import requests
import urllib.parse

URL = "https://7d24b6c524004d77.247ctf.com/"

# SHA-256 constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def right_rotate(n, d):
    return ((n >> d) | (n << (32 - d))) & 0xffffffff

def sha256_compress(state, block):
    """SHA-256 compression function"""
    w = list(struct.unpack('>16I', block)) + [0] * 48

    for i in range(16, 64):
        s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff
        S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return tuple((x + y) & 0xffffffff for x, y in zip(state, (a, b, c, d, e, f, g, h)))

def sha256_padding(message_len):
    """Generate SHA-256 padding for a message of given length"""
    padding = b'\x80'
    padding += b'\x00' * ((55 - message_len) % 64)
    padding += struct.pack('>Q', message_len * 8)
    return padding

def hash_extend(original_hash, original_data, key_length, append_data):
    """
    Perform hash length extension attack on SHA-256

    original_hash: the known hash (hex string)
    original_data: the known suffix after the key
    key_length: length of the secret key
    append_data: data to append

    Returns: (new_hash, new_message_suffix)
    """
    # Parse original hash into state
    state = struct.unpack('>8I', bytes.fromhex(original_hash))

    # Calculate original message length (key + original_data)
    original_len = key_length + len(original_data)

    # Generate padding for original message
    padding = sha256_padding(original_len)

    # The full suffix that strrev(user) needs to be
    new_suffix = original_data + padding + append_data

    # Calculate the length of key + original_data + padding
    extended_len = original_len + len(padding)

    # Pad the append_data to process
    append_padded = append_data + sha256_padding(extended_len + len(append_data))

    # Process append_data blocks
    for i in range(0, len(append_padded), 64):
        block = append_padded[i:i+64]
        if len(block) == 64:
            state = sha256_compress(state, block)

    # Convert state back to hash
    new_hash = ''.join(f'{x:08x}' for x in state)

    return new_hash, new_suffix

# Known values
original_hash = "941f351a0c83589622bb5b81cddb18f4a74a7e877cd9b9548e37fec58370fc3e"
original_data = b"742"  # strrev("247")
key_length = 40  # 247CTF{32-hex-chars}
append_data = b"1"  # Will make user not equal to 247

print("=== Hash Length Extension Attack ===\n")
print(f"Original hash: {original_hash}")
print(f"Original data: {original_data}")
print(f"Key length: {key_length}")
print(f"Append data: {append_data}")

# Perform the attack
new_hash, new_suffix = hash_extend(original_hash, original_data, key_length, append_data)

print(f"\nNew hash: {new_hash}")
print(f"New suffix (hex): {new_suffix.hex()}")

# The user parameter needs to be reversed (strrev)
user_bytes = new_suffix[::-1]
print(f"User bytes (reversed): {user_bytes.hex()}")

# URL encode for request
user_encoded = urllib.parse.quote(user_bytes, safe='')
print(f"User URL encoded: {user_encoded}")

# Send request
print("\n" + "="*50)
print("Sending request...")

response = requests.get(URL, params={'user': user_bytes, 'hmac': new_hash})
print(f"Status: {response.status_code}")
print(f"Response: {response.text[:1000]}")

# Extract flag
import re
flag_match = re.search(r'247CTF\{[^}]+\}', response.text)
if flag_match:
    print(f"\n*** FLAG: {flag_match.group(0)} ***")
else:
    print("\nNo flag found. Trying different key lengths...")

    # Try different key lengths (37-43 is common for 247CTF flags)
    for key_len in range(37, 50):
        new_hash, new_suffix = hash_extend(original_hash, original_data, key_len, append_data)
        user_bytes = new_suffix[::-1]
        response = requests.get(URL, params={'user': user_bytes, 'hmac': new_hash})
        if "247CTF{" in response.text:
            flag_match = re.search(r'247CTF\{[^}]+\}', response.text)
            if flag_match:
                print(f"Key length {key_len}: FLAG = {flag_match.group(0)}")
                break
        else:
            print(f"Key length {key_len}: No flag")
