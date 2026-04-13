#!/usr/bin/env python3
"""
Six Seven - DawgCTF 2026
Category: crypto

Stream cipher with deterministic PRNG: gen(prev) produces next key byte.
Key seeded by os.urandom(1) = 1 byte = 256 possibilities.
Brute-force the seed, check against known plaintext prefix "DawgCTF{".
"""

ct = bytes.fromhex("9f2eadbd998e9ca1aab6bfbba9bf85afa9bf85a9bfb9a8bfaea985b3b485a3b5afa885a9aea8bfbbb785b9b3aab2bfa8a985ece3b8bcbfebe3eebbbceee9bceab9bea7")

def gen(start):
    return (((6 * 7) * (start - 6) * 7) + ((start * 6) - 7) * (start ^ 6)) % 255

for s in range(256):
    key = bytes([s])
    for i in range(1, len(ct)):
        key += gen(key[i-1]).to_bytes(1, "big")
    pt = bytes(a ^ b for a, b in zip(key, ct))
    if pt[:8] == b"DawgCTF{":
        print(f"[+] FLAG: {pt.decode()}")
        break
