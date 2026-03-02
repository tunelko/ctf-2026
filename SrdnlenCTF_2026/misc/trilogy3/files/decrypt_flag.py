#!/usr/bin/env python3
"""
decrypt_flag.py — Decryptor for the APFS forensics challenge.

Usage:
    python3 decrypt_flag.py encrypted_flag.bin <key_hex>

The key is a 64-character hex string (32 bytes).
Decryption uses PBKDF2-SHA256 with a HIGH iteration count,
so each attempt takes ~90 seconds. Choose your key wisely.
"""

import hashlib
import hmac
import struct
import sys
import time


def decrypt_flag(enc_path: str, key_hex: str) -> None:
    with open(enc_path, "rb") as f:
        data = f.read()
    
    # Parse header: salt(16) + iterations(4) + flag_len(4) = 24 bytes header
    if len(data) < 24 + 32:  # header + at least hmac
        print("[!] File too small to be a valid encrypted flag.")
        sys.exit(1)
    
    salt = data[0:16]
    iterations, flag_len = struct.unpack_from('<II', data, 16)
    
    padded_len = ((flag_len + 31) // 32) * 32
    ciphertext = data[24:24 + padded_len]
    stored_tag = data[24 + padded_len:24 + padded_len + 32]
    
    if len(ciphertext) != padded_len or len(stored_tag) != 32:
        print("[!] Malformed encrypted file.")
        sys.exit(1)
    
    print(f"[*] Salt: {salt.hex()}")
    print(f"[*] PBKDF2 iterations: {iterations:,}")
    print(f"[*] Flag length: {flag_len}")
    print(f"[*] Ciphertext: {ciphertext.hex()}")
    print()
    
    # Validate key format
    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 32:
            raise ValueError
    except ValueError:
        print("[!] Key must be a 64-character hex string (32 bytes).")
        sys.exit(1)
    
    # Slow key derivation
    print(f"[*] Deriving key with PBKDF2-SHA256 ({iterations:,} iterations)...")
    print(f"[*] This will take approximately 90 seconds...")
    t0 = time.time()
    derived = hashlib.pbkdf2_hmac('sha256', key_bytes, salt, iterations)
    elapsed = time.time() - t0
    print(f"[*] Key derivation took {elapsed:.1f}s")
    print()
    
    # Verify HMAC
    computed_tag = hmac.new(derived, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(computed_tag, stored_tag):
        print("[✗] WRONG KEY — HMAC verification failed.")
        print("    The key you provided is not correct.")
        sys.exit(1)
    
    # Decrypt
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 32):
        block_key = hashlib.sha256(derived + struct.pack('<I', i // 32)).digest()
        for j in range(min(32, len(ciphertext) - i)):
            plaintext.append(ciphertext[i + j] ^ block_key[j])
    
    flag = bytes(plaintext[:flag_len])
    print(f"[✓] SUCCESS! Decrypted flag:")
    print(f"    {flag.decode('utf-8', errors='replace')}")


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 decrypt_flag.py <encrypted_flag.bin> <key_hex>")
        print()
        print("  key_hex: 64-character hex string (32 bytes)")
        print()
        print("Example:")
        print("  python3 decrypt_flag.py encrypted_flag.bin abcdef0123456789...")
        sys.exit(1)
    
    decrypt_flag(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
