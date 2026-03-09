#!/usr/bin/env python3
"""
Challenge: jumpy
Category:  rev
Platform:  UNbreakable 2026
Technique: Custom cipher (GrayInterleaveSbox) reversal
"""
import hashlib
import struct
import subprocess
import os

# === Key derivation ===
cipher_name = b'UNBR26::GrayInterleaveSbox::v1'
key1_raw = bytes.fromhex('5ac311807701f0339c4d6610a07f0255')
key2_raw = bytes.fromhex('49f4d15e51ab4bff42e0d8ffe25b1bcc')
secret = bytes(a ^ b for a, b in zip(key1_raw, key2_raw))
sha256_key = hashlib.sha256(cipher_name + secret).digest()

def gen_round_key(block_counter):
    msg = sha256_key + b'KS' + struct.pack('<I', block_counter)
    return hashlib.sha256(msg).digest()

def build_sbox():
    sbox = list(range(256))
    seed = bytearray(sha256_key)
    counter = 0
    byte_idx = 0x20
    current_hash = bytearray(32)
    for i in range(255, 0, -1):
        if byte_idx > 0x1f:
            msg = bytes(seed) + struct.pack('<I', counter)
            current_hash = bytearray(hashlib.sha256(msg).digest())
            counter += 1
            byte_idx = 0
        j = current_hash[byte_idx] % (i + 1)
        sbox[i], sbox[j] = sbox[j], sbox[i]
        byte_idx += 1
    return sbox

sbox = build_sbox()
inv_sbox = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i

# === Cipher operations ===

def gray_encode(x):
    return (x ^ (x >> 1)) & 0xff

def gray_decode(g):
    """Inverse Gray code for 8-bit value."""
    mask = g
    while mask:
        mask >>= 1
        g ^= mask
    return g & 0xff

def nonlinear_mix(val, key_byte):
    """(val ^ key) + 2*(val & key)"""
    xored = (val ^ key_byte) & 0xff
    anded = (val & key_byte) & 0xff
    return (xored + anded * 2) & 0xff

def inv_nonlinear_mix(result, key_byte):
    """Inverse of nonlinear_mix.
    result = (val ^ k) + 2*(val & k)
    Note: val ^ k + 2*(val & k) = val + k (this is binary addition!)
    Because: a XOR b = a + b - 2*(a AND b) for single bits, so
    a XOR b + 2*(a AND b) = a + b
    """
    # result = val + key_byte (mod 256)
    return (result - key_byte) & 0xff

def rotate_left(val, amount):
    if amount == 0:
        return val
    return ((val << amount) | (val >> (8 - amount))) & 0xff

def rotate_right(val, amount):
    if amount == 0:
        return val
    return ((val >> amount) | (val << (8 - amount))) & 0xff

def nibble_interleave(a, b):
    """Swap low nibble of a with high nibble of b."""
    a_hi = (a >> 4) & 0xf
    a_lo = a & 0xf
    b_hi = (b >> 4) & 0xf
    b_lo = b & 0xf
    return (a_hi << 4) | b_lo, (b_hi << 4) | a_lo

def inv_nibble_interleave(a, b):
    """Inverse: same operation (it's an involution)."""
    return nibble_interleave(a, b)

# === Encrypt one 32-byte block ===

def encrypt_block(plaintext, block_counter):
    buf = bytearray(plaintext)
    rk = gen_round_key(block_counter)

    for pos in range(0, 32, 2):
        a, b = buf[pos], buf[pos + 1]
        nlk_a = (31 * block_counter + 17 * pos) & 0xff
        nlk_b = (31 * block_counter + 17 * (pos + 1)) & 0xff

        # Step 1: XOR with round key
        a ^= rk[pos]
        b ^= rk[pos + 1]

        # Step 2: Nonlinear mix
        a = nonlinear_mix(a, nlk_a)
        b = nonlinear_mix(b, nlk_b)

        # Step 3: Gray code
        a = gray_encode(a)
        b = gray_encode(b)

        # Step 4: Nibble interleave
        a, b = nibble_interleave(a, b)

        # Step 5: S-box
        a = sbox[a]
        b = sbox[b]

        # Step 6: Bit rotation
        rot_a = (rk[pos] + 8) & 7
        rot_b = (rk[pos + 1] + 8) & 7
        a = rotate_left(a, rot_a)
        b = rotate_left(b, rot_b)

        buf[pos] = a
        buf[pos + 1] = b

    return bytes(buf)

# === Decrypt one 32-byte block ===

def decrypt_block(ciphertext, block_counter):
    buf = bytearray(ciphertext)
    rk = gen_round_key(block_counter)

    for pos in range(0, 32, 2):
        a, b = buf[pos], buf[pos + 1]
        nlk_a = (31 * block_counter + 17 * pos) & 0xff
        nlk_b = (31 * block_counter + 17 * (pos + 1)) & 0xff

        # Reverse step 6: Inv-rotation
        rot_a = (rk[pos] + 8) & 7
        rot_b = (rk[pos + 1] + 8) & 7
        a = rotate_right(a, rot_a)
        b = rotate_right(b, rot_b)

        # Reverse step 5: Inv-sbox
        a = inv_sbox[a]
        b = inv_sbox[b]

        # Reverse step 4: Inv-nibble-interleave (same operation)
        a, b = inv_nibble_interleave(a, b)

        # Reverse step 3: Inv-gray
        a = gray_decode(a)
        b = gray_decode(b)

        # Reverse step 2: Inv-nonlinear
        a = inv_nonlinear_mix(a, nlk_a)
        b = inv_nonlinear_mix(b, nlk_b)

        # Reverse step 1: XOR with round key
        a ^= rk[pos]
        b ^= rk[pos + 1]

        buf[pos] = a
        buf[pos + 1] = b

    return bytes(buf)

# === Verify encryption ===

print("[*] Verifying encryption...")
test_plain = b'\x00' * 32
my_ct = encrypt_block(test_plain, 0)

subprocess.run(['./chall'], input=b'\x00' * 32, capture_output=True)
with open('enc.sky', 'rb') as f:
    real_ct = f.read()
os.system('cp /home/student/.cache/vmware/drag_and_drop/qtIF6j/enc.sky enc.sky 2>/dev/null')

print(f"  My:   {my_ct.hex()}")
print(f"  Real: {real_ct[:32].hex()}")
print(f"  Match: {my_ct == real_ct[:32]}")

# Verify decryption round-trip
my_pt = decrypt_block(my_ct, 0)
print(f"  Decrypt roundtrip: {my_pt == test_plain}")

# Test with block 1 too
my_ct1 = encrypt_block(bytes([0x20] * 32), 1)  # padding block
print(f"  Block 1 match: {my_ct1 == real_ct[32:64]}")

# === Decrypt enc.sky ===

print("\n[*] Decrypting enc.sky...")
with open('enc.sky', 'rb') as f:
    enc_data = f.read()

num_blocks = len(enc_data) // 32
print(f"  {len(enc_data)} bytes = {num_blocks} blocks")

plaintext = b''
for i in range(num_blocks):
    block = enc_data[i*32:(i+1)*32]
    pt = decrypt_block(block, i)
    plaintext += pt
    print(f"  Block {i}: {pt.hex()} | {pt}")

# Remove PKCS-like padding
pad_byte = plaintext[-1]
if 1 <= pad_byte <= 32:
    # Verify padding
    pad_ok = all(b == pad_byte for b in plaintext[-pad_byte:])
    if pad_ok:
        plaintext = plaintext[:-pad_byte]
        print(f"\n  Removed {pad_byte} bytes of padding")

print(f"\n[+] Decrypted: {plaintext}")
print(f"[+] Flag: {plaintext.decode('utf-8', errors='replace')}")
