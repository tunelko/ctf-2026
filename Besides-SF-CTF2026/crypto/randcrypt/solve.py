#!/usr/bin/env python3
"""randcrypt solver — invert bijective PRNG from leaked EOF block state"""
import struct

def u128_mask(x):
    return x & ((1 << 128) - 1)

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inverse(a, mod):
    g, x, _ = extended_gcd(a % mod, mod)
    return x % mod

M = 1 << 128

# PRNG constants
C1_MUL, C1_ADD = 0xc7d966554fdd88952bd67b67587a550d, 0xaad7d93a4256e8156b2b70757a011d80
C2_MUL, C2_ADD = 0xa064c0bdb010eab3cb5a960584361b11, 0xca5e129f885443193e87d676b3f2f21e
C3_MUL, C3_ADD = 0xad68c652004075c9b1562331444753a3, 0xfa2556c0ac3f32d07116f45b079e2977
C4_MUL, C4_ADD = 0x6a257956638a88560427312461d8096d, 0x7f226a22555b20e3e790563048bad20a

C1_INV = mod_inverse(C1_MUL, M)
C2_INV = mod_inverse(C2_MUL, M)
C3_INV = mod_inverse(C3_MUL, M)
C4_INV = mod_inverse(C4_MUL, M)

def rng_next(state):
    x = state
    x = u128_mask((x << 7) ^ x);  x = u128_mask(x * C1_MUL); x = u128_mask(x + C1_ADD)
    x = u128_mask((x >> 13) ^ x); x = u128_mask(x * C2_MUL); x = u128_mask(x + C2_ADD)
    x = u128_mask((x << 19) ^ x); x = u128_mask(x * C3_MUL); x = u128_mask(x + C3_ADD)
    x = u128_mask((x >> 23) ^ x); x = u128_mask(x * C4_MUL); x = u128_mask(x + C4_ADD)
    return x

def inv_xor_lshift(x, shift, bits=128):
    mask = (1 << bits) - 1
    result = x
    for _ in range(bits // shift + 1):
        result = x ^ ((result << shift) & mask)
    return result & mask

def inv_xor_rshift(x, shift, bits=128):
    result = x
    for _ in range(bits // shift + 1):
        result = x ^ (result >> shift)
    return result

def rng_prev(state):
    x = state
    x = u128_mask(x - C4_ADD); x = u128_mask(x * C4_INV); x = inv_xor_rshift(x, 23)
    x = u128_mask(x - C3_ADD); x = u128_mask(x * C3_INV); x = inv_xor_lshift(x, 19)
    x = u128_mask(x - C2_ADD); x = u128_mask(x * C2_INV); x = inv_xor_rshift(x, 13)
    x = u128_mask(x - C1_ADD); x = u128_mask(x * C1_INV); x = inv_xor_lshift(x, 7)
    return x

def main():
    with open("flag.jxl.enc", "rb") as f:
        enc = f.read()

    # EOF block leaks PRNG state (0 XOR state = state)
    state_eof = int.from_bytes(enc[-32:-16], 'big')
    total_len = int.from_bytes(enc[-16:], 'big') ^ rng_next(state_eof)
    n_data_blocks = (len(enc) - 32) // 16
    print(f"Original file length: {total_len}")
    print(f"Data blocks: {n_data_blocks}")

    # Walk back to state_1
    state = state_eof
    for i in range(n_data_blocks):
        state = rng_prev(state)
        if (i + 1) % 2000 == 0:
            print(f"  Inverted {i+1}/{n_data_blocks}...")
    state_1 = state
    print(f"state_1 = 0x{state_1:032x}")

    # Decrypt
    state = state_1
    plaintext = bytearray()
    for i in range(n_data_blocks):
        block = int.from_bytes(enc[i*16:(i+1)*16], 'big')
        plaintext.extend((block ^ state).to_bytes(16, 'big'))
        state = rng_next(state)

    plaintext = bytes(plaintext[:total_len])
    with open("flag.jxl", "wb") as f:
        f.write(plaintext)
    print(f"Saved flag.jxl ({len(plaintext)} bytes)")
    print(f"Header: {plaintext[:4].hex()} ({'JXL ✓' if plaintext[:2] == b'\\xff\\x0a' else '?'})")

if __name__ == "__main__":
    main()
