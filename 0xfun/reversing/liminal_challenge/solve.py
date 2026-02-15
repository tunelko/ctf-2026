#!/usr/bin/env python3
"""
Solver for Liminal -- reversing 500pts (hard)
0xFun CTF 2026

The binary implements an 8-round SPN (Substitution-Permutation Network) cipher
using speculative execution (Spectre-like) for the S-boxes.

Structure per round:
  1. XOR with round key
  2. 8 S-boxes (one per byte, 256 bijective entries each)
  3. Bit permutation (64-bit) -- except last round

To find the input that produces 0x4C494D494E414C21 ("LIMINAL!"),
we invert the cipher: apply inverse operations in reverse order.
"""
import struct
import sys
import os

def extract_from_binary(binary_path):
    """Extracts round keys, S-boxes and permutation table from the binary."""
    with open(binary_path, 'rb') as f:
        binary = f.read()

    # VA -> file offset mapping for the RW data segment
    # LOAD segment: VA 0x408df8 -> file offset 0x7df8
    # Simplified: file_offset = VA - 0x401000
    VA_BASE = 0x401000

    # Round keys: 8 x 8 bytes at VA 0x42f2c0
    keys_foff = 0x42f2c0 - VA_BASE
    round_keys = []
    for i in range(8):
        k = struct.unpack('<Q', binary[keys_foff + i*8 : keys_foff + i*8 + 8])[0]
        round_keys.append(k)

    # Bit permutation table: 64 bytes at VA 0x42f280
    perm_foff = 0x42f280 - VA_BASE
    perm_table = list(binary[perm_foff : perm_foff + 64])

    # S-boxes: 64 lookup tables (8 byte positions x 8 bits)
    # Each table: 256 entries x 8 bytes at file_offset 0xE280 + i*0x800
    # Values: offset 0x0 = bit 0, offset 0x240 = bit 1
    table_base_foff = 0xE280
    table_stride = 0x800

    sboxes = []
    for byte_pos in range(8):
        sbox = [0] * 256
        for bit_pos in range(8):
            table_idx = byte_pos * 8 + bit_pos
            table_foff = table_base_foff + table_idx * table_stride
            entries = []
            for i in range(256):
                val = struct.unpack('<Q', binary[table_foff + i*8 : table_foff + i*8 + 8])[0]
                entries.append(val)
            unique_vals = sorted(set(entries))
            assert len(unique_vals) == 2, f"S-box {byte_pos} bit {bit_pos}: expected 2 unique values, found {len(unique_vals)}"
            for i in range(256):
                if entries[i] == unique_vals[1]:  # higher value = bit set
                    sbox[i] |= (1 << bit_pos)
        sboxes.append(sbox)

    return round_keys, sboxes, perm_table


def build_inverses(sboxes, perm_table):
    """Builds inverse S-boxes and inverse permutation."""
    inv_sboxes = []
    for sbox in sboxes:
        inv = [0] * 256
        for i in range(256):
            inv[sbox[i]] = i
        inv_sboxes.append(inv)

    inv_perm = [0] * 64
    for out_bit in range(64):
        inv_perm[perm_table[out_bit]] = out_bit

    return inv_sboxes, inv_perm


def apply_sbox(state, sboxes):
    """Applies 8 S-boxes (one per byte) to the 64-bit state."""
    result = 0
    for i in range(8):
        byte_val = (state >> (i * 8)) & 0xFF
        result |= sboxes[i][byte_val] << (i * 8)
    return result


def apply_perm(state, perm):
    """Applies bit permutation to the 64-bit state."""
    result = 0
    for out_bit in range(64):
        in_bit = perm[out_bit]
        if state & (1 << in_bit):
            result |= (1 << out_bit)
    return result


def encrypt(plaintext, round_keys, sboxes, perm_table):
    """Encrypts a 64-bit block with the 8-round SPN."""
    state = plaintext
    for r in range(8):
        state ^= round_keys[r]
        state = apply_sbox(state, sboxes)
        if r < 7:  # no permutation in the last round
            state = apply_perm(state, perm_table)
    return state


def decrypt(ciphertext, round_keys, inv_sboxes, inv_perm):
    """Decrypts a 64-bit block by inverting the SPN."""
    state = ciphertext
    # Last round: only inverse S-box and XOR key (no permutation)
    state = apply_sbox(state, inv_sboxes)
    state ^= round_keys[7]
    # Rounds 6 -> 0: inverse permutation, inverse S-box, XOR key
    for r in range(6, -1, -1):
        state = apply_perm(state, inv_perm)
        state = apply_sbox(state, inv_sboxes)
        state ^= round_keys[r]
    return state


def main():
    binary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'liminal')
    if not os.path.exists(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        sys.exit(1)

    print("[*] Extracting SPN cipher components from binary...")
    round_keys, sboxes, perm_table = extract_from_binary(binary_path)
    inv_sboxes, inv_perm = build_inverses(sboxes, perm_table)

    print(f"[*] Round keys extracted: {len(round_keys)}")
    print(f"[*] S-boxes extracted: {len(sboxes)} (all bijective)")
    print(f"[*] Bit permutation: {len(perm_table)} entries")

    # Verify with roundtrip
    test = 0xDEADBEEFCAFEBABE
    enc = encrypt(test, round_keys, sboxes, perm_table)
    dec = decrypt(enc, round_keys, inv_sboxes, inv_perm)
    assert dec == test, "Roundtrip verification error"
    print("[+] Roundtrip verification: OK")

    # Decrypt the target
    target = 0x4C494D494E414C21  # "LIMINAL!" in ASCII
    solution = decrypt(target, round_keys, inv_sboxes, inv_perm)

    # Verify
    verify = encrypt(solution, round_keys, sboxes, perm_table)
    assert verify == target, f"Verification failed: encrypt(solution) = {verify:#018x} != {target:#018x}"

    print(f"\n[+] Target:       {target:#018x} ('LIMINAL!')")
    print(f"[+] Solution:     {solution:#018x}")
    print(f"[+] Verification: encrypt({solution:#018x}) = {verify:#018x}")
    print(f"\n[+] FLAG: 0xfun{{{solution:#018x}}}")


if __name__ == '__main__':
    main()
