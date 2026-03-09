#!/usr/bin/env python3
"""
Challenge: xSTF's Decryption Capsule — upCTF 2026
Category:  crypto (CBC padding oracle)
Flag:      upCTF{p4dd1ng_0r4cl3_s4ys_xSTF_1s_num3r0_un0-dqxH5Zcr60416fcd}

AES-CBC decryption oracle leaks padding validity through error messages.
Use padding oracle attack to encrypt arbitrary plaintext (build from last block).
"""

from pwn import *
import os

HOST = "46.225.117.62"
PORT = 30004
BLOCK_SIZE = 16
TARGET = b"xSTF is the best portuguese CTF team :P"

def pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def send_payload(r, iv, ct):
    r.sendlineafter(b">", (iv + ct).hex().encode())
    return r.recvline(timeout=5).decode().strip()

def find_intermediate(r, ct_block):
    """Discover D(K, ct_block) via padding oracle — 1 block at a time."""
    intermediate = [0] * BLOCK_SIZE
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - pos
        test_iv = bytearray(BLOCK_SIZE)
        for k in range(pos + 1, BLOCK_SIZE):
            test_iv[k] = intermediate[k] ^ pad_val

        for guess in range(256):
            test_iv[pos] = guess
            resp = send_payload(r, bytes(test_iv), ct_block)
            if "ain't" in resp or "Yeah" in resp:
                # Verify last byte to avoid false positive (0x02 0x02 vs 0x01)
                if pos == BLOCK_SIZE - 1 and pad_val == 1:
                    v = bytearray(test_iv); v[pos - 1] ^= 1
                    if "ain't" not in send_payload(r, bytes(v), ct_block):
                        continue
                intermediate[pos] = guess ^ pad_val
                break
    return bytes(intermediate)

def main():
    target_padded = pad(TARGET)  # 48 bytes = 3 blocks
    num_blocks = len(target_padded) // BLOCK_SIZE
    pt_blocks = [target_padded[i*16:(i+1)*16] for i in range(num_blocks)]

    r = remote(HOST, PORT)
    r.recvuntil(b"transmission...")

    # Build ciphertext from last block backwards
    ct_blocks = [os.urandom(16)]  # random last ciphertext block
    for i in range(num_blocks - 1, -1, -1):
        log.info(f"Block {i}/{num_blocks-1}")
        inter = find_intermediate(r, ct_blocks[0])
        prev = bytes(a ^ b for a, b in zip(inter, pt_blocks[i]))
        ct_blocks.insert(0, prev)

    # ct_blocks[0] = IV, rest = ciphertext
    resp = send_payload(r, ct_blocks[0], b''.join(ct_blocks[1:]))
    print(resp)
    print(r.recvall(timeout=3).decode())
    r.close()

if __name__ == "__main__":
    main()
