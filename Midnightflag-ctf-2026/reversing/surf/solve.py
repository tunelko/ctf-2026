#!/usr/bin/env python3
"""Solve 'What is that browser doing??' - Midnight Flag CTF 2026"""
from collections import defaultdict

data = open('surf', 'rb').read()
sbox = data[0xdfa0:0xdfa0+256]

def little_encryption(ch):
    val = ch if ch < 128 else ch - 256  # movsbl (sign extend)
    val = (val << 7) & 0xFFFF            # shl 7, keep 16 bits
    val = (val * 0x539 >> 5) & 0xFC      # *1337, >>5, mask
    return sbox[val]

# Encrypted flag from b64encode function
target = bytes([
    0x22,0x91,0x70,0x6a,0x64,0x43,0x5f,0xfa,
    0xbf,0x50,0xde,0x53,0x18,0xde,0x04,0xbf,
    0x50,0xde,0x65,0xc4,0x86,0x50,0xde,0xba,
    0x43,0x61,0x61,0x50,0xde,0xfa,0x86,0x41,
    0xde,0x52,0x5f,0x52,0x86,0x18,0x71,0xe0,
    0x86,0x18,0x9c,0x20,
])

# Invert sbox: enc_byte -> list of possible plaintext bytes
rev = defaultdict(list)
for c in range(256):
    rev[little_encryption(c)].append(c)

# Decrypt — pick printable, prefer uppercase for MCTF prefix, lowercase for body
flag = ''
for b in target:
    printable = sorted(c for c in rev[b] if 32 <= c < 127)
    flag += chr(printable[-1])  # highest printable = lowercase letter or }

print(flag)
