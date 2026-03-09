#!/usr/bin/env python3
"""
Challenge: inconspicuous — upCTF 2026
Category:  misc (reversing / self-modifying binary)
Flag:      upCTF{I_w4s_!a110wed_t0_write_m4lw4r3}

ELF reads password, computes XOR key = strlen(pw) + 0x10,
decrypts embedded shellcode, mprotects as RWX, calls it.
Brute-force XOR key (1 byte): key 0x1C produces valid x86-64 prolog.
Decrypted code compares password byte-by-byte, prints flag on success.
"""

import struct

elf = open("inconspicuous", "rb").read()

# Encrypted blob at VA 0x403060 → file offset 0x2060
# Length at VA 0x403194 → file offset 0x2194
enc_len = struct.unpack('<I', elf[0x2194:0x2198])[0]
encrypted = elf[0x2060:0x2060 + enc_len]

# Brute-force XOR key: look for x86-64 function prolog (55 48 89 e5)
for key in range(256):
    dec = bytes([b ^ key for b in encrypted])
    if dec[:4] == b'\x55\x48\x89\xe5':
        print(f"XOR key: 0x{key:02X} (password length: {key - 0x10})")

        # Extract password from CMP instructions
        pw = []
        i = 0
        while i < len(dec) - 1:
            if dec[i] == 0x3C:  # CMP AL, imm8
                pw.append(chr(dec[i + 1]))
                i += 2
            else:
                i += 1
            if len(pw) == key - 0x10:
                break
        print(f"Password: {''.join(pw)}")

        # Extract flag (write syscall: lea rsi,[rip+0xa] at offset 0xF9, len 0x27)
        flag_off = 0x10A
        flag_len = 0x27
        flag = dec[flag_off:flag_off + flag_len].decode()
        print(f"FLAG: {flag}")
        break
