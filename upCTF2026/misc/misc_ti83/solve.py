#!/usr/bin/env python3
"""
Challenge: BluPage TI-83+ PROG — upCTF 2026
Category:  misc (reversing / Z80 assembly)
Flag:      upCTF{1F41L3DC4LCF0RTH1S}

TI-83+ assembly program "CODE CHECKER". Z80 code uses:
1. Timer ISR with CRC-8 (poly 0xB8, init 0xA5) iterated 1+2+...+18=171 times
2. CRC result XOR 0x17 = XOR key to decrypt comparison routine
3. Decrypted routine XORs expected data with CRC-8 keystream, compares to input
"""

data = open("PROG.8xp", "rb").read()

# Find BB 6D (AsmPrgm token) to locate Z80 code
bb6d = data.find(b'\xbb\x6d')
base = 0x9D95
code_start = bb6d + 2

def addr_to_off(addr):
    return code_start + (addr - base)

# --- Step 1: Compute CRC-8 XOR key ---
# ISR runs once per keypress with B=char_count iterations
# Total iterations for 18 chars: 1+2+...+18 = 171
crc = 0xA5
for _ in range(171):
    carry = crc & 1
    crc >>= 1
    if carry:
        crc ^= 0xB8

xor_key = crc ^ 0x17  # 0xA7

# --- Step 2: Decrypt comparison routine (57 bytes at 0x9DAA) ---
encrypted = data[addr_to_off(0x9DAA):addr_to_off(0x9DAA) + 57]
decrypted_routine = bytes([b ^ xor_key for b in encrypted])

# --- Step 3: Apply CRC-8 keystream to expected data (18 bytes at 0x9D98) ---
# The decrypted routine XORs each expected byte with evolving C value
# C starts at 0xA5, each iteration: SRL C; if carry: C ^= 0xB8
expected_enc = data[addr_to_off(0x9D98):addr_to_off(0x9D98) + 18]

c = 0xA5
expected_tokens = []
for b in expected_enc:
    carry = c & 1
    c >>= 1
    if carry:
        c ^= 0xB8
    expected_tokens.append(b ^ c)

# --- Step 4: Convert TI-83+ key tokens to ASCII ---
# 0x8E-0x97 → '0'-'9', 0x9A-0xB3 → 'A'-'Z'
def token_to_char(t):
    if 0x8E <= t <= 0x97:
        return chr(t - 0x8E + 0x30)
    elif 0x9A <= t <= 0xB3:
        return chr(t - 0x9A + 0x41)
    return '?'

code = ''.join(token_to_char(t) for t in expected_tokens)
print(f"FLAG: upCTF{{{code}}}")
