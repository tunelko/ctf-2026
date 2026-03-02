#!/usr/bin/env python3
# solve.py — Flecha Negra v2 solver
# Recovers the deactivation key from the binary and decrypts the flag.
import struct

# === Step 1: Recover the key ===
# The binary XOR-decodes a target string at 0x40c0 with 0x55 (40 bytes).
# The target is space-separated decimal ASCII values of the REVERSED key.
encoded = bytes([
    0x64,0x65,0x67,0x75,0x64,0x65,0x66,0x75,
    0x6c,0x60,0x75,0x6c,0x62,0x75,0x6c,0x60,
    0x75,0x64,0x65,0x65,0x75,0x64,0x65,0x64,
    0x75,0x64,0x65,0x64,0x75,0x64,0x64,0x65,
    0x75,0x6c,0x60,0x75,0x64,0x65,0x60,0x75
])
target = bytes([b ^ 0x55 for b in encoded]).decode()
# target = "102 103 95 97 95 100 101 101 110 95 105 "

# Parse decimal ASCII values → reversed key → original key
reversed_key = ''.join(chr(int(n)) for n in target.strip().split())
key = reversed_key[::-1]
print(f"[+] Recovered key: {key}")

# === Step 2: Decrypt the flag ===
# The success function (fcn.0000148a) XOR-decrypts a 51-byte buffer with the key.
buf = bytearray()
buf += struct.pack('<Q', 0x00240a2a0e0d3e21)
buf += struct.pack('<Q', 0x0b550a000039133c)
buf += struct.pack('<Q', 0x3e3602546c0f0010)
buf += struct.pack('<Q', 0x386c092c3b030231)
buf += struct.pack('<Q', 0x2a163a01022a5911)
buf += struct.pack('<Q', 0x540200100b383150)
# Last 4 bytes overlap at offset 47
dw = struct.pack('<I', 0x22010354)
buf[47] = dw[0]
buf.append(dw[1])
buf.append(dw[2])
buf.append(dw[3])

key_bytes = key.encode()
flag = ''.join(chr(buf[i] ^ key_bytes[i % len(key_bytes)]) for i in range(len(buf)))
print(f"[+] FLAG: {flag}")
