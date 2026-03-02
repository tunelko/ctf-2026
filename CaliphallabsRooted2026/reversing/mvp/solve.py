#!/usr/bin/env python3
"""
Challenge: MVP
Category:  reversing
Platform:  caliphallabsRooted2026

The PE has a certificate embedded (via PE Authenticode structure).
The binary reads the certificate data at offset 0x5b0, decrypts it with
AES-256-CBC (key="caliphal_labs!!!!!!!!!!!!!!!!!!!", IV="mvpmvpmvpmvpmvpm"),
writes the result as a temp DLL, loads it, calls get_mvp() export.
The flag is inside the decrypted DLL.
"""
import struct
import sys
from Crypto.Cipher import AES

BINARY = "mvp.exe"

def solve():
    with open(BINARY, "rb") as f:
        data = f.read()

    # Parse PE to find certificate table
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    opt_off = pe_off + 24
    dd_off = opt_off + 112  # PE32+ data directories offset
    cert_file_off = struct.unpack_from("<I", data, dd_off + 4 * 8)[0]
    cert_size = struct.unpack_from("<I", data, dd_off + 4 * 8 + 4)[0]

    cert_data = data[cert_file_off : cert_file_off + cert_size]
    dw_len = struct.unpack_from("<I", cert_data, 0)[0]

    # Encrypted DLL starts at offset 0x5b0 in cert data
    enc_offset = 0x5B0
    enc_len = dw_len - enc_offset
    encrypted = cert_data[enc_offset : enc_offset + enc_len]

    print(f"[*] Certificate at file offset 0x{cert_file_off:x}, size {cert_size}")
    print(f"[*] Encrypted data: {enc_len} bytes (offset 0x{enc_offset:x} in cert)")

    # AES-256-CBC decrypt
    key = b"caliphal_labs!!!!!!!!!!!!!!!!!!!"  # 32 bytes
    iv = b"mvpmvpmvpmvpmvpm"                   # 16 bytes

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted[:2] == b"MZ", "Decryption failed - not a valid PE"
    print(f"[+] Decrypted DLL: {len(decrypted)} bytes (MZ header OK)")

    # Save DLL
    with open("decrypted.dll", "wb") as f:
        f.write(decrypted)

    # Find flag in strings
    idx = decrypted.find(b"clctf{")
    if idx != -1:
        end = decrypted.index(b"}", idx) + 1
        flag = decrypted[idx:end].decode()
        print(f"\n[+] FLAG: {flag}")
        with open("flag.txt", "w") as f:
            f.write(flag)
    else:
        print("[-] Flag not found in decrypted DLL, check strings manually")

if __name__ == "__main__":
    solve()
