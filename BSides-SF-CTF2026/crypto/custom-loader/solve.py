#!/usr/bin/env python3
"""custom-loader: RC4 decrypt flag.enc with key BSIDES_SF_2026"""
from Crypto.Cipher import ARC4

key = b"BSIDES_SF_2026"
with open("flag.enc", "rb") as f:
    ct = f.read()

pt = ARC4.new(key).decrypt(ct)
print(f"[+] Decrypted: {pt}")
# Flag is in the decrypted flat binary as ASCII
import re
flag = re.search(rb'CTF\{[^}]+\}', pt)
if flag:
    print(f"[+] FLAG: {flag.group(0).decode()}")
