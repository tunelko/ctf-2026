#!/usr/bin/env python3
"""Ancient Mystery — 49 rounds of base64 decode (3136 years / 64 years per round)"""
import base64

with open("secret_message.txt", "r") as f:
    data = f.read().strip()

for i in range(49):
    data = base64.b64decode(data).decode()

# Original flag format: flag{...}, submit as kashiCTF{...}
print(f"[+] Raw: {data}")
print(f"[+] FLAG: kashiCTF{{{data.split('{')[1]}")
