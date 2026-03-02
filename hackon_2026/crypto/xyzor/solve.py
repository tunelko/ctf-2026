#!/usr/bin/env python3
# solve.py — XYZOR solver
# Usage: python3 solve.py

import requests
import json

URL = "https://hackon-crypto-xyzor-service.chals.io"

# Flag data from /flag page
FLAG_CT = "1001000001111000101001100100010001010010100100010111011010010000111101110010001010101101111001111001000110110011011111100101111110110010001101111010011110110011110100011101001101010101010000000110111010100000100111100110000010010011011100010010011000010110"
FLAG_ORDER = "yxyyxyyzxxzxyyxzyxyzyyzzxzxzxzyxxyyzzzzzzyxzxyxzzzyxxzzxzxxyyyyzzzzxxzzyxxzzzzxxyxyxyyyyyyzzxxzzzzzyzzxyyxyxxyxyxzyyzyzxyxzyyyzyzzxxyxyxxzzzzzyyyzzxxxyxyxxzyyzyzzxyxyyxyzyyxzxxxyxxyzzxxyyyxxyxxzyyxyxxyyyyzxxyzzzyyxzzxzzzzxxzzyxyzyzzzxxzyzxzxyzzzxzxxyxzzxxz"

OFFSET = {'x': 0, 'y': 1, 'z': 2}

def encrypt_oracle(plaintext: str) -> dict:
    """Send plaintext to the XYZOR encryption oracle."""
    resp = requests.post(f"{URL}/encrypt",
                         data={"plaintext": plaintext},
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
    return resp.json()

def recover_key_bits(plaintext_bits: str, ciphertext_bits: str, order: str) -> dict:
    """Recover key bits from a known plaintext/ciphertext/order triple."""
    key_bits = {}
    for i in range(len(order)):
        offset = OFFSET[order[i]]
        key_pos = i + offset
        # key[key_pos] = plaintext[i] XOR ciphertext[i]
        key_bits[key_pos] = int(plaintext_bits[i]) ^ int(ciphertext_bits[i])
    return key_bits

# Determine which key positions we need for the flag
needed = set()
for i, o in enumerate(FLAG_ORDER):
    needed.add(i + OFFSET[o])

print(f"[*] Need {len(needed)} unique key bit positions (range {min(needed)}-{max(needed)})")

# Recover key bits by sending known plaintext to the oracle
# Use a 34-byte plaintext (272 bits) to cover positions up to 272+2=274
known_key = {}
plaintext = "A" * 34  # 34 bytes = 272 bits, enough to cover 0..257+

attempt = 0
while not needed.issubset(known_key.keys()):
    attempt += 1
    result = encrypt_oracle(plaintext)
    pt_bits = result["plaintext_bits"]
    ct_bits = result["ciphertext_bits"]
    order = result["order"]

    new_bits = recover_key_bits(pt_bits, ct_bits, order)
    known_key.update(new_bits)

    still_missing = needed - set(known_key.keys())
    print(f"[*] Attempt {attempt}: recovered {len(new_bits)} bits, total known: {len(known_key)}, still missing: {len(still_missing)}")

    if attempt > 50:
        print("[-] Too many attempts, something is wrong")
        break

print(f"[+] All {len(needed)} required key positions recovered after {attempt} requests")

# Decrypt the flag
flag_bits = []
for i in range(len(FLAG_CT)):
    offset = OFFSET[FLAG_ORDER[i]]
    key_pos = i + offset
    pt_bit = int(FLAG_CT[i]) ^ known_key[key_pos]
    flag_bits.append(str(pt_bit))

flag_bitstring = ''.join(flag_bits)
# Convert bits to bytes
flag_bytes = bytes(int(flag_bitstring[i:i+8], 2) for i in range(0, len(flag_bitstring), 8))
flag = flag_bytes.decode('utf-8', errors='replace')

print(f"\n[+] FLAG: {flag}")
