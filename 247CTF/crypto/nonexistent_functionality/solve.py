#!/usr/bin/env python3
"""
Padding Oracle Attack - Optimized with saved progress
"""

from base64 import b64encode, b64decode
import requests

URL = "https://1ea5b729c6308626.247ctf.com/get_flag"

# Saved progress from previous runs
PREXOR1 = bytes.fromhex("dc36f147a01e5d911633981ac0364f54")  # Complete!

def test_padding(data_bytes):
    """Send data to server and check response"""
    encoded = b64encode(data_bytes).decode()
    resp = requests.get(URL, params={'password': encoded}, timeout=10)
    return resp.text

def find_prexor_block(c1, start_byte=0, known_prexor=None):
    """Find pre-XOR values for a block"""
    if known_prexor:
        prexor = list(known_prexor)
    else:
        prexor = [0] * 16

    for byte_pos in range(start_byte, 16):
        print(f"  Byte {byte_pos}: ", end="", flush=True)
        target_pad = byte_pos + 1

        for guess in range(256):
            iv = bytearray(16)
            for j in range(byte_pos):
                iv[j] = prexor[j] ^ target_pad
            iv[byte_pos] = guess

            data = bytes(iv) + c1
            result = test_padding(data)

            if "Invalid password!" in result:
                prexor[byte_pos] = guess ^ target_pad
                print(f"0x{prexor[byte_pos]:02x}")
                break
        else:
            print("FAILED")
            return None

    return bytes(prexor)

def main():
    print("=== Padding Oracle Attack (Optimized) ===\n")

    # We have prexor1 from phase 1
    prexor1 = PREXOR1
    print(f"Pre-XOR block 1: {prexor1.hex()}")

    # Phase 2: Find pre-XOR for block 2
    target_block2 = b"t_admin_password"
    c1_fixed = bytes([prexor1[i] ^ target_block2[i] for i in range(16)])
    print(f"C1 for phase 2: {c1_fixed.hex()}")

    print("\n=== Finding pre-XOR for block 2 ===")
    # Continue from saved progress
    prexor2_partial = bytes.fromhex("d3e744bebbc395a903de61c22b1c0783")

    # Check if we have all 16 bytes
    if len(prexor2_partial) == 16:
        prexor2 = prexor2_partial
        print(f"Pre-XOR block 2 (loaded): {prexor2.hex()}")
    else:
        prexor2 = find_prexor_block(c1_fixed + bytes(16), start_byte=len(prexor2_partial),
                                    known_prexor=prexor2_partial + bytes(16-len(prexor2_partial)))
        if prexor2 is None:
            print("Phase 2 failed!")
            return
        print(f"Pre-XOR block 2: {prexor2.hex()}")

    # Phase 3: Find pre-XOR for block 1 with fixed C1
    print("\n=== Finding pre-XOR for block 1 with fixed C1 ===")
    prexor1_new = find_prexor_block(c1_fixed)
    if prexor1_new is None:
        print("Phase 3 failed!")
        return
    print(f"Pre-XOR block 1 (new): {prexor1_new.hex()}")

    # Craft final payload
    target_block1 = b"\x0b" * 11 + b"secre"
    iv = bytes([prexor1_new[i] ^ target_block1[i] for i in range(16)])
    c2 = bytes(16)

    payload = iv + c1_fixed + c2
    print(f"\nFinal payload (b64): {b64encode(payload).decode()}")

    # Test
    print("\n=== Testing final payload ===")
    result = test_padding(payload)
    print(f"Result: {result}")

    if "247CTF{" in result:
        import re
        flag = re.search(r'247CTF\{[^}]+\}', result)
        if flag:
            print(f"\n*** FLAG: {flag.group(0)} ***")

if __name__ == "__main__":
    main()
