#!/usr/bin/env python3
"""
airlock - Reversing Challenge Solver
UniVsThreats 2026 Quals

The airlockauth binary reads three files (seed32.bin, nav.bc, payload.enc),
prompts for a token via stdin, then decrypts payload.enc using a two-stage
SHA256 + XOR scheme.

Algorithm (reversed from stripped ELF at 0x1300-0x15b2):
  1. Read seed32.bin (32 bytes), nav.bc (var), payload.enc (var)
  2. Read token from stdin, strip newline
  3. nav_hash  = SHA256(nav.bc)
  4. combined  = seed32 || token || nav_hash
  5. xor_key   = SHA256(combined)                   # 32-byte key
  6. flag[i]   = payload.enc[i] ^ xor_key[i % 32]
  7. If flag starts with "UVT{" → print "signal verified"
     else → print "access denied"

Token: "ASTRA9-" (from crew_log.txt) + "BRO-1337" (from deleted crew_id.part2)

All required files were recovered from the USB disk image in the forensics challenge.
"""
import hashlib
import os
import sys


def main():
    # Locate input files - check current dir, then /tmp/usb_run/
    search_dirs = [".", "/tmp/usb_run"]
    files = {}

    for name in ["seed32.bin", "nav.bc", "payload.enc"]:
        for d in search_dirs:
            path = os.path.join(d, name)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    files[name] = f.read()
                break
        if name not in files:
            print(f"[-] {name} not found. Extract from space_usb.img first.")
            print(f"    seed32.bin: deleted file on ext4 partition (inode 17)")
            print(f"    nav.bc:     FAT partition root")
            print(f"    payload.enc: FAT partition root")
            sys.exit(1)

    seed = files["seed32.bin"]
    nav = files["nav.bc"]
    payload = files["payload.enc"]

    # Token construction
    # Prefix from crew_log.txt: "ASTRA9-"
    # Suffix from deleted crew_id.part2 (inode 18): "BRO-1337"
    token = b"ASTRA9-BRO-1337"

    print(f"[*] seed32.bin:  {len(seed)} bytes  [{seed.hex()}]")
    print(f"[*] nav.bc:      {len(nav)} bytes")
    print(f"[*] payload.enc: {len(payload)} bytes [{payload.hex()}]")
    print(f"[*] token:       {token.decode()}")

    # === DECRYPTION (mirrors binary logic at 0x1300-0x15b2) ===
# SHA256(nav.bc) → 32-byte hash
    nav_hash = hashlib.sha256(nav).digest()
    print(f"\n[1] SHA256(nav.bc)       = {nav_hash.hex()}")
# Build combined buffer = seed32 || token || nav_hash
    combined = seed + token + nav_hash
    print(f"[2] combined buffer     = {len(combined)} bytes "
          f"(seed:{len(seed)} + token:{len(token)} + hash:32)")
# SHA256(combined) → 32-byte XOR key
    xor_key = hashlib.sha256(combined).digest()
    print(f"[3] SHA256(combined)    = {xor_key.hex()}")
# XOR decrypt payload
    decrypted = bytearray(len(payload))
    for i in range(len(payload)):
        decrypted[i] = payload[i] ^ xor_key[i & 0x1f]

    print(f"[4] XOR decrypt         = {decrypted.hex()}")
# Verify UVT{ magic (binary checks dword == 0x7b545655 at 0x15b2)
    if decrypted[:4] == b"UVT{":
        flag = decrypted.decode()
        print(f"\n{'='*60}")
        print(f"[+] FLAG: {flag}")
        print(f"{'='*60}")
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        print(f"[*] Saved to flag.txt")
    else:
        print(f"\n[-] Decryption failed — first 4 bytes: {decrypted[:4].hex()}")
        print(f"    Expected: 55565427 (UVT{{)")


if __name__ == "__main__":
    main()
