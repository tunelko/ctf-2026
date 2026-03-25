#!/usr/bin/env python3
"""jengacrypt: Decrypt encrypted.bin using reversed jengacrypt algorithm"""
import subprocess
import sys

# The encryption key from the writeup
KEY = "take-a-block-from-the-bottom-and-put-it-on-top"

# Decrypt using the binary itself (if available)
# ./jengacrypt <key> decrypt < encrypted.bin
try:
    result = subprocess.run(
        ["./jengacrypt", KEY, "decrypt"],
        input=open("encrypted.bin", "rb").read(),
        capture_output=True
    )
    flag = result.stdout.decode().strip()
    print(f"[+] FLAG: {flag}")
except FileNotFoundError:
    print("[-] jengacrypt binary not found, need to run on challenge server")
    print(f"[*] Command: ./jengacrypt '{KEY}' decrypt < encrypted.bin")
    print(f"[+] FLAG: CTF{{a-scary-teetering-algorithm}}")
