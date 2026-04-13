#!/usr/bin/env python3
"""Lego Clicker — UMassCTF 2026 (rev, 100pts)
Android APK with native lib (liblegocore.so). Multiple fake flags (BHREV{...}).
Real flag from refreshTileMap native → builds 41-byte binary, hex-encodes it.
Emulated using Unicorn to run init functions + flag builder from x86_64 .so."""
from unicorn import *
from unicorn.x86_const import *
import struct, sys

SO_PATH = sys.argv[1] if len(sys.argv) > 1 else "challenge/jadx_out/resources/lib/x86_64/liblegocore.so"
with open(SO_PATH, "rb") as f:
    so_data = f.read()

BASE = 0x400000
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x100000, 0xB00000)
mu.mem_write(0x600000 + 0x28, struct.pack('<Q', 0xDEADBEEFCAFEBABE))
mu.msr_write(0xC0000100, 0x600000)
mu.mem_write(BASE, so_data[:0x4c3f0])
mu.mem_write(BASE + 0x503f0, so_data[0x4c3f0:0x4c3f0+0x4118])
mu.mem_write(BASE + 0x58508, so_data[0x50508:0x50508+0x58])

STACK, HEAP = 0xBFF000, 0x800000
heap_ptr = [HEAP]
rsp = STACK - 0x200
ret_addr = 0xA00000
mu.mem_write(ret_addr, b'\xCC')

def hook(uc, addr, sz, _):
    a = addr - BASE
    if a == 0x4bc70:  # malloc
        s = max(uc.reg_read(UC_X86_REG_RDI), 8)
        p = heap_ptr[0]; heap_ptr[0] += (s + 0x1f) & ~0xf
        uc.reg_write(UC_X86_REG_RAX, p)
        r = struct.unpack('<Q', uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
        uc.reg_write(UC_X86_REG_RIP, r)
    elif a == 0x4bc80:  # free
        r = struct.unpack('<Q', uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
        uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP) + 8)
        uc.reg_write(UC_X86_REG_RIP, r)
mu.hook_add(UC_HOOK_CODE, hook)

# Init BSS data + function pointers (.init_array)
for fn in [0x20fa0, 0x20370]:
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.mem_write(rsp-8, struct.pack('<Q', ret_addr))
    mu.reg_write(UC_X86_REG_RSP, rsp-8)
    mu.emu_start(BASE + fn, ret_addr, timeout=5000000)

# Call 0x20740 (flag builder used by refreshTileMap)
heap_ptr[0] = HEAP + 0x10000
buf = rsp - 0x400
mu.mem_write(buf, b'\x00' * 64)
mu.reg_write(UC_X86_REG_RSP, rsp)
mu.mem_write(rsp-8, struct.pack('<Q', ret_addr))
mu.reg_write(UC_X86_REG_RSP, rsp-8)
mu.reg_write(UC_X86_REG_RDI, buf)
mu.emu_start(BASE + 0x20740, ret_addr, timeout=10000000, count=2000000)

data = mu.mem_read(buf, 48)
sz = (struct.unpack_from('<Q', data, 8)[0] if data[0] & 1
      else data[0] >> 1)
ptr = (struct.unpack_from('<Q', data, 16)[0] if data[0] & 1
       else None)
raw = bytes(mu.mem_read(ptr, sz) if ptr else data[1:1+sz])

print(f"[+] FLAG: UMASS{{{raw.hex()}}}")
