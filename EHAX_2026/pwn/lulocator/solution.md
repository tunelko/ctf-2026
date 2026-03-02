# lulocator

**Category:** pwn
**Points:** 490
**Remote:** `nc chall.ehax.in 40137`
**Description:** Who needs that buggy malloc? Made my own completely safe lulocator.

**Flag:** `EH4X{unf0rtun4t3ly_th3_lul_1s_0n_m3}`

---

## Analysis

### Binary protections

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

Stripped binary, glibc 2.35.

### Functionality

Menu-driven heap allocator with 7 operations:

| Option | Function | Description |
|--------|----------|-------------|
| 1 | new | Allocate object with custom size |
| 2 | write | Write data into object's buffer |
| 3 | delete | Free object |
| 4 | info | Leak object address, stdout pointer, capacity |
| 5 | set_runner | Store object pointer in global `runner` |
| 6 | run | Call `runner->func_ptr(runner+0x28)` |
| 7 | quit | Exit |

### Custom allocator internals

- Arena: single `mmap(0x40000)` region, bump allocator with free list
- Chunk layout: `[8-byte header (size|in_use_bit)] [object data]`
- Free list: circular doubly-linked list with sentinel at `0x404850`
- Safe-unlink on `free_list_remove` (during malloc): `fwd->bk == node && bk->fwd == node`
- First-fit search: `(chunk_header & ~0xF) >= aligned_needed`

### Object layout (returned by `handler_new`)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8 | field_0 (free list fwd when freed) |
| 0x08 | 8 | field_1 (free list bk when freed) |
| 0x10 | 8 | func_ptr (default: `0x401608`) |
| 0x18 | 8 | FILE* stdout |
| 0x20 | 8 | capacity |
| 0x28+ | N | data buffer |

---

## Vulnerability

### Heap overflow in `handler_write` (0x401978)

The write handler checks:
```c
if (capacity + 0x18 >= user_len) {
    read_exact(0, obj + 0x28, user_len);
}
```

This allows writing `capacity + 0x18` bytes into a buffer of only `capacity` bytes — a **24-byte overflow** past the data area.

### What the overflow reaches

For size=64 objects (chunk size 0x70):
- Bytes 0-63: object's own data
- Bytes 64-71: **next chunk's header** (8 bytes)
- Bytes 72-79: next object's field_0
- Bytes 80-87: next object's field_1

The overflow **cannot** directly reach `func_ptr` at offset +0x10 of the next object (would need 8 more bytes).

### Libc leak via `info`

The `info` command prints `obj+0x18` which is the stored stdout FILE pointer — a direct libc leak.

---

## Exploitation: Overlapping Chunks via Fake Chunk Size

Since the overflow can corrupt the next chunk's header but can't reach `func_ptr` directly, we use the overflow to create an **overlapping allocation**:

### Step-by-step

1. **Allocate A, B, C** (size=64 each, chunk=0x70 each)
   ```
   Arena: [A: 0x70][B: 0x70][C: 0x70]
   ```

2. **Leak libc** via `info(C)` → stdout pointer → libc base → `system()`

3. **Set runner = C** via `set_runner(C)`

4. **Overflow from A** to corrupt B's chunk header:
   - Write 88 bytes (64 data + 24 overflow)
   - Overwrite B's chunk header from `0x71` to `0xE1` (fake size 0xE0 covering B+C)

5. **Free B** → goes to free list with fake size 0xE0
   - Safe-unlink passes because B is the only free list element

6. **Allocate D** (size=168) → `custom_malloc(168+0x28=0xC0)` → aligned 0xD0
   - Free list search finds B with size 0xE0 ≥ 0xD0 → uses B's chunk
   - D's data area (168 bytes) overlaps C's entire metadata
   ```
   Arena: [A: 0x70][D: ......0xE0......] (overlapping C)
   ```

7. **Write through D** to overwrite C's fields:
   - Offset 88 from D's data → C's `func_ptr` = `system()`
   - Offset 112 from D's data → C's data = `"/bin/sh\0"`

8. **run()** → calls `runner->func_ptr(runner+0x28)` = `system("/bin/sh")` → shell!

---

## Exploit

```bash
python3 exploit.py          # LOCAL
python3 exploit.py REMOTE   # REMOTE
python3 exploit.py GDB      # GDB
```

See `exploit.py` for the full exploit.

---

## Key Lessons

1. **Off-by-0x18 overflow**: Even small heap overflows can be devastating when they corrupt allocator metadata (chunk headers)
2. **Fake chunk size → overlapping allocation**: Corrupting the size field in a chunk header creates overlapping allocations, turning a limited overflow into arbitrary write within the heap
3. **Safe-unlink bypass**: The safe-unlink check on removal is satisfied when the freed chunk is the only element in the free list (trivial circular DLL)
4. **`info` leak**: Storing libc pointers (stdout) in heap objects without stripping them provides easy leaks
5. **Function pointer + controlled argument**: The `run` command's `func_ptr(data)` pattern is a classic call-primitive — overwriting `func_ptr` with `system` and `data` with `"/bin/sh"` gives instant shell

---

## Files

- `exploit.py` — Full exploit with LOCAL/REMOTE/GDB support
- `lulocator` — Challenge binary
- `libc.so.6` — glibc 2.35 (Ubuntu)
- `flag.txt` — Captured flag
- `solution.md` — This writeup
