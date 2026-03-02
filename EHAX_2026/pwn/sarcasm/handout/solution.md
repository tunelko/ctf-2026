# SarcAsm - PWN Challenge

## Challenge Info
- **Name**: Unsarcastically, introducing the best asm in market: SarcAsm
- **Category**: pwn
- **Authors**: nrg & the_moon_guy
- **Remote**: `nc 20.244.7.184 9999`
- **Flag**: `EH4X{l00ks_l1k3_1_n33d_4_s4rc4st1c_tut0r14l}`

## Binary Analysis

```
$ checksec --file=sarcasm
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

Fully protected binary. Custom stack-based VM interpreter with its own assembly language ("SarcAsm"). Includes an unreachable `execve("/bin/sh")` function at offset `0x3000`.

### VM Instruction Set

| Opcode | Mnemonic | Description |
|--------|----------|-------------|
| PUSH N | Push integer | |
| NEWBUF N | Create buffer (capacity N) | |
| WRITEBUF off len | Read `len` bytes from stdin at buffer offset | |
| SLICE off len | Create slice sharing parent data | |
| PRINTB | Print buffer/slice contents | |
| GSTORE N | Store to global variable N | |
| GLOAD N | Load from global variable N | |
| BUILTIN N | Push builtin function object N | |
| CALL N | Call builtin with N args | |
| GC | Trigger garbage collection | |
| HALT | Stop execution | |

### Object Types

- **Buffer (type 1)**: Heap-allocated data, supports WRITEBUF
- **Slice (type 2)**: Shares parent buffer's data pointer
- **Builtin (type 3)**: Function object with indirect function pointer at `data+8`

### Pool Allocator

Size classes: 0x10, 0x20, 0x40, 0x80, ... with LIFO freelist per class. Every allocation has 8-byte header `[size:4][mark:4]`, usable data at `+8`.

- BUILTIN data: `pool_alloc(0x20)` → class 0x20
- NEWBUF N: `pool_alloc(N)` → rounds up to nearest class (N=17-32 → class 0x20)

## Vulnerability

**GC Use-After-Free via Slice Data Sharing**

The garbage collector frees dead objects' data buffers via `pool_free(obj->field_18)`. Since a **slice** shares its parent buffer's `field_18` data pointer:

1. If the **parent buffer is dead** → GC frees the data → slice's data pointer dangles (classic UAF)
2. If the **slice is dead** but parent is alive → GC frees `slice->field_18` = parent's data, **while the parent buffer is still alive** with a writable dangling pointer

Bug #2 is the critical primitive: we get a **live buffer with WRITEBUF capability** whose data chunk is freed and returned to the pool freelist.

## Exploitation

### Phase 1: PIE Leak

1. Create `buf_a` (capacity 32, pool class 0x20)
2. Write 8 bytes, create `slice_a = SLICE(0, 8)`
3. Drop `buf_a` ref, trigger GC → frees `buf_a` data, `slice_a` dangles
4. `BUILTIN 0` → `pool_alloc(0x20)` reuses freed chunk, writes print function pointer at `data+8`
5. `PRINTB slice_a` → leaks function pointer → compute PIE base

### Phase 2: Function Pointer Overwrite

1. Create `buf_b` (capacity 32, pool class 0x20)
2. Write 8 bytes, create `slice_b = SLICE(0, 8)`
3. Drop ONLY `slice_b` ref, trigger GC → GC frees `slice_b->field_18` = `buf_b`'s data (while `buf_b` alive!)
4. `BUILTIN 1` → `pool_alloc(0x20)` reuses freed chunk → overlap with `buf_b`
5. `WRITEBUF 0 8` on `buf_b` → reads 8 bytes from stdin → overwrites BUILTIN 1's function pointer at `data+8` with `execve_shell` address
6. `CALL 0` on corrupted BUILTIN 1 → `call rax` → `execve("/bin/sh")`

### Stdin Data Flow

```
[bytecode] [8 bytes pad1] [8 bytes pad2] → PRINTB outputs leak → [8 bytes target addr]
```

## Scripts

- `exploit.py` - Full exploit with LOCAL/REMOTE/GDB support

```bash
python3 exploit.py          # LOCAL
python3 exploit.py REMOTE   # REMOTE
python3 exploit.py GDB      # DEBUG
```

## Key Lessons

1. **Slice data sharing is dangerous**: When a GC-managed slice shares its parent's data pointer, freeing either object frees the shared data for both
2. **Pool allocator reuse**: LIFO freelists make UAF-to-overlap predictable when you control allocation order and sizes
3. **Indirect call via heap data**: The BUILTIN object stores its function pointer in a heap-allocated data buffer, making it overwritable through UAF
4. **Two-phase exploit**: Leak first (read dangling slice), then overwrite (write via live buffer whose data was freed)

## Files

- `sarcasm` - Challenge binary
- `libc.so.6` - Provided libc (glibc 2.35)
- `ld-linux-x86-64.so.2` - Provided dynamic linker
- `exploit.py` - Exploit script
- `flag.txt` - Captured flag
- `solution.md` - This writeup
