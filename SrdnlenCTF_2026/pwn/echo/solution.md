# echo

| Field | Value |
|-------|-------|
| Platform | srdnlenIT2026 |
| Category | pwn |
| Difficulty | Medium |
| Remote | `nc echo.challs.srdnlen.it 1091` |

## Description
> Echo is one of the most famous and simple programs on any system. Nothing can go wrong if I re-implement it, right?

## TL;DR
Off-by-one in `read_stdin` (`jae` instead of `ja`) lets us overflow by 1 byte, progressively expanding the read size. Combined with a missing null-terminator on the overflow exit path, we leak canary, PIE, and libc from the stack, then ROP to `system("/bin/sh")`.

## Initial Analysis

```
echo: ELF 64-bit LSB pie executable, x86-64, dynamically linked
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

Binary has 3 functions: `main`, `echo`, `read_stdin`.

- `echo()`: buffer `s[64]` at `rbp-0x50`, `var_10h` (max_len byte) at `rbp-0x10` initialized to `0x40`.
  Loop: `printf("echo ")` → `read_stdin(s, var_10h)` → if `s[0] != 0` → `puts(s)` → repeat.
- `read_stdin(buf, max)`: reads byte-by-byte via `read(0, buf+i, 1)`. Loop uses `jae` (>=) comparison instead of `ja` (>), reading **max+1 bytes** (off-by-one).

## Vulnerabilities Identified

### 1. Off-by-one (CWE-193)
`read_stdin` loop condition `jae` (unsigned >=) instead of `ja` (unsigned >) reads one extra byte. Byte 64 overwrites `var_10h`, controlling how many bytes are read in the NEXT round.

### 2. Missing null-terminator on overflow path
When the loop exits via counter exceeding max (the off-by-one path), `read_stdin` does NOT null-terminate the buffer. Only newline and read-error paths null-terminate. This means `puts(s)` leaks stack contents past our input.

### 3. Counter byte wrap
With `max_len=0xFF`, the counter (stored as byte) wraps from 0x100 back to 0x00, creating an infinite read loop. Must use `\n` to terminate.

## Solution Steps

### 5-Round exploit chain

**R1** (max_len=0x40→0x48): Send 65 bytes. Byte 64 sets next max_len to 0x48.

**R2** (max_len=0x48, leak canary): Send 73 bytes. Byte 72 overwrites canary's null byte (byte 0). No null-termination on overflow path → `puts` leaks canary bytes 1-7.

**R3** (max_len=0x58, leak PIE): Send 89 bytes. Overwrites through canary and saved_rbp. Byte 88 overwrites return address byte 0 (known to be 0x42 from `PIE+0x1342`). Leak return address bytes 1-5 → compute PIE base.

**R4** (max_len=0x77, leak libc): Send 120 bytes. Fills stack all the way through main's frame (including argc which has null bytes). `puts` leaks `__libc_start_call_main` return address at offset 120+.

**R5** (max_len=0xFF, ROP): Send payload with `s[0]=\x00` (exit loop), restored canary, ROP chain: `ret` (alignment) → `pop rdi; ret` → `/bin/sh` → `system()`. Terminate with `\n` to avoid counter wrap.

### Stack layout from `s[0]`
```
0-63:    buffer s
64:      var_10h (max_len byte)
65-71:   padding
72-79:   stack canary
80-87:   echo's saved rbp
88-95:   echo's return address (-> main+0x53)
96-103:  main's argv
104-111: main's gap + argc (has null bytes!)
112-119: main's saved rbp
120-127: __libc_start_call_main ret address (LIBC LEAK)
```

## Exploit Script

See `solve.py`. Run with:
```bash
python3 solve.py           # Local
python3 solve.py REMOTE    # Remote
python3 solve.py GDB       # Debug
```

## Flag
```
srdnlen{1_Byt3_70_Rul3_7h3m_4ll,_1_Byt3_70_F1nd_7h3m,_1_Byt3_70_Br1n6_7h3m_4ll_4nd_1n_7h3_D4rkn355_B1nd_7h3m}
```

## Key Lessons
- Off-by-one from `>=` vs `>` comparison is subtle but gives full control when it overwrites a "length" variable
- Missing null-termination on one code path creates powerful info leaks via `puts`
- Single-byte counters can wrap (0xFF+1=0x00), causing infinite loops — use `\n` to terminate
- Stack residue from `main`'s caller (`__libc_start_call_main`) provides libc leak without needing GOT dereference
- Progressive max_len expansion: 0x40 → 0x48 → 0x58 → 0x77 → 0xFF gives increasingly deeper stack access

## Files

```
pwn/echo/
├── echo            # Binary
├── solve.py        # Full exploit (LOCAL/REMOTE/GDB)
├── flag.txt        # Captured flag
└── solution.md     # This writeup
```
