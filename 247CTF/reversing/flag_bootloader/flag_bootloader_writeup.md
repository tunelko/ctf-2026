# Writeup: Flag Bootloader - 247CTF Reversing Challenge

## Challenge Info

- **Name**: Flag Bootloader
- **Category**: Reversing
- **Platform**: 247CTF
- **File**: `flag.com` (512 bytes)

## Challenge Description

> Can you unlock the secret boot sequence hidden within our flag bootloader to recover the flag?

---

## Initial Analysis

### File Identification

```bash
$ file flag.com
flag.com: DOS/MBR boot sector

$ ls -la flag.com
-rw-rw-r-- 1 root root 512 Apr 12  2020 flag.com
```

The file is a **512-byte bootloader** - exactly the size of a boot sector (MBR). The last two bytes are the boot signature `55 AA`.

### Hexadecimal Inspection

```bash
$ xxd flag.com | tail -10
000001a0: 6420 636f 6465 210a 0d00 3234 3743 5446  d code!...247CTF
000001b0: 7b77 2167 3060 350c 0c78 792e 2e20 7270  {w!g0`5..xy.. rp
000001c0: 7529 2b00 5c21 7062 6365 6007 0d06 023b  u)+.\!pbce`....;
000001d0: 3b7d 0a0d 000a 000a 0d4e 6f20 6d65 6d6f  ;}.......No memo
000001e0: 7279 210a 0d00 0000 0000 0000 0000 0000  ry!.............
000001f0: 0000 0000 0000 0000 0000 0000 0000 55aa  ..............U.
```

**Key findings:**
- String "Unlock code:" at offset 0x18b
- String "Invalid code!" at offset 0x19a
- Encoded flag: `247CTF{w!g0`5..xy.. rp...}` at offset 0x1aa
- Boot signature `55 AA` at the end

The flag is **encoded/obfuscated** - we need the unlock code to decode it.

---

## Code Analysis

### Disassembly (16-bit x86)

```bash
$ objdump -D -b binary -m i8086 -M intel flag.com
```

### Bootloader Structure

```
┌─────────────────────────────────────────────────────────────┐
│  BOOTLOADER STRUCTURE (512 bytes)                           │
├─────────────────────────────────────────────────────────────┤
│  0x000-0x022: Helper functions (print, getchar)             │
│  0x023-0x069: Main loop - requests unlock code              │
│  0x06a-0x17b: Validation routine (16 checks)                │
│  0x17c-0x18a: Error handling and exit                       │
│  0x18b-0x1d4: Strings (messages and encoded flag)           │
│  0x1d5-0x1fd: Padding (zeros)                               │
│  0x1fe-0x1ff: Boot signature (55 AA)                        │
└─────────────────────────────────────────────────────────────┘
```

### Validation Routine (0x06a - 0x17b)

The routine validates 16 characters of the unlock code. Each validation follows the same pattern:

```asm
mov al, 0xXX        ; Load base value
xor al, 0xYY        ; XOR with constant (or SUB)
cmp [bx], al        ; Compare with user input
jne error           ; Jump if doesn't match
xor [si], al        ; Decode 2 bytes of the flag
inc si
xor [si], al
inc bx
inc si
```

**Each correct character:**
1. Is validated against a calculated value
2. Is used as an **XOR key** to decode 2 bytes of the flag

---

## Unlock Code Extraction

### Analysis of the 16 Validations

| Offset | Instructions | Calculation | Result |
|--------|--------------|-------------|--------|
| 0x074 | `mov al,0x4b; xor al,0x0c` | 0x4B ^ 0x0C | 0x47 = 'G' |
| 0x085 | `mov al,0x53; xor al,0x06` | 0x53 ^ 0x06 | 0x55 = 'U' |
| 0x096 | `mov al,0x58; sub al,0x01` | 0x58 - 0x01 | 0x57 = 'W' |
| 0x0a7 | `mov al,0x62; sub al,0x29` | 0x62 - 0x29 | 0x39 = '9' |
| 0x0b8 | `mov al,0x68; xor al,0x23` | 0x68 ^ 0x23 | 0x4B = 'K' |
| 0x0c9 | `mov al,0x4b; xor al,0x00` | 0x4B ^ 0x00 | 0x4B = 'K' |
| 0x0da | `mov al,0x62; sub al,0x1e` | 0x62 - 0x1E | 0x44 = 'D' |
| 0x0eb | `mov al,0x4d; sub al,0x0b` | 0x4D - 0x0B | 0x42 = 'B' |
| 0x0fc | `mov al,0x45; xor al,0x0d` | 0x45 ^ 0x0D | 0x48 = 'H' |
| 0x10b | `mov al,0x10; xor al,0x28` | 0x10 ^ 0x28 | 0x38 = '8' |
| 0x11a | `mov al,0x58; xor al,0x1d` | 0x58 ^ 0x1D | 0x45 = 'E' |
| 0x129 | `mov al,0x7a; xor al,0x28` | 0x7A ^ 0x28 | 0x52 = 'R' |
| 0x138 | `mov al,0x65; sub al,0x13` | 0x65 - 0x13 | 0x52 = 'R' |
| 0x147 | `mov al,0x33; xor al,0x07` | 0x33 ^ 0x07 | 0x34 = '4' |
| 0x156 | `mov al,0x25; xor al,0x15` | 0x25 ^ 0x15 | 0x30 = '0' |
| 0x165 | `mov al,0x4c; add al,0x0c` | 0x4C + 0x0C | 0x58 = 'X' |

### Unlock Code

```
GUW9KKDBH8ERR40X
```

---

## Flag Decoding

### Encoded Flag (offset 0x1b1)

```
77 21 67 30 60 35 0c 0c 78 79 2e 2e 20 72 70 75
29 2b 00 5c 21 70 62 63 65 60 07 0d 06 02 3b 3b
```

### Decoding Process

Each character of the unlock code is an XOR key that decodes 2 bytes of the flag:

```
Key 'G' (0x47): 77 ^ 47 = '0', 21 ^ 47 = 'f'  → "0f"
Key 'U' (0x55): 67 ^ 55 = '2', 30 ^ 55 = 'e'  → "2e"
Key 'W' (0x57): 60 ^ 57 = '7', 35 ^ 57 = 'b'  → "7b"
Key '9' (0x39): 0c ^ 39 = '5', 0c ^ 39 = '5'  → "55"
Key 'K' (0x4B): 78 ^ 4b = '3', 79 ^ 4b = '2'  → "32"
Key 'K' (0x4B): 2e ^ 4b = 'e', 2e ^ 4b = 'e'  → "ee"
Key 'D' (0x44): 20 ^ 44 = 'd', 72 ^ 44 = '6'  → "d6"
Key 'B' (0x42): 70 ^ 42 = '2', 75 ^ 42 = '7'  → "27"
Key 'H' (0x48): 29 ^ 48 = 'a', 2b ^ 48 = 'c'  → "ac"
Key '8' (0x38): 00 ^ 38 = '8', 5c ^ 38 = 'd'  → "8d"
Key 'E' (0x45): 21 ^ 45 = 'd', 70 ^ 45 = '5'  → "d5"
Key 'R' (0x52): 62 ^ 52 = '0', 63 ^ 52 = '1'  → "01"
Key 'R' (0x52): 65 ^ 52 = '7', 60 ^ 52 = '2'  → "72"
Key '4' (0x34): 07 ^ 34 = '3', 0d ^ 34 = '9'  → "39"
Key '0' (0x30): 06 ^ 30 = '6', 02 ^ 30 = '2'  → "62"
Key 'X' (0x58): 3b ^ 58 = 'c', 3b ^ 58 = 'c'  → "cc"
```

### Decoded Flag

```
247CTF{0f2e7b55XXXXXXXXXXXXXXXX723962cc}
```

---

## Solution Script

```python
#!/usr/bin/env python3
"""
247CTF - Flag Bootloader Solver
Extracts the unlock code and decodes the flag
"""

with open('flag.com', 'rb') as f:
    data = f.read()

# Extract XOR keys from verification code
xor_keys = []
i = 0x74  # First mov al instruction

while i < 0x180:
    if data[i] == 0xb0:  # mov al, imm8
        val = data[i+1]
        op = data[i+2]
        operand = data[i+3]

        # Look for cmp [bx], al (38 07)
        for j in range(i+4, min(i+10, len(data)-1)):
            if data[j] == 0x38 and data[j+1] == 0x07:
                if op == 0x34:    # xor
                    result = val ^ operand
                elif op == 0x2c:  # sub
                    result = val - operand
                elif op == 0x04:  # add
                    result = (val + operand) & 0xff
                else:
                    break
                xor_keys.append(result)
                break
    i += 1

# Unlock code
unlock_code = ''.join(chr(k) for k in xor_keys)
print(f"Unlock code: {unlock_code}")

# Decode the flag
flag_start = 0x1aa
flag = bytearray(b"247CTF{")
encoded = data[flag_start + 7:]

for i, key in enumerate(xor_keys):
    flag.append(encoded[i*2] ^ key)
    flag.append(encoded[i*2 + 1] ^ key)

flag.append(ord('}'))
print(f"Flag: {flag.decode()}")
```

---

## Flag

```
247CTF{0f2e7b55XXXXXXXXXXXXXXXX723962cc}
```

---

## Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    BOOTLOADER FLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐                                        │
│  │  Print "Unlock  │                                        │
│  │  code:"         │                                        │
│  └────────┬────────┘                                        │
│           ▼                                                 │
│  ┌─────────────────┐                                        │
│  │  Read 16 chars  │◄──────────────────────┐                │
│  │  from keyboard  │                       │                │
│  └────────┬────────┘                       │                │
│           ▼                                │                │
│  ┌─────────────────┐     ┌─────────────┐   │                │
│  │  Validate char  │────►│  XOR decode │   │                │
│  │  against calc   │ OK  │  2 flag     │   │                │
│  │  value          │     │  bytes      │   │                │
│  └────────┬────────┘     └─────────────┘   │                │
│           │ FAIL                           │                │
│           ▼                                │                │
│  ┌─────────────────┐                       │                │
│  │  Print "Invalid │                       │                │
│  │  code!"         │───────────────────────┘                │
│  └─────────────────┘                                        │
│                                                             │
│  After 16 valid chars:                                      │
│  ┌─────────────────┐                                        │
│  │  Print decoded  │                                        │
│  │  FLAG!          │                                        │
│  └─────────────────┘                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Lessons Learned

### Reversing Techniques

1. **Bootloaders are 16-bit code**: Use `objdump -m i8086` for correct disassembly
2. **Repetitive patterns**: Identify similar validation structures
3. **XOR is reversible**: If A ^ B = C, then C ^ B = A

### Design Observations

1. **Simple obfuscation**: XOR/SUB/ADD operations add a layer of indirection
2. **Dual-purpose keys**: Code characters serve both for validation and decoding
3. **Fixed size**: 512 bytes limit code complexity

### Useful Tools

- `objdump -D -b binary -m i8086 -M intel` - 16-bit disassembly
- `xxd` / `hexdump` - Hexadecimal inspection
- Python with `struct` - Binary parsing

---

## Files

```
/root/ctf/bootloader/
├── flag_bootloader.md    # This writeup
├── flag.com              # Original bootloader (512 bytes)
└── solve.py              # Solution script
```

---

## References

- [x86 Real Mode](https://wiki.osdev.org/Real_Mode) - Real mode documentation
- [MBR Boot Sector](https://wiki.osdev.org/MBR) - Boot sector structure
- [BIOS Interrupts](https://wiki.osdev.org/BIOS) - INT 10h (video), INT 16h (keyboard)
