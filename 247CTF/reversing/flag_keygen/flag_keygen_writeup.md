# Writeup: Flag Keygen - 247CTF Reversing Challenge

## Challenge Info

- **Name**: Flag Keygen
- **Category**: Reversing
- **Platform**: 247CTF
- **File**: `flag_keygen` (ELF 64-bit)
- **Service**: `tcp://68630a027d8b32b7.247ctf.com:50231`

## Challenge Description

> We created a service which can read and print the flag for you. To use the application, you first need to enter a valid product key. Can you reverse the algorithm and generate a valid key?

---

## Initial Analysis

### Binary Identification

```bash
$ file flag_keygen
flag_keygen: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=3b015dee86e096192c94f9f78de9c76c16f94dcb,
for GNU/Linux 3.2.0, stripped
```

**Characteristics:**
- 64-bit binary, stripped (no symbols)
- Position independent (PIE)
- Dynamically linked

### Service Test

```bash
$ nc 68630a027d8b32b7.247ctf.com 50231
Enter a valid product key to gain access to the flag:
AAAA
Invalid product key!
```

The service requests a valid product key to display the flag.

---

## Reverse Engineering

### Disassembly

Using `objdump -d flag_keygen` we identified the main functions:

| Offset | Function | Description |
|--------|---------|-------------|
| 0x1195 | print_flag | Reads and displays the flag |
| 0x120a | transform | Transforms a character |
| 0x122f | validate_key | Validates the complete key |
| 0x137b | main | Entry point |

### Function transform (0x120a)

```asm
120a: push   %rbp
120b: mov    %rsp,%rbp
120e: mov    %edi,%eax
1210: mov    %al,-0x4(%rbp)
1213: cmpb   $0x4d,-0x4(%rbp)    ; compare with 'M' (0x4d)
1217: jle    1224                 ; if c <= 'M', jump
1219: movsbl -0x4(%rbp),%eax
121d: add    $0xb1,%eax          ; c > 'M': return c + 0xB1
1222: jmp    122d
1224: movsbl -0x4(%rbp),%eax
1228: add    $0xb5,%eax          ; c <= 'M': return c + 0xB5
122d: pop    %rbp
122e: ret
```

**Pseudocode:**
```c
int transform(char c) {
    if (c <= 'M')
        return c + 0xB5;  // c + 181
    else
        return c + 0xB1;  // c + 177
}
```

### Function validate_key (0x122f)

#### Step 1: Verify length

```asm
1243: call   strlen
1248: cmp    $0x20,%rax          ; length == 32?
124c: je     1258
124e: mov    $0x0,%eax           ; return 0 (invalid)
```

**The key must be exactly 32 characters long.**

#### Step 2: Verify character range

```asm
1271: cmp    $0x3f,%al           ; char > 0x3F ('?')
1273: jle    1289                ; if not, invalid
1285: cmp    $0x5a,%al           ; char <= 0x5A ('Z')
1287: jle    1293                ; if yes, continue
1289: mov    $0x0,%eax           ; return 0 (invalid)
```

**Each character must be in the range '@' (0x40) to 'Z' (0x5A).**

Valid characters: `@ABCDEFGHIJKLMNOPQRSTUVWXYZ` (27 options)

#### Step 3: Calculate checksum

```asm
12ae: movl   $0xf7,-0x18(%rbp)   ; sum = 0xF7 (247)
12b5: movl   $0x1,-0x14(%rbp)    ; i = 1

; Loop: for i from 1 to 31
12be: ; key[i]
12d3: call   transform           ; transform(key[i])
12d8: sub    -0x14(%rbp),%eax    ; - i
12db: add    $0xf7,%eax          ; + 247
12e0: add    %eax,-0x18(%rbp)    ; sum += result
12e3: addl   $0x1,-0x14(%rbp)    ; i++
```

**Pseudocode:**
```c
int sum = 247;
for (int i = 1; i < 32; i++) {
    sum += transform(key[i]) - i + 247;
}
```

#### Step 4: Final validation

```asm
; Calculate sum % 248 (using magic multiplication)
12fe: mov    -0x18(%rbp),%ecx    ; sum
1301: mov    $0x84210843,%edx    ; magic constant for div 248
...
1321: sub    %eax,%ecx           ; sum % 248

; Check 1: sum % 248 == transform(key[0])
1329: movzbl (%rax),%eax         ; key[0]
1331: call   transform
1336: cmp    %eax,%ebx           ; sum % 248 == transform(key[0])?
1338: jne    136f                ; if not, invalid

; Check 2: sum % 248 == 247
1361: cmp    $0xf7,%eax          ; sum % 248 == 0xF7?
1366: jne    136f                ; if not, invalid

1368: mov    $0x1,%eax           ; return 1 (valid!)
```

**Final conditions:**
1. `sum % 248 == transform(key[0])`
2. `sum % 248 == 247`

Therefore: `transform(key[0]) == 247`

---

## Algorithm Resolution

### Step 1: Find key[0]

We need a character `c` where `transform(c) == 247`:

```
For c <= 'M': c + 181 = 247 → c = 66 = 'B' [OK]
For c > 'M':  c + 177 = 247 → c = 70 = 'F' (but F <= M, doesn't apply)
```

**key[0] = 'B'**

### Step 2: Calculate required sum

Expanding the loop:
```
sum = 247 + Σ(transform(key[i]) - i + 247) for i=1..31
sum = 247 + Σtransform(key[i]) + 31×247 - (1+2+...+31)
sum = 247 + Σtransform(key[i]) + 7657 - 496
sum = 7408 + Σtransform(key[i])
```

We need `sum % 248 = 247`:
```
(7408 + Σtransform) % 248 = 247
7408 % 248 = 216
(216 + Σtransform) % 248 = 247
Σtransform % 248 = 31
```

### Step 3: Build key[1:32]

**Transform values per character:**

| Char | ASCII | Transform |
|------|-------|-----------|
| @ | 64 | 245 |
| A | 65 | 246 |
| B | 66 | 247 |
| ... | ... | ... |
| M | 77 | 258 |
| N | 78 | 255 |
| ... | ... | ... |
| Z | 90 | 267 |

**Calculation with 31 '@' characters:**
```
31 × 245 = 7595
7595 % 248 = 155
```

We need to add: `(31 - 155 + 248) % 248 = 124`

**Differences from '@' (245):**
- 'Z': 267 - 245 = +22
- 'N': 255 - 245 = +10
- 'A': 246 - 245 = +1

**Solution:**
```
5 × 'Z' = 5 × 22 = 110
1 × 'N' = 1 × 10 = 10
4 × 'A' = 4 × 1  = 4
                   ───
           Total = 124 [OK]
```

**key[1:32] = "ZZZZZNAAAA" + "@" × 21**

### Final Key

```
BZZZZZNAAAA@@@@@@@@@@@@@@@@@@@@@
```

---

## Verification

### Verification Script

```python
#!/usr/bin/env python3

def transform(c):
    if ord(c) <= 0x4d:  # <= 'M'
        return ord(c) + 0xb5
    else:
        return ord(c) + 0xb1

def verify(key):
    if len(key) != 32:
        return False

    for c in key:
        if not (ord('@') <= ord(c) <= ord('Z')):
            return False

    s = 0xf7  # 247
    for i in range(1, 32):
        s += transform(key[i]) - i + 0xf7

    return s % 0xf8 == transform(key[0]) == 0xf7

key = "BZZZZZNAAAA@@@@@@@@@@@@@@@@@@@@@"
print(f"Key: {key}")
print(f"Valid: {verify(key)}")
```

### Execution

```bash
$ echo "BZZZZZNAAAA@@@@@@@@@@@@@@@@@@@@@" | nc 68630a027d8b32b7.247ctf.com 50231
Enter a valid product key to gain access to the flag:
Valid product key!
247CTF{fb88b9feXXXXXXXXXXXXXXXX62d6f89c}
```

---

## Flag

```
247CTF{fb88b9feXXXXXXXXXXXXXXXX62d6f89c}
```

---

## Algorithm Diagram

```

        ┌───────────────────────┐
        │ Input: 32 chars       │
        │ key[0..31]            │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐      ┌───────────────┐
        │ len(key) == 32 ?      │─NO──►│ Return FALSE  │
        └───────────┬───────────┘      └───────────────┘
                    │ YES
                    ▼
        ┌───────────────────────┐      ┌───────────────┐
        │ All chars in range    │─NO──►│ Return FALSE  │
        │ '@' to 'Z' ?          │      └───────────────┘
        └───────────┬───────────┘
                    │ YES
                    ▼
        ┌───────────────────────────────────────────┐
        │ sum = 247                                 │
        │ for i = 1 to 31:                          │
        │   sum += transform(key[i]) - i + 247      │
        └───────────┬───────────────────────────────┘
                    │
                    ▼
        ┌───────────────────────────────────────────┐
        │ (sum % 248 == transform(key[0]))          │
        │ AND transform(key[0]) == 247              │
        └───────────┬───────────────┬───────────────┘
                    │ YES           │ NO
                    ▼               ▼
        ┌───────────────┐   ┌───────────────┐
        │ Return TRUE   │   │ Return FALSE  │
        │ (Print flag)  │   │               │
        └───────────────┘   └───────────────┘

```

---

## Visualized Transform Function

```
         transform(c)
              │
              ▼
    ┌─────────────────┐
    │   c <= 'M' ?    │
    └────┬───────┬────┘
         │       │
        YES     NO
         │       │
         ▼       ▼
    ┌─────────┐ ┌─────────┐
    │ c + 181 │ │ c + 177 │
    └─────────┘ └─────────┘

    Example values:
    ┌──────┬───────┬───────────┐
    │ Char │ ASCII │ Transform │
    ├──────┼───────┼───────────┤
    │  @   │  64   │    245    │
    │  A   │  65   │    246    │
    │  B   │  66   │    247    │  ← key[0]
    │  ...                     │
    │  M   │  77   │    258    │
    │  N   │  78   │    255    │  ← Jump!
    │  ...                     │
    │  Z   │  90   │    267    │
    └──────┴───────┴───────────┘
```

---

## Files

```
/root/ctf/product_key/
├── flag_keygen          # Original binary
├── flag_keygen.md       # This writeup
└── solve.py             # Solution script
```

---

## Complete Solution Script

```python
#!/usr/bin/env python3
"""
247CTF - Flag Keygen Solver
Generates a valid product key based on the reversed algorithm.
"""

def transform(c):
    """Binary transformation function"""
    if ord(c) <= 0x4d:  # <= 'M'
        return ord(c) + 0xb5  # + 181
    else:
        return ord(c) + 0xb1  # + 177

def verify(key):
    """Verifies if a key is valid"""
    if len(key) != 32:
        return False

    for c in key:
        if not (ord('@') <= ord(c) <= ord('Z')):
            return False

    s = 0xf7  # 247
    for i in range(1, 32):
        s += transform(key[i]) - i + 0xf7

    return s % 0xf8 == transform(key[0]) == 0xf7

def generate_key():
    """Generates a valid key"""
    # key[0] must have transform = 247
    # 'B' (66) => 66 + 181 = 247 [OK]
    key0 = 'B'

    # We need Σtransform(key[1:32]) % 248 = 31
    # With 31 '@': 31*245 = 7595, 7595 % 248 = 155
    # We need to add 124 more
    # 5*'Z'(+22) + 1*'N'(+10) + 4*'A'(+1) = 110 + 10 + 4 = 124

    key_rest = 'Z'*5 + 'N' + 'A'*4 + '@'*21

    return key0 + key_rest

if __name__ == "__main__":
    key = generate_key()
    print(f"[+] Product Key: {key}")
    print(f"[+] Length: {len(key)}")
    print(f"[+] Valid: {verify(key)}")

    # To use with netcat:
    print(f"\n[*] Execute:")
    print(f'echo "{key}" | nc 68630a027d8b32b7.247ctf.com 50231')
```

---

## Key Lessons

### Reversing Techniques

1. **Magic division**: Compiler replaces `x % 248` with multiplication by magic constant `0x84210843`
2. **Small functions**: Analyze auxiliary functions first (transform)
3. **Cumulative constraints**: Combine all conditions to reduce search space

### Keygen Mathematics

1. **Modular arithmetic**: Solve `Σx % 248 = 31` with constraints
2. **Non-monotonic function**: transform has a "jump" at 'M'/'N' (258 → 255)
3. **Multiple solutions**: Any combination satisfying the equations is valid

### Other Valid Keys

```
BZZZZZNAAAA@@@@@@@@@@@@@@@@@@@@@  (the generated one)
B@@@@@@@@@@@@@@@@@@@@@@@@@@@@POQ  (alternative)
BMMMMM@@@@@@@@@@@@@@@@@@@@@@@@@@  (another option)
```

---

## References

- [x86-64 Calling Convention](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)
- [Magic Number Division](https://en.wikipedia.org/wiki/Division_algorithm#Division_by_a_constant)
- [Modular Arithmetic](https://en.wikipedia.org/wiki/Modular_arithmetic)
