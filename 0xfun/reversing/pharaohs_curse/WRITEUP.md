# Pharaoh's Curse — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Reversing
**Points:** 100
**Difficulty:** Easy
**Author:** SwitchCaseAdvocate
**Flag:** `0xfun{ph4r40h_vm_1nc3pt10n}`

> *"The pharaoh's tomb holds ancient secrets. Only those who speak the old tongue may enter."*

---

## Summary

A two-stage reversing challenge with nested VMs (inception):

1. **Stage 1** -- `tomb_guardian`: ELF binary with a custom stack-based VM that verifies a password through XOR operations. When correct, it prints the 7z archive password.
2. **Stage 2** -- `hiero_vm` + `challenge.hiero`: Rust interpreter that executes a program written with Egyptian hieroglyphs and cuneiform characters. The program reads 27 characters and validates them with arithmetic constraints (ADD mod 256). Solved with Z3.

---

## Provided Files

| File | Type | Description |
|------|------|-------------|
| `tomb_guardian` | ELF 64-bit x86-64, stripped | Custom VM, first layer |
| `sacred_chamber.7z` | Password-protected 7z | Contains the second layer |

---

## Stage 1: tomb_guardian

### Initial Reconnaissance

```
$ file tomb_guardian
ELF 64-bit LSB pie executable, x86-64, stripped

$ strings tomb_guardian | grep -i flag
(nothing relevant)
```

The binary is stripped and uses `getc`/`putc` for I/O. It also imports `ptrace` as an anti-debug technique.

### Static Analysis

With radare2, the binary structure is identified:

- **0x4040** (676 bytes): VM bytecode array
- **0x4300**: function pointer table (dispatch table)
- `main` initializes the VM and calls the execution loop

### VM Architecture

Stack-based VM with the following components:
- 8 8-bit registers (`r0`-`r7`)
- 256 bytes of memory
- 256-byte stack with `sp` pointer
- Instruction pointer `ip`

**Opcode Table:**

| Opcode | Mnemonic | Description |
|--------|----------|-------------|
| `0x00` | NOP | No operation |
| `0x01 XX` | PUSH XX | Push immediate to stack |
| `0x02 RR` | POP RR | Pop to register |
| `0x03 RR` | PUSHR RR | Push from register |
| `0x04 AA` | STORE AA | Pop to memory address |
| `0x05 AA` | LOAD AA | Push from memory address |
| `0x10` | ADD | Pop two values, push sum |
| `0x11` | SUB | Pop two values, push difference |
| `0x12` | XOR | Pop two values, push XOR |
| `0x13` | AND | Pop two values, push AND |
| `0x14` | OR | Pop two values, push OR |
| `0x20` | CMP_EQ | Pop two values, push 1 if equal, 0 if not |
| `0x30 LO HI` | JMP | Unconditional jump to address LO\|HI<<8 |
| `0x31 LO HI` | JZ | Jump if TOS == 0 |
| `0x32 LO HI` | JNZ | Jump if TOS != 0 |
| `0x40` | READ | Read a byte from stdin, push to stack |
| `0x41` | WRITE | Pop a byte, write to stdout |
| `0xFE/0xFF` | HALT | Stop the VM |

### Password Extraction

The first 110 bytes of bytecode contain 11 identical character verification blocks. Each block follows the pattern:

```
40          ; READ -- read a character from stdin
01 XX       ; PUSH XX -- push XOR constant
12          ; XOR -- XOR(input, XX)
01 YY       ; PUSH YY -- push expected value
20          ; CMP_EQ -- compare result with expected
31 91 02    ; JZ 0x0291 -- if not equal, jump to HALT
```

The verification is: `(input_char XOR XX) == YY`, therefore `input_char = XX XOR YY`.

Extraction of the 11 characters:

| # | Offset | XOR val (XX) | Expected (YY) | Char = XX^YY | ASCII |
|---|--------|-------------|----------------|--------------|-------|
| 1 | 0x00 | 0xAA | 0x9A | 0x30 | `0` |
| 2 | 0x0A | 0xBB | 0xCB | 0x70 | `p` |
| 3 | 0x14 | 0xCC | 0xFF | 0x33 | `3` |
| 4 | 0x1E | 0xDD | 0xB3 | 0x6E | `n` |
| 5 | 0x28 | 0xEE | 0xB1 | 0x5F | `_` |
| 6 | 0x32 | 0x11 | 0x62 | 0x73 | `s` |
| 7 | 0x3C | 0x22 | 0x11 | 0x33 | `3` |
| 8 | 0x46 | 0x33 | 0x40 | 0x73 | `s` |
| 9 | 0x50 | 0x44 | 0x70 | 0x34 | `4` |
| 10 | 0x5A | 0x55 | 0x38 | 0x6D | `m` |
| 11 | 0x64 | 0x66 | 0x55 | 0x33 | `3` |

**Binary password: `0p3n_s3s4m3`**

### Success Message and 7z Password

After verification, the bytecode generates a message character by character using ADD pairs:

```
01 XX       ; PUSH a
01 YY       ; PUSH b
10          ; ADD -- push (a+b) & 0xFF
41          ; WRITE -- print the character
```

The decoded message contains the password for the 7z archive:

```
$ echo -n '0p3n_s3s4m3' | ./tomb_guardian
Kh3ops_Pyr4m1d ... the sacred chamber awaits ...
```

**7z password: `Kh3ops_Pyr4m1d`**

### Extraction

```bash
$ 7z x sacred_chamber.7z -pKh3ops_Pyr4m1d
-> challenge.hiero (2110 bytes)
-> hiero_vm (351456 bytes, Rust ELF)
```

---

## Stage 2: hiero_vm + challenge.hiero

### Reconnaissance

```
$ file hiero_vm
ELF 64-bit LSB pie executable, x86-64, stripped

$ file challenge.hiero
UTF-8 Unicode text
```

`hiero_vm` is a Rust-written interpreter that executes programs with hieroglyphic notation. The program `challenge.hiero` uses two Unicode writing systems:

- **Egyptian hieroglyphs** (U+13000-U+1342F): opcodes/instructions
- **Cuneiform** (U+12000-U+12FFF): numeric operands (value = codepoint - 0x12000)

### Hieroglyphic Program Analysis

The program `challenge.hiero` parses as a sequence of whitespace-separated tokens:

**Hieroglyphic Instruction Table:**

| Hieroglyph | Codepoint | Instruction | Description |
|------------|-----------|-------------|-------------|
| U+132F4 | U+132F4 | READ | Read a character from stdin |
| U+13079 | U+13079 | REF n | Reference to variable n |
| U+1340D | U+1340D | STORE | Store to variable |
| U+13440 | U+13440 | PUSH | Push variable to stack |
| U+130ED | U+130ED | OP | Arithmetic operation between TOS |
| U+13216 | U+13216 | CMP | Compare TOS with expected value |
| U+13250 | U+13250 | COND a b | Conditional jump |
| U+13333 | U+13333 | SUCCESS | Print success message |
| U+1336F | U+1336F | END | End of program |

Cuneiform operands encode numeric values:
- U+12000 -> value 0
- U+12001 -> value 1
- U+120D8 -> value 0xD8
- ...etc

### Program Structure

#### Part 1: Input Reading (27 characters)

```
READ
REF 0
STORE -> var[0] = input[0]

READ
REF 1
STORE -> var[1] = input[1]

... (repeated until var[26])
```

Reads 27 characters and stores them in variables `var[0]` through `var[26]`.

#### Part 2: Verification with Arithmetic Constraints

24 verification blocks, each with the pattern:

```
REF 6       -- reference var[a]
PUSH        -- push var[a] to stack
REF 7       -- reference var[b]
PUSH        -- push var[b] to stack
OP          -- arithmetic operation
REF 0xD8    -- expected result value
CMP         -- compare result with expected
COND        -- if fails, go to END
```

#### Part 3: Result

```
SUCCESS     -- if all comparisons pass
END
```

### Identifying the Operation

Initially it was assumed that the OP instruction was XOR (the most common operation in VM CTFs). However, **Z3 returned "no solution"** even without printable constraints. This rules out XOR.

Multiple operations were tested:

| Operation | Solution? |
|-----------|-----------|
| XOR | No |
| SUB (a-b) | No |
| SUB (b-a) | No |
| MUL | No |
| **ADD** | **Yes** |

The correct operation is **modular addition (ADD mod 256)**. The expected values (0x61-0xE4) are consistent with sums of printable ASCII characters.

### Constraint Extraction

**19 consecutive comparisons (chain):**

| var[a] | var[b] | Expected (a+b mod 256) |
|--------|--------|------------------------|
| 6 | 7 | 0xD8 |
| 7 | 8 | 0x9C |
| 8 | 9 | 0xA6 |
| 9 | 10 | 0xA6 |
| 10 | 11 | 0x64 |
| 11 | 12 | 0x98 |
| 12 | 13 | 0xC7 |
| 13 | 14 | 0xD5 |
| 14 | 15 | 0xE3 |
| 15 | 16 | 0xCC |
| 16 | 17 | 0x90 |
| 17 | 18 | 0x9F |
| 18 | 19 | 0xD1 |
| 19 | 20 | 0x96 |
| 20 | 21 | 0xA3 |
| 21 | 22 | 0xE4 |
| 22 | 23 | 0xA5 |
| 23 | 24 | 0x61 |
| 24 | 25 | 0x9E |

**5 cross comparisons (robustness):**

| var[a] | var[b] | Expected |
|--------|--------|----------|
| 6 | 10 | 0xA4 |
| 8 | 15 | 0xA1 |
| 12 | 20 | 0x9B |
| 15 | 23 | 0x9E |
| 7 | 18 | 0xD6 |

Total: **24 equations, 20 unknowns** (var[6]-var[25]), overdetermined system.

### Solving with Z3

The known flag format `0xfun{...}` is used to anchor 7 of the 27 variables:

```python
from z3 import *

comparisons = [
    (6, 7, 0xd8), (7, 8, 0x9c), (8, 9, 0xa6), (9, 10, 0xa6),
    (10, 11, 0x64), (11, 12, 0x98), (12, 13, 0xc7), (13, 14, 0xd5),
    (14, 15, 0xe3), (15, 16, 0xcc), (16, 17, 0x90), (17, 18, 0x9f),
    (18, 19, 0xd1), (19, 20, 0x96), (20, 21, 0xa3), (21, 22, 0xe4),
    (22, 23, 0xa5), (23, 24, 0x61), (24, 25, 0x9e),
    # Cross comparisons
    (6, 10, 0xa4), (8, 15, 0xa1), (12, 20, 0x9b),
    (15, 23, 0x9e), (7, 18, 0xd6),
]

known = {
    0: ord('0'), 1: ord('x'), 2: ord('f'),
    3: ord('u'), 4: ord('n'), 5: ord('{'),
    26: ord('}'),
}

solver = Solver()
v = [BitVec(f'v{i}', 8) for i in range(27)]

for idx, val in known.items():
    solver.add(v[idx] == val)

for i in range(6, 26):
    solver.add(v[i] >= 0x20, v[i] <= 0x7e)  # printable ASCII

for a, b, expected in comparisons:
    solver.add(v[a] + v[b] == expected)  # ADD mod 256

assert solver.check() == sat
model = solver.model()
flag = ''.join(chr(model[v[i]].as_long()) for i in range(27))
print(flag)  # 0xfun{ph4r40h_vm_1nc3pt10n}
```

### Verification

```bash
$ echo -n '0xfun{ph4r40h_vm_1nc3pt10n}' | ./hiero_vm challenge.hiero
The ancient seals accept your offering
```

---

## Flag

```
0xfun{ph4r40h_vm_1nc3pt10n}
```

---

## Challenge Diagram

```
+----------------------------------------------------+
|                  tomb_guardian                     |
|              (custom VM, C, stripped)              |
|                                                    |
|  Input: "0p3n_s3s4m3"                              |
|  Verification: char XOR const == expected          |
|  Output: "Kh3ops_Pyr4m1d"                          |
+---------------------+------------------------------+
                      |
                      v
+---------------------------------------------------+
|              sacred_chamber.7z                    |
|           Password: Kh3ops_Pyr4m1d                |
+---------------------+-----------------------------+
                      |
                      v
+-----------------------------------------------------+
|          hiero_vm + challenge.hiero                 |
|       (hieroglyphic VM, Rust + Unicode)             |
|                                                     |
|  Input: 27 flag chars                               |
|  Verification: var[a] + var[b] == expected (mod 256)|
|  24 equations -> Z3 solver                          |
|  Output: "The ancient seals accept your offering"   |
+-----------------------------------------------------+
```

---

## Tools Used

- **radare2**: static analysis of the tomb_guardian binary
- **Python 3**: VM emulator, hieroglyphic parser, solving scripts
- **Z3 (z3-solver)**: solving the modular equation system
- **7z**: extraction of password-protected archive

---

## Lessons Learned

1. **Nested VMs (inception)**: the challenge combines two completely different VMs -- one based on binary bytecodes and the other on Unicode characters.
2. **Don't assume the operation**: the hieroglyphic OP instruction looked like XOR (the most common in CTFs), but it was ADD. When Z3 says "no solution", try other operations.
3. **Unicode as programming language**: Egyptian hieroglyphs as opcodes and cuneiform as operands is a creative and elegant design.
4. **Flag format as anchor**: knowing `0xfun{...}` provides 7 fixed values that, combined with the 24 equations and printable constraints, determine a unique solution.
