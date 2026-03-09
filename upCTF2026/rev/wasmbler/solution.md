# Wasmbler — upCTF 2026

**Category:** REV (WebAssembly VM)
**Flag:** `upCTF{n3rd_squ4d_4ss3mbl3_c0de_7f2b1d}`

## TL;DR

Client-side flag checker compiled to WebAssembly with Emscripten. The binary implements a custom stack-based VM with 13 operations. The dispatch table is shuffled (Fisher-Yates + LCG with seed `0x1337beef`) after each instruction, meaning the same opcode byte maps to different operations at each step. The 388-byte bytecode encodes 31 constraints over the 38 flag characters. It is solved by decoding the operation sequence (emulating the shuffle), extracting the constraints, and solving them with Z3.

---

## Analysis

### Infrastructure

```
Static web page with input + "Check" button
challenge.js (Emscripten runtime) + challenge.wasm (3584 bytes)
100% client-side validation: Module.ccall('check_flag', ...)
```

### Function `check_flag` (func 17)

```c
int check_flag(char *input) {
    if (strlen(input) != 38) return 0;

    // Reset VM state
    memcpy(dispatch_table, initial_table, 68);  // 66000 ← 65924
    input_ptr = input;                           // 66064

    // Execute bytecode
    while (pc < 387) {
        uint8_t raw = bytecode[pc++];
        int opcode_idx = raw % 13;
        call_indirect(dispatch_table[opcode_idx]);  // execute operation
        shuffle();                                    // Fisher-Yates shuffle
    }

    return pop();  // 1 = correct, 0 = wrong
}
```

### Memory Layout (WASM linear memory)

| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 65536 | 388 | `bytecode` | VM ROM program |
| 65924 | 52 | `init_table` | Initial dispatch table `[1,2,...,13]` |
| 66000 | 52 | `dispatch` | Active dispatch table (shuffled) |
| 66052 | 4 | `g_seed` | LCG state (init: `0x1337beef`) |
| 66056 | 4 | `stack_count` | Stack size |
| 66060 | 4 | `g_pc` | Program counter |
| 66064 | 4 | `input_ptr` | Pointer to input string |
| 66080 | 256 | `stack` | VM stack (bytes) |

### Instruction Set (13 operations)

| Table Index | Name | Operation |
|-------------|------|-----------|
| 1 | LOAD_NEXT | `push(bytecode[pc++])` — immediate operand |
| 2 | LOAD_INPUT | `push(input[pop()])` — index into input |
| 3 | ADD | `a=pop(); b=pop(); push((b+a) & 0xff)` |
| 4 | SUB | `a=pop(); b=pop(); push((b-a) & 0xff)` |
| 5 | XOR | `a=pop(); b=pop(); push(b ^ a)` |
| 6 | OR | `a=pop(); b=pop(); push(b \| a)` |
| 7 | AND | `a=pop(); b=pop(); push(b & a)` |
| 8 | SHL | `a=pop()&7; b=pop(); push((b << a) & 0xff)` |
| 9 | SHR | `a=pop()&7; b=pop(); push(b >> a)` |
| 10 | ROL | Rotate left 8-bit |
| 11 | ROR | Rotate right 8-bit |
| 12 | MOD | `a=pop(); b=pop(); push(b % (a\|1))` |
| 13 | CMP_EQ | `a=pop(); b=pop(); push(b == a ? 1 : 0)` |

### Anti-Analysis Mechanism: Dispatch Table Shuffle

After each instruction, the dispatch table is shuffled with Fisher-Yates using an LCG:

```c
void shuffle() {
    for (int i = 12; i > 0; i--) {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;  // LCG
        int j = seed % (i + 1);
        swap(dispatch[i], dispatch[j]);
    }
}
```

This means byte `0x04` could be `SUB` at step 0, but `LOAD_NEXT` at step 3, etc. However, the seed is deterministic (`0x1337beef`), so it can be emulated offline.

### Bytecode Structure

The bytecode follows a repetitive pattern of 31 verification blocks:

```
[LOAD_NEXT 1]              ← initial accumulator = 1

Block type 1 (single byte check):
  LOAD_NEXT idx             ← input index
  LOAD_INPUT                ← push input[idx]
  LOAD_NEXT const           ← operation constant
  <OP>                      ← ROL/ROR/SHL/SHR
  LOAD_NEXT expected        ← expected value
  CMP_EQ                    ← result == expected?
  AND                       ← accumulate with previous result

Block type 2 (two byte relation):
  LOAD_NEXT idx1
  LOAD_INPUT                ← push input[idx1]
  LOAD_NEXT idx2
  LOAD_INPUT                ← push input[idx2]
  <OP>                      ← XOR/SUB/ADD/AND/OR
  LOAD_NEXT idx3            ← (optional third input)
  ...
  LOAD_NEXT expected
  CMP_EQ
  AND
```

---

## Extracted Constraints

Decoding the 387 bytes of bytecode with the emulated shuffle:

| # | Constraint | Type |
|---|-----------|------|
| 0 | `ROL(f[13], 5) == 174` | single |
| 1 | `ROR(f[35], 6) == 196` | single |
| 2 | `(f[14] - f[28]) == (f[37] + 83)` | triple |
| 3 | `ROR(f[27], 2) == 12` | single |
| 4 | `ROL(f[21], 4) == 214` | single |
| 5 | `(f[36] + f[12]) == (f[4] + 143)` | triple |
| 6 | `f[10] ^ f[23] == 51` | pair |
| 7 | `f[10] << 2 == 124` | single |
| 8 | `f[25] ^ f[17] == 107` | pair |
| 9 | `ROR(f[31], 6) == 220` | single |
| 10 | `f[9] ^ f[16] == 59` | pair |
| 11 | `(f[37] ^ f[25]) == (f[23] + 182)` | triple |
| 12 | `(f[5] - f[3]) == (f[7] + 244)` | triple |
| 13 | `(f[4] & f[24]) == (f[29] + 157)` | triple |
| 14 | `(f[7] - f[18]) == (f[27] + 144)` | triple |
| 15 | `f[32] % (f[11] \| 1) == 102` | pair/mod |
| 16 | `ROR(f[9], 2) == 25` | single |
| 17 | `f[20] << 1 == 102` | single |
| 18 | `(f[19] ^ f[15]) == (f[3] + 195)` | triple |
| 19 | `(f[28] ^ f[33]) == (f[7] + 35)` | triple |
| 20 | `ROL(f[34], 5) == 76` | single |
| 21 | `(f[15] - f[30]) == (f[26] + 162)` | triple |
| 22 | `(f[22] \| f[27]) == (f[26] + 15)` | triple |
| 23 | `ROL(f[15], 5) == 140` | single |
| 24 | `(f[8] ^ f[27]) == (f[11] + 207)` | triple |
| 25 | `(f[32] + f[33]) == (f[10] + 57)` | triple |
| 26 | `(f[6] + f[8]) == (f[16] + 129)` | triple |
| 27 | `ROR(f[12], 4) == 23` | single |
| 28 | `f[24] << 2 == 204` | single |
| 29 | `(f[22] - f[23]) == 246` | pair |
| 30 | `(f[26] + f[7]) == (f[8] + 36)` | triple |

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
from z3 import *

flag = [BitVec(f'f{i}', 8) for i in range(38)]
solver = Solver()

# Known prefix/suffix
for i, c in enumerate(b'upCTF{'):
    solver.add(flag[i] == c)
solver.add(flag[37] == ord('}'))

# Printable ASCII
for i in range(6, 37):
    solver.add(flag[i] >= 0x20, flag[i] <= 0x7e)

def rol8(x, n):
    n = n & 7
    return (x << n) | (LShR(x, 8 - n)) if n else x

def ror8(x, n):
    n = n & 7
    return (LShR(x, n)) | (x << (8 - n)) if n else x

# 31 constraints from bytecode
solver.add(rol8(flag[13], 5) == 174)
solver.add(ror8(flag[35], 6) == 196)
solver.add((flag[14] - flag[28]) == (flag[37] + 83))
solver.add(ror8(flag[27], 2) == 12)
solver.add(rol8(flag[21], 4) == 214)
solver.add((flag[36] + flag[12]) == (flag[4] + 143))
solver.add(flag[10] ^ flag[23] == 51)
solver.add((flag[10] << 2) == 124)
solver.add(flag[25] ^ flag[17] == 107)
solver.add(ror8(flag[31], 6) == 220)
solver.add(flag[9] ^ flag[16] == 59)
solver.add((flag[37] ^ flag[25]) == (flag[23] + 182))
solver.add((flag[5] - flag[3]) == (flag[7] + 244))
solver.add((flag[4] & flag[24]) == (flag[29] + 157))
solver.add((flag[7] - flag[18]) == (flag[27] + 144))
solver.add(URem(flag[32], (flag[11] | 1)) == 102)
solver.add(ror8(flag[9], 2) == 25)
solver.add((flag[20] << 1) == 102)
solver.add((flag[19] ^ flag[15]) == (flag[3] + 195))
solver.add((flag[28] ^ flag[33]) == (flag[7] + 35))
solver.add(rol8(flag[34], 5) == 76)
solver.add((flag[15] - flag[30]) == (flag[26] + 162))
solver.add((flag[22] | flag[27]) == (flag[26] + 15))
solver.add(rol8(flag[15], 5) == 140)
solver.add((flag[8] ^ flag[27]) == (flag[11] + 207))
solver.add((flag[32] + flag[33]) == (flag[10] + 57))
solver.add((flag[6] + flag[8]) == (flag[16] + 129))
solver.add(ror8(flag[12], 4) == 23)
solver.add((flag[24] << 2) == 204)
solver.add((flag[22] - flag[23]) == 246)
solver.add((flag[26] + flag[7]) == (flag[8] + 36))

if solver.check() == sat:
    model = solver.model()
    result = bytes([model.eval(flag[i]).as_long() for i in range(38)])
    print(f"FLAG: {result.decode()}")
```

```bash
python3 solve.py
# FLAG: upCTF{n3rd_squ4d_4ss3mbl3_c0de_7f2b1d}
```

### Verification with emulator

A full Python emulator of the VM was written, replicating the exact WASM behavior (stack, dispatch table shuffle, LCG, all operations). The flag `upCTF{n3rd_squ4d_4ss3mbl3_c0de_7f2b1d}` produces result `1` (CORRECT).

---

## Discarded Approaches

| # | Approach | Why it was not needed |
|---|----------|----------------------|
| 1 | Per-character brute force | Possible but inefficient; many constraints involve 2-3 bytes simultaneously |
| 2 | Static WASM analysis without emulating the shuffle | The shuffle changes the opcode-to-operation mapping at each step; without emulating it the constraints are incorrect |
| 3 | In-browser WASM instrumentation | Viable but slower than extracting constraints offline |

---

## Key Lessons

1. **Dispatch table shuffle as obfuscation**: A deterministic LCG + Fisher-Yates causes the same byte to map to different operations at each step. It is effective against static analysis but trivial to emulate with the known seed
2. **wasm2wat is sufficient**: No advanced WASM decompilation tools were needed; the WAT format is readable and the functions are short
3. **Z3 solves mixed constraints easily**: Rotations, shifts, XOR, modular arithmetic, and multi-byte relations — all in a single solver call
4. **Client-side validation = game over**: All the state needed to solve is in the downloadable WASM binary

## References

- [WebAssembly Text Format (WAT)](https://webassembly.github.io/spec/core/text/index.html)
- [wabt: The WebAssembly Binary Toolkit](https://github.com/WebAssembly/wabt)
- [Z3 Python API](https://z3prover.github.io/api/html/namespacez3py.html)
- [Fisher-Yates shuffle](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle)
- [LCG (glibc parameters)](https://en.wikipedia.org/wiki/Linear_congruential_generator)
