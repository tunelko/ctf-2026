# BitStorm — Crypto (50pts, Beginner)

> "We built a custom pseudo-random number generator. but it's big and messy. Can you reverse the entropy storm and recover the initial state (the flag)?"

## Summary

Custom PRNG (`GiantLinearRNG`) with a state of 32 words of 64 bits (2048 bits total). All operations are linear over GF(2) (XOR, shifts, rotations), which allows recovering the initial state by solving a system of linear equations over GF(2) with Gaussian elimination.

**Flag:** `0xfun{L1n34r_4lg3br4_W1th_Z3_1s_Aw3s0m3}`

## PRNG Analysis

### Structure

```
State:  32 words x 64 bits = 2048 bits
Seed:   flag contents (up to 256 bytes), padded with \x00
Output: 60 values of 64 bits
```

### Initialization

The flag (without the `0xfun{...}` wrapper) is converted to a big-endian integer of 256 bytes. This integer is split into 32 words of 64 bits:

```python
state[i] = (seed_int >> 64*(31-i)) & 0xFFFFFFFFFFFFFFFF
```

### `next()` function

Each step has three phases:

**1. Computing `new_val`** (new state element):

```python
taps = [0, 1, 3, 7, 13, 22, 28, 31]
new_val = 0
for i in taps:
    val = state[i]
    mixed = val ^ (val << 11) ^ (val >> 7)     # linear mixing
    mixed = rotl(mixed, (i*3) % 64)             # tap-dependent rotation
    new_val ^= mixed
new_val ^= (state[31] >> 13) ^ (state[31] << 5)  # extra contribution
```

**2. State update** (shift register):

```python
state = state[1:] + [new_val]  # discard state[0], append new_val at the end
```

**3. Output computation:**

```python
out = 0
for i in range(32):
    if i % 2 == 0:
        out ^= state[i]           # even words: directly
    else:
        out ^= rotr(state[i], 2)  # odd words: rotated 2 bits
```

### Key observation: full linearity over GF(2)

**All** PRNG operations are linear over GF(2):

| Operation | Linear over GF(2)? |
|-----------|---------------------|
| XOR | Yes (addition in GF(2)) |
| Logical shift (<<, >>) | Yes (bit permutation + zeros) |
| Rotation | Yes (bit permutation) |

There are no multiplications, ANDs, ORs, or nonlinear operations. This means every bit of every output is a linear combination (XOR) of the initial state bits.

## Exploitation Strategy

### Symbolic modeling

We represent each state bit as a 2048-bit dependency vector. If bit `j` of the state depends on original bits `{a, b, c}`, its vector is `1<<a | 1<<b | 1<<c`.

Symbolic operations work on these vectors:
- `sym_xor(a, b)` -> XOR of dependency vectors
- `sym_lshift(a, k)` -> reorder bit positions
- `sym_rotl(a, k)` -> circular permutation of positions

### System of equations

After 60 symbolic steps, each output bit generates an equation:

```
dep_vector . seed_bits = output_bit    (over GF(2))
```

With 60 outputs x 64 bits = **3840 equations** for **2048 unknowns**, the system is overdetermined and has a unique solution.

### Solving

Gaussian elimination over GF(2) using Python integers as bit vectors. The elimination finds all 2048 pivots in ~1.5 seconds, recovering the complete initial state.

### Flag reconstruction

```python
seed_bytes = solution.to_bytes(256, 'big')
content = seed_bytes.rstrip(b'\0').decode('ascii')
flag = f"0xfun{{{content}}}"
```

## Exploit

See `solve.py` — the solver includes:
1. **Test phase**: generates outputs with a known flag, solves, and verifies that the flag is recovered correctly.
2. **Real phase**: applies the same solver to the challenge outputs.

### Execution

```
$ python3 solve.py
============================================================
PHASE 1: Testing with known flag
============================================================
[...] TEST PASSED! Solver is correct.
Recovered text: test_flag_XYZ_1234567890_ABCDEF

============================================================
PHASE 2: Solving real challenge
============================================================
[...] Gauss done: 2048 pivots found in 1.5s

Verifying real solution...
VERIFICATION PASSED!

FLAG: 0xfun{L1n34r_4lg3br4_W1th_Z3_1s_Aw3s0m3}
```

## Complexity

| Phase | Time |
|-------|------|
| Symbolic simulation (60 steps) | < 0.1s |
| Gaussian elimination (2048x3840) | ~1.5s |
| **Total** | **~1.6s** |

## Lessons Learned

1. **Recognizing linearity over GF(2)**: when a PRNG only uses XOR, shifts, and rotations, everything can be modeled as linear algebra over GF(2). It doesn't matter how "big and messy" it looks.
2. **Test-first in cryptographic solvers**: always verify with a known case before applying to the real challenge. This catches modeling bugs before wasting time debugging.
3. **Python big integers as bit vectors**: representing GF(2) vectors as Python integers is efficient and elegant. XOR is native and Gaussian elimination runs fast even for 2048 dimensions.
