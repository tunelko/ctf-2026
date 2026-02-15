# Fortune Teller Revenge — Writeup (crypto)

**CTF:** 0xfun / Pragyan CTF 2026
**Category:** Crypto
**Flag:** `0xfun{r3v3ng3_0f_th3_f0rtun3_t3ll3r}`

---

## Description

> How dare you break the Fortune Teller's heart? After you exploited her trust,
> the Fortune Teller has grown... distant. Her visions still come in 64-bit
> truths with 32-bit glimpses, but now they arrive from far across time itself.
> The constants remain known. The pattern has changed. Can you still predict her
> future?

Service: `nc chall.0xfun.org 50943`
File: `fortune_revenge.py`

---

## Analysis

The challenge implements a **64-bit truncated LCG** with a `jump()` function that advances 100,000 steps at once:

```python
class FortuneTellerRevenge:
    M = 2**64
    A = 2862933555777941757
    C = 3037000493
    JUMP = 100000
    A_JUMP = pow(A, JUMP, M)  # = 3297373631046652033
    C_JUMP = 8391006422427229792
```

The server executes:
1. `g1 = glimpse()` -> `next()` and returns the upper 32 bits
2. `jump()` -> advances 100,000 states
3. `g2 = glimpse()` -> `next()` and returns the upper 32 bits
4. `jump()` -> advances 100,000 states
5. `g3 = glimpse()` -> `next()` and returns the upper 32 bits
6. Asks to predict the next 5 values

### Difference from the original Fortune Teller

In the original challenge, the 3 glimpses were consecutive (`next()` without `jump()`), which allowed solving with LLL lattice reduction. Here, the `jump()` of 100,000 steps between each glimpse complicates the lattice approach, but opens a brute-force path.

---

## Solution

### Step 1: Combine jump() + next() into a single LCG

The composition of two LCGs is another LCG. If:
- `next()`: `s' = A*s + C mod M`
- `jump()`: `s' = A_JUMP*s + C_JUMP mod M`

Then `jump()` followed by `next()` is equivalent to:

```
state3 = A * (A_JUMP * state1 + C_JUMP) + C
       = (A * A_JUMP) * state1 + (A * C_JUMP + C)
```

That is, an LCG with:
- `A_TOTAL = A * A_JUMP mod 2^64 = 8810128861561192317`
- `C_TOTAL = A * C_JUMP + C mod 2^64 = 1496106642115246093`

This effective LCG maps `state1 -> state3 -> state5` (the states after each `next()` that produces g1, g2, g3).

### Step 2: Brute-force of 2^32

We know the upper 32 bits of `state1` (= `g1`). We only need to try the 2^32 possible values for the lower 32 bits:

```
state1 = (g1 << 32) | low   for low in [0, 2^32)
state3 = A_TOTAL * state1 + C_TOTAL
```

If `state3 >> 32 == g2`, we verify:

```
state5 = A_TOTAL * state3 + C_TOTAL
```

If `state5 >> 32 == g3`, we found the state. With 2 independent 32-bit verifications, the probability of a false positive is ~2^-32, so we obtain a unique solution.

### Step 3: Predict the next 5

Once `state5` is known, we apply `next()` 5 times:

```
s = state5
for i in range(5):
    s = A * s + C mod 2^64
    print(s)
```

### Implementation

A C program (`fortune_revenge_bf.c`) was used for the brute-force, which takes ~3 seconds to traverse all 2^32 values:

```c
uint64_t A_TOTAL = A * A_JUMP;
uint64_t C_TOTAL = A * C_JUMP + C;

for (uint64_t low1 = 0; low1 < 0x100000000ULL; low1++) {
    uint64_t state1 = (g1 << 32) | low1;
    uint64_t state3 = A_TOTAL * state1 + C_TOTAL;
    if ((state3 >> 32) == g2) {
        uint64_t state5 = A_TOTAL * state3 + C_TOTAL;
        if ((state5 >> 32) == g3) {
            // Generate the next 5 with regular next()
        }
    }
}
```

---

## Files

| File | Description |
|------|-------------|
| `fortune_revenge.py` | Challenge source code (provided) |
| `fortune_revenge_bf.c` | Brute-force solver in C |
| `fortune_revenge_bf` | Compiled solver binary |

## Execution

```bash
# Compile
gcc -O2 -o fortune_revenge_bf fortune_revenge_bf.c

# Connect to the server, obtain g1 g2 g3, then:
./fortune_revenge_bf <g1> <g2> <g3>
# Prints the 5 full 64-bit states to send to the server
```

---

## Key Concepts

- **LCG composition**: Two affine transformations mod 2^n compose into another affine transformation
- **Truncated LCG brute-force**: With 32 known bits from a 64-bit state, 2^32 candidates are tested in ~3s in C
- **Cross-verification**: Two independent truncated outputs provide certainty of a unique solution (2^-32 collision probability)
