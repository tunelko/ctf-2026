# Liminal — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Reversing
**Points:** 500
**Difficulty:** Hard
**Author:** SwitchCaseAdvocate
**Flag:** `0xfun{0x4c8e40be1e97f544}`

> *"Some computations exist in the spaces between... This machine whispers its secrets through shadows left in silicon, performing operations that both happen and don't."*

---

## Summary

An x86-64 ELF binary implements an 8-round SPN (Substitution-Permutation Network) cipher using **speculative execution** (Spectre-like side-channel) to perform S-box substitutions. The challenge asks to find the input that produces `0x4C494D494E414C21` ("LIMINAL!" in ASCII). The solution requires extracting all cipher components from the binary and inverting the operation.

---

## Reconnaissance

```
$ file liminal
ELF 64-bit LSB executable, x86-64, stripped, dynamically linked, 191008 bytes

$ strings liminal | grep -i fail
FAILED
CONFIDENCE
```

The binary is **non-deterministic**: the same input produces different results between executions (confidence ~1/50). This is because it uses cache timing (Spectre) to extract bits, which is inherently noisy.

---

## SPN Cipher Analysis

### General Structure

```
For each round r (0..7):
  1. state ^= round_key[r]        # XOR with round key
  2. state = sbox_substitution()   # 8 independent S-boxes (one per byte)
  3. if r < 7: state = permute()   # Bit permutation (except last round)
```

### Extracted Components

#### Round Keys (8 x 64 bits)

Location: VA `0x42f2c0` -> file offset `0x2E2C0`

```
K0: 0xeff230922b8f2f34    K4: 0x8a818effc7402e80
K1: 0xb7acc594df2767b4    K5: 0x81997bb21d2231bb
K2: 0x15194c24bd0f9e09    K6: 0x1abd026bbf95ef64
K3: 0x2420afeac6c5e1ec    K7: 0xbfc90d85da8f9378
```

#### S-boxes (8 x 256 entries)

- 8 bijective S-boxes, one per byte position (0-7)
- Implemented via speculative execution: each bit is extracted with a function that uses `clflush`/`mfence`/cache timing
- 64 lookup tables (8 bytes x 8 bits) at file offset `0xE280`, separated by `0x800` bytes
- Each table maps 256 inputs to two cache offsets: lower value = bit 0, higher value = bit 1

#### Bit Permutation (64 entries)

Location: VA `0x42f280` -> file offset `0x2E280`

```
[19, 61, 28, 7, 45, 56, 51, 53, 35, 2, 5, 57, 14, 32, 21, 16,
 47, 4, 50, 10, 43, 60, 46, 23, 20, 44, 11, 26, 38, 48, 40, 24,
 22, 18, 17, 55, 62, 42, 0, 12, 52, 1, 30, 59, 58, 6, 36, 39,
 63, 3, 29, 54, 31, 9, 37, 13, 49, 34, 27, 25, 8, 33, 15, 41]
```

Semantics: `output_bit[i] = input_bit[perm[i]]`

---

## S-box Extraction Process

The speculative execution mechanism works as follows:

1. The `compute` function (VA `0x405b37`) calls 8 S-box wrapper functions
2. Each wrapper calls 8 bit-extraction functions (one per output byte bit)
3. Each bit-extraction function:
   - Loads a 256-entry table with `lea rcx, [rip+offset]`
   - Indexes with the input byte to get an offset
   - Uses `clflush` to evict cache lines
   - Speculatively accesses `probe[offset]`
   - Measures access timing for `probe[0]` vs `probe[0x240]`
   - The faster value indicates which bit was extracted

For static extraction, we simply read the lookup tables:
- Table value = `0x0` (low offset) -> bit = 0
- Table value = `0x240` (high offset) -> bit = 1

---

## Cipher Inversion

To decrypt, we apply the inverse operations in reverse order:

```python
def decrypt(ciphertext):
    state = ciphertext
    # Last round (no permutation): inv_sbox, XOR key
    state = apply_inv_sbox(state)
    state ^= round_keys[7]
    # Rounds 6 -> 0: inv_perm, inv_sbox, XOR key
    for r in range(6, -1, -1):
        state = apply_inv_perm(state)
        state = apply_inv_sbox(state)
        state ^= round_keys[r]
    return state
```

---

## Solution

```
Target:   0x4C494D494E414C21  ("LIMINAL!")
Input:    0x4C8E40BE1E97F544

Verification: encrypt(0x4C8E40BE1E97F544) = 0x4C494D494E414C21
```

---

## Notes on the Side-Channel

The author ("SwitchCaseAdvocate") references **liminal operations** -- computations that "happen and don't happen" simultaneously, like speculative execution: the CPU executes instructions that are later discarded, but leave observable traces in the cache. The binary exploits this to perform S-box substitutions non-deterministically (from the program's perspective), but the correct values are statically encoded in the lookup tables.

---

## Flag

```
0xfun{0x4c8e40be1e97f544}
```

---

## Tools Used

- **radare2**: Static analysis of the stripped ELF binary
- **Python 3**: Component extraction and cipher inversion
- **struct**: Binary data parsing (little-endian)
