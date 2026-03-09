# Deoxyribonucleic acid — upCTF 2026

**Category:** MISC (Encoding)
**Points:** 100
**Flag:** `upCTF{DnA_IsCh3pear_Th3n_R4M}`

## TL;DR

DNA sequence of 175 bases encoded with the Goldman et al. (2013) scheme for data storage in DNA. Each base encodes a trit (0, 1, 2) relative to the previous base, avoiding homopolymers. 174 trits are decoded, grouped into blocks of 6, and converted to ASCII values (3⁶ = 729 > 256).

---

## Analysis

### Challenge Data

```
ACTCTACGAGTCTACAGAGTCGTCGTATCAGTCTCACGTGAGCGAGTATACAGTGTCGAGCGTG
CGACTCGCTACAGAGTCGCTGTAGCACGAGTCTAGTGTGTCGATCGAGTGTAGTCTGTCGTCG
TCGCTGTAGCACGAGTATAGTCTGTCGTAGTAGCAGTATGATAGAGCA
```

Along with the encoding table:

```
          | 0 | 1 | 2
 ---------|---|---|---
    A     | C | G | T
    C     | G | T | A
    G     | T | A | C
    T     | A | C | G
```

And the hint: **"Goldman et al. (2013)"** — a reference to the paper *"Towards practical, high-capacity, low-maintenance information storage in synthesized DNA"* published in Nature.

### Encoding Scheme

Goldman et al. designed a system where each nucleotide encodes a **trit** (base-3 digit) relative to the previous nucleotide:

| Previous base → | Trit 0 | Trit 1 | Trit 2 |
|-----------------|--------|--------|--------|
| **A** | C | G | T |
| **C** | G | T | A |
| **G** | T | A | C |
| **T** | A | C | G |

Key properties:
- **The same base is never repeated consecutively** (avoids homopolymers, which are problematic in real sequencing)
- The first base is a **prefix** that does not encode data — it only establishes the context for the next one
- Each subsequent base encodes exactly one trit

### Step-by-step Decoding

**1. DNA → Trits**

175 bases → 174 trits (first base = context)

```
DNA:   A  C  T  C  T  A  C  G  A  G  T  C  T  A  C  A  G  A  G  T  ...
Trit:     0  1  1  1  0  0  0  1  1  0  1  1  0  0  2  1  1  1  0  1  ...
```

Example: `A→C` = trit 0, `C→T` = trit 1, `T→C` = trit 1, etc.

**2. Trits → Bytes (6 trits per byte)**

6 trits are needed to represent one byte: 3⁶ = 729, which covers the range 0–255.

```
Trits:  0 1 1 1 0 0 | 0 1 1 0 1 1 | 0 0 2 1 1 1 | ...
Base3:    0·243 + 1·81 + 1·27 + 1·9 + 0·3 + 0·1 = 117
          0·243 + 1·81 + 1·27 + 0·9 + 1·3 + 1·1 = 112
          0·243 + 0·81 + 2·27 + 1·9 + 1·3 + 1·1 = 67
ASCII:    'u'         'p'         'C'
```

**3. Full Result**

174 trits / 6 = 29 bytes:

```
117 112  67  84  70 123  68 110  65  95  73 115  67 104  51 112
 u    p   C   T   F   {   D   n   A   _   I   s   C   h   3   p

101  97 114  95  84 104  51 110  95  82  52  77 125
 e   a   r   _   T   h   3   n   _   R   4   M   }
```

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
dna = "ACTCTACGAGTCTACAGAGTCGTCGTATCAGTCTCACGTGAGCGAGTATACAGTGTCGAGCGTGCGACTCGCTACAGAGTCGCTGTAGCACGAGTCTAGTGTGTCGATCGAGTGTAGTCTGTCGTCGTCGCTGTAGCACGAGTATAGTCTGTCGTAGTAGCAGTATGATAGAGCA"

# (prev_base, curr_base) → trit
decode = {}
for prev, row in [('A','CGT'), ('C','GTA'), ('G','TAC'), ('T','ACG')]:
    for trit, base in enumerate(row):
        decode[(prev, base)] = trit

# DNA → trits
trits = [decode[(dna[i-1], dna[i])] for i in range(1, len(dna))]

# 6 trits → 1 byte
flag = ''
for i in range(0, len(trits) - 5, 6):
    val = 0
    for j in range(6):
        val = val * 3 + trits[i + j]
    flag += chr(val)

print(flag)
```

```bash
python3 solve.py
# upCTF{DnA_IsCh3pear_Th3n_R4M}
```

---

## Key Lessons

1. **Goldman et al. (2013) is a real scheme**: published in Nature, it proposes data storage in synthetic DNA using base-3 encoding with rotational substitution
2. **The substitution table avoids homopolymers**: this is a real biological constraint — repeated sequences of the same base cause sequencing errors
3. **6 trits per byte**: ceil(8 / log2(3)) = ceil(5.047) = 6 trits needed to represent 256 values
4. **The first base is just context**: it does not encode information, it only provides the reference for decoding the second base

## References

- Goldman, N. et al. (2013). [Towards practical, high-capacity, low-maintenance information storage in synthesized DNA](https://doi.org/10.1038/nature11875). Nature, 494(7435), 77-80.
- [DNA digital data storage — Wikipedia](https://en.wikipedia.org/wiki/DNA_digital_data_storage)
