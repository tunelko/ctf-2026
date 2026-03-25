# ghostcrypt — BSidesSF 2026 (Crypto, 993pts)

## TL;DR

Stranger Things-style alphabet wall with a 5x5 Polybius grid cipher. The "Summon Litany" endpoint returns encrypted flag letters. Decrypt via pattern analysis on the monoalphabetic substitution.

## Flag

```
CTF{murmursfromthebeyond}
```

## Description

Web challenge at `https://ghostcrypt-2c7aa570.challenges.bsidessf.net/`. The page shows a Stranger Things-style alphabet wall (25 letters, I/J merged) with a spooky interface. Two controls:
- **Invoke**: encrypts user-provided "incantation" with a given "arcana" (key)
- **Summon Litany**: returns the encrypted flag with hidden arcana ("?????????")

Button tooltip: `FLAG: 'CTF{<summon litany>}'. Interpret litany as all lowercase, no spaces.`

## Analysis

### Cipher structure

The encryption operates on a 5x5 Polybius grid:
```
A B C D E
F G H J K
L M N O P
Q R S T U
V W X Y Z
```

Each letter's grid position (row, col) is transformed by applying a row permutation and column permutation determined by the arcana keyword. For a given arcana, the cipher is a **monoalphabetic substitution**.

### Encryption oracle

The `/invoke` endpoint serves as an encryption oracle — encrypt any plaintext with any arcana. Testing with `arcana=ghost` and full alphabet confirmed the substitution nature.

### Ciphertext from summon-litany

```
Playback: H O N H O N L   R N K H   P Q D   C D Z K F E
Words:     HONHONL  RNKH  PQD  CDZKFE  (7-4-3-6)
```

### Pattern-based decryption

Without knowing the arcana, the monoalphabetic substitution can be cracked via word pattern analysis:

1. **HONHONL** has pattern ABCABCD — a 7-letter word where the first 3 letters repeat → **MURMURS** (M-U-R-M-U-R-S)
2. Given H→M, O→U, N→R, L→S:
   - **RNKH** = ?ROM → **FROM** (R→F, K→O)
   - **PQD** = **THE** (P→T, Q→H, D→E)
   - **CDZKFE** = B-E-?-O-?-? → **BEYOND** (C→B, Z→Y, F→N, E→D)

### Verification

All 13 cipher→plain mappings are bijective (no conflicts). The plaintext **"MURMURS FROM THE BEYOND"** perfectly fits the ghost/supernatural theme.

## Approaches Discarded

- Brute-forcing the 9-character arcana keyword (5^9 ≈ 2M effective keyspace due to column-only dependence — possible but unnecessary)
- Trying to reverse-engineer the exact cipher algebra (row/column permutation composition)

## Key Lessons

- Encryption oracles help characterize cipher structure, but sometimes classical cryptanalysis (pattern matching) is faster
- The ABCABCD word pattern is very distinctive — few English words match it (MURMURS is the obvious one in context)
- 993 points but solvable without finding the key — just crack the monoalphabetic substitution
