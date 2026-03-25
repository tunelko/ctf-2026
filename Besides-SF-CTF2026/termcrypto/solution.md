# TokenCrypt — BSidesSF 2026

**Category:** Crypto
**Author:** symmetric
**Flag:** `CTF{chatgpt_slid_into_my_dms}`

---

## TL;DR

TokenCrypt is a custom 24-bit Feistel cipher with a 96-bit key split as `s(16) | seed56(56) | b24(24)`. The 16-bit Feistel key `s` can be brute-forced (65536 candidates) by exploiting the linear affine layer over GF(2). With known plaintexts at 16 rounds (one chunk), each candidate `s` yields a linear system that either fits all pairs (correct key) or doesn't. After recovering `s`, `M`, and `b`, the 1024-round flag is decrypted chunk-by-chunk. The plaintext consists of GPT-4o (`o200k_base`) token IDs.

---

## Cipher Analysis

### Key layout (96 bits)
```
s(16) || seed56(56) || b24(24)
```

### Encryption (N rounds = K chunks of 16)
```python
for c in range(K):           # c = 0, 1, ..., K-1
    x = A(C_s(x ^ c))       # chunk_encrypt
```
Where:
- `C_s` = 16-round balanced Feistel, keyed by 16-bit `s`
- `A(z) = M*z XOR b` = affine layer over GF(2), `M` is a 24×24 invertible binary matrix

### At 16 rounds (K=1, c=0)
```
ct = A(C_s(pt)) = M * C_s(pt) XOR b
```
This is a **known-plaintext-friendly structure**: XOR two ciphertexts eliminates `b`:
```
ct_i XOR ct_j = M * (C_s(pt_i) XOR C_s(pt_j))
```

---

## Attack

### Step 1 — Capture known plaintext pairs

Connect to server, set security to **Fastest** (16 rounds), encrypt 30 tokens with step=547 (ensures the Feistel outputs span a full-rank 24-dimensional GF(2) space):

```python
tokens = [100000 + i * 547 for i in range(30)]
```

Also capture the flag ciphertext (`getflag` → 1024 rounds).

### Step 2 — Brute-force s ∈ [0, 65535]

For each candidate `s`:

1. Compute `d_i = C_s(pt_i) XOR C_s(pt_0)` (Feistel difference)
2. Compute `e_i = ct_i XOR ct_0` (CT difference, eliminates `b`)
3. Solve the GF(2) linear system `e_i = M * d_i` for the 24×24 matrix `M`
4. Recover `b = ct_0 XOR M * C_s(pt_0)`
5. Verify on all 30 pairs — correct `s` passes all checks

With rank-24 input differences and 30 pairs, M is uniquely determined. Only the correct `s` satisfies all 30 constraints (false positive probability ≈ 2⁻²⁴).

**Runtime:** ~60 seconds in Python (≈450 candidates/sec).

### Step 3 — Decrypt the flag

With recovered `(s, M, b)`:

```python
# Inverse affine: A^-1(y) = M^-1 * (y XOR b)
# Inverse chunk: chunk_decrypt(y) = C_s^-1(A^-1(y))

for c in reversed(range(64)):   # 1024/16 = 64 chunks
    y = chunk_decrypt(y) ^ c
```

### Step 4 — Decode token IDs

The decrypted 24-bit values are **GPT-4o token IDs** (`o200k_base`, vocab size 200,019):

```python
import tiktoken
enc = tiktoken.get_encoding('o200k_base')
enc.decode([1895, 37, 90, 13503, 70, 555, 26945, 315, 109569, 74208, 1565, 1782, 92])
# → 'CTF{chatgpt_slid_into_my_dms}'
```

Token 109569 exceeds the GPT-4 (`cl100k_base`) vocab limit of 100,277 — the key hint that GPT-4o's larger vocabulary is required.

---

## Vulnerability

**CWE-327 — Use of a Broken or Risky Cryptographic Algorithm**

The 16-bit Feistel key `s` is independently brute-forceable (2¹⁶ = 65,536 candidates) because the affine layer `M` is determined purely from known plaintexts via GF(2) linear algebra once `s` is fixed. The 56-bit matrix seed and 24-bit offset never need to be recovered directly.

---

## Approaches Discarded

| Approach | Why discarded |
|---|---|
| Brute-force full 96-bit key | 2⁹⁶ — infeasible |
| Recover seed56 from M | Not needed: M is solved directly from KPs |
| Consecutive token inputs (100000-100024) | Rank only 21/24 for Feistel outputs — not enough for unique solution |
| cl100k_base / gpt2 tokenizer | Token 109569 out of vocab range |

---

## Key Lessons

1. **Split-key designs multiply attacks**: independently attacking each key component (s alone, then M+b via linear algebra) is far cheaper than attacking the full key.
2. **Affine layers over GF(2) are transparent under known-plaintext**: XOR differences between KPs eliminate the constant `b` and expose `M` as a linear system.
3. **Input diversity matters**: consecutive inputs produced degenerate Feistel outputs (rank 21/24). Spread-out inputs (step=547) achieved full rank.
4. **Check the tokenizer version**: GPT-4o's o200k_base has 2× the vocabulary of cl100k_base — large token IDs are the distinguishing hint.

---

## Exploit

```
capture.py   — connect to server, capture 30 KP pairs + flag CT → fresh.json
crack3.py    — offline brute-force s, solve M/b via GF(2) GE, decrypt flag tokens
```

Final decoding:
```python
import tiktoken
tiktoken.get_encoding('o200k_base').decode(
    [1895, 37, 90, 13503, 70, 555, 26945, 315, 109569, 74208, 1565, 1782, 92]
)
```

---

## Flag

```
CTF{chatgpt_slid_into_my_dms}
```
