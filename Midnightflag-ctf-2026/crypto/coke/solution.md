# Coke

**CTF:** Midnight Flag CTF 2026
**Category:** Crypto
**Author:** fun88337766
**Difficulty:** Hard

## TL;DR

Gabidulin code-based McEliece cryptosystem over GF(2^64) with distortion rank s=2. Frobenius kernel attack recovers the secret Gabidulin code, then Welch-Berlekamp decoding recovers the message.

## Description

The server outputs a single JSON blob containing:
- Public generator matrix `Gpub` (16×48 over GF(2^64))
- Encrypted flag (AES-GCM, key = SHA256(message))
- Ciphertext `y = msg * Gpub + e` where rank(e) = t = 8

Parameters: `q=2, m=64, n=32, k=16, lambda=16, s=2, t=8`.

Note from author: *"Classic Overbeck is bait. Distortion rank is low on purpose."*

## Analysis

### Cryptosystem structure

```
Gpub = [X | Gsec] * P
```

- `Gsec`: K×N_SECRET Moore matrix (Gabidulin code) with support g = (g_1,...,g_32)
  - Row i: `[g_1^{2^i}, ..., g_32^{2^i}]` for i=0..15
- `X = A*B`: K×LAMBDA distortion matrix with rank s=2
- `P`: N×N invertible binary column scrambler

### Vulnerability: Low distortion rank

**Key property of Moore matrices**: applying Frobenius (squaring all elements) to row i gives row i+1.

Define `D_l[i] = Frob^l(Gpub[i]) - Gpub[i+l]`. After undoing P:
```
D_l * P^{-1} = [Frob^l(X[i]) - X[i+l] | 0...0]
```

The right N_SECRET=32 columns are zero, and the left LAMBDA=16 columns have rank ≤ 2s per level. Stacking levels 1..7 reaches rank 16 = LAMBDA, giving a right kernel of dimension exactly 32 = N_SECRET.

Projecting Gpub through this kernel yields a pure Moore matrix — the secret Gabidulin code, stripped of distortion and scrambling.

### Welch-Berlekamp decoding

After projection: `yV = msg * GV + eV` where GV is a [32, 16] Gabidulin code and rank(eV) ≤ 8.

Find linearized polynomials E (q-degree t) and V (q-degree k+t-1) satisfying:
```
V(g_j) = E(r_j)  for all j
```

This is a 32×32 linear system (32 unknowns: 24 V-coefficients + 8 E-coefficients with e_t=1 normalization).

Then recover message via right skew division: `f = E^{-1} ∘ V`, which reduces to forward substitution:
```
m_s = (V_s ⊕ Σ_{l>0} E_l * m_{s-l}^{[l]}) / E_0
```

## Solution Steps

1. **Frobenius kernel attack**: Stack Frobenius difference matrices D_1..D_7 until rank = 16
2. **Right kernel**: 32-dimensional kernel projects out the distortion
3. **Verify Moore structure**: Frob(GV[i]) = GV[i+1] (rank 0 difference)
4. **Welch-Berlekamp**: Build and solve the 32×32 system for E and V coefficients
5. **Skew division**: Recover message polynomial coefficients
6. **Decrypt**: SHA256(msg) → AES-GCM key → flag

```python
# See solve2.py for full implementation
```

## Flag

```
MCTF{h4rdc0re_rank_metr1c_extens10n_overb4ck}
```

## Key Lessons

- Low distortion rank (s=2) makes the GPT/Loidreau cryptosystem trivially breakable via Frobenius kernel attack
- The Frobenius endomorphism is the fundamental tool for analyzing rank-metric codes
- Gabidulin decoding via Welch-Berlekamp is cleaner than syndrome-based approaches — no parity check matrix needed
- Right skew division of linearized polynomials reduces to forward substitution
- Challenge hint was accurate: "Classic Overbeck is bait" — the attack doesn't need Overbeck's specific technique

## References

- Gabidulin, E. M. (1985). "Theory of codes with maximum rank distance"
- Overbeck, R. (2008). "Structural attacks for public key cryptosystems based on Gabidulin codes"
- Coggia, D. & Couvreur, A. (2020). "On the security of a Loidreau rank metric code based encryption scheme"
- Wachter-Zeh, A. (2013). "Decoding of block and convolutional codes in rank metric"
