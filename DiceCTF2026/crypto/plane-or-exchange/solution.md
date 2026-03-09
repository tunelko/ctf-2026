# plane-or-exchange

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | diceCTF 2026                   |
| Category    | crypto                         |
| Difficulty  | Medium/Hard                    |

## Description
> Alice and Bob had a brief exchange, and now they know something which I do not. Would you please help me to drop some Eves?

## TL;DR
Diffie-Hellman key exchange over knot invariants (Alexander polynomial). The Alexander polynomial is **multiplicative** under connected sum, so the shared secret can be computed from public keys alone: `shared = normalize(Alex(alice_pub) * Alex(bob_pub) / Alex(public_info))`.

## Initial Analysis

### Source code review

`protocol.py` implements a DH-like key exchange:

- **Private keys**: knot diagrams (pairs of permutations `(x, o)`)
- **Public generator**: `public_info` — a knot diagram known to both parties
- **Public keys**: `alice_pub = scramble(connect(public_info, alice_priv), 1000)`
- **Shared secret**: `sha256(normalize(calculate(connect(my_priv, their_pub))))`
- **Encryption**: XOR with SHA256-extended key stream

Key functions:
- `connect(g1, g2)` — connected sum (#) of two knot diagrams
- `calculate(point)` — computes the **Alexander polynomial** via Seifert matrix determinant
- `scramble(data, iter)` — applies 1000 random Reidemeister-like moves (`slide1`, `slide2`, `shuffle`)
- `normalize(poly)` — shifts Laurent polynomial to min exponent 0, positive constant term

### The invariant

The `calculate` function builds a Seifert-like matrix from the knot diagram (`mine` → `sweep`) and computes:

```python
det(M(t)) * (1-t)^(1-n)
```

where M is the matrix with entries `t^(-a_ij)`. This is (a variant of) the **Alexander polynomial** of the knot.

## Identified Vulnerability

The Alexander polynomial is a **knot invariant** that is **multiplicative under connected sum**:

```
Alex(K1 # K2) = Alex(K1) * Alex(K2)
```

The `scramble` operations (slide1, slide2, shuffle) are Reidemeister-like moves that **preserve the invariant**. So:

```
Alex(alice_pub) = Alex(connect(public_info, alice_priv))
               = Alex(public_info) * Alex(alice_priv)
```

The shared secret is:
```
shared = normalize(Alex(alice_priv) * Alex(bob_pub))
       = normalize(Alex(alice_pub) * Alex(bob_pub) / Alex(public_info))
```

All three public values are known — no private keys needed.

### Vulnerability Type
The knot-based DH is insecure because the Alexander polynomial is efficiently computable and multiplicative, allowing passive eavesdroppers to recover the shared secret.

## Solution Process

### Step 1: Efficient polynomial evaluation via integer determinants

Computing the symbolic determinant of 27x27 and 30x30 polynomial matrices is prohibitively slow with sympy. Instead, we evaluate the Alexander polynomial at integer points `u = 2, 3, ..., 231` using:

1. Substitute `u = 1/t` so matrix entries become `u^(a_ij)` (non-negative after row shift)
2. For each integer `u`, compute the exact integer determinant using **Bareiss algorithm** (fraction-free Gaussian elimination)
3. Multiply by `u^(shift + n - 1)` and divide by `(u-1)^(n-1)` (exact division, Alexander polynomial property)

This takes ~1 second for all 230 points across all three polynomials.

### Step 2: Compute shared values pointwise

At each evaluation point:
```
shared(u_i) = Alex(alice_pub, u_i) * Alex(bob_pub, u_i) / Alex(public_info, u_i)
```

All divisions are exact (multiplicative property).

### Step 3: Recover polynomial via Newton interpolation

Use Newton's divided differences on the 230 exact integer values. The divided differences become zero at level 70, revealing a degree-69 polynomial in `u`.

### Step 4: Convert and normalize

Convert `u → 1/t`, apply `normalize()` to get the canonical form. The result is a palindromic degree-22 polynomial (characteristic of a knot invariant):

```
2*t^22 - 31*t^21 + 234*t^20 - ... - 31*t + 2
```

### Step 5: Decrypt

```python
shared_secret = sha256(str(norm_poly)).hexdigest()
# XOR decrypt with SHA256-extended key
```

## Execution

```bash
python3 solve.py
```

```
[*] Evaluating shared polynomial at 230 integer points...
[*] Interpolating polynomial via Newton divided differences...
    Polynomial degree: 69
[*] Normalized polynomial: 2*t**22 - 31*t**21 + 234*t**20 - ...

[+] Flag: dice{plane_or_planar_my_w0rds_4r3_411_knotted_up}
```

## Flag
```
dice{plane_or_planar_my_w0rds_4r3_411_knotted_up}
```

## Key Lessons
- The Alexander polynomial is multiplicative under connected sum — this breaks any DH scheme built on it
- For knot-based crypto to be secure, the invariant must be hard to compute from the scrambled diagram (not the case here)
- Integer-point evaluation + Newton interpolation is a powerful technique for recovering exact polynomials when symbolic computation is too slow
- Bareiss algorithm gives exact integer determinants without floating-point errors — critical for correctness
- The palindromic structure of the Alexander polynomial (degree 22, symmetric coefficients) confirms the result is a valid knot invariant
