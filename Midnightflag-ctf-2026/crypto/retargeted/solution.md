# Retargeted Jets

**CTF:** Midnight Flag CTF 2026
**Category:** Crypto
**Author:** fun88337766
**Difficulty:** Hard

## TL;DR

A Schnorr-like zero-knowledge proof system for polynomial evaluations uses a "ratchet" to derive the 4th query's mask from the previous 3. Since Taylor shift is linear and `shift(taylor(f, xi), xj-xi) = taylor(f, xj)`, the ratchet relation collapses all unknown polynomial terms into a single scalar multiple, recovering the full polynomial from 4 queries despite it having degree 31.

## Description

The server holds a secret polynomial `f` of degree 31 over `Z_Q` (Q is a 255-bit prime, P = 2Q+1). The menu offers:

1. **Audited opening** (up to 4 times): given a point `x ≠ admin_x`, returns a zero-knowledge proof that `Y` commits to `f(x)`. The proof includes a vector `w` (32 elements), scalars `s, t`, and commitments `Y, A, B`.

2. **Redeem**: submit `f(admin_x)` to get the flag.

With only 4 evaluations of a degree-31 polynomial, standard interpolation is impossible (need 32 points). The vulnerability is in the mask ratchet mechanism.

## Analysis

### Proof structure

Each opening at point `x_i` computes:
```
T_i = taylor(f, x_i)         # Taylor expansion of f centered at x_i (32 coefficients)
z_i = u_i + c_i * T_i        # u_i is random mask, c_i is Fiat-Shamir challenge
w_i = shift_taylor(z_i, δ_i) # returned to verifier
```

From `w_i` we recover `z_i = shift_taylor(w_i, -δ_i)` since `δ_i` is derived from public values.

### The ratchet vulnerability

For queries 1-3, `u_i` is fresh random. For query 4, `_mask_for()` constructs:

```python
u_4 = shift_taylor(u_3, x4-x3) + μ·shift_taylor(u_2, x4-x2) + ν·shift_taylor(u_1, x4-x1)
```

where:
- `μ = ratchet_mu(x2, Y2, A2, B2)` — computable from query 2's public output
- `ν = ratchet_nu(x1, Y1, A1, B1, s1, t1)` — computable from query 1's public output

### The key mathematical property

Taylor expansion shifting is **linear**, and crucially:

```
shift_taylor(taylor(f, x_i), x_j - x_i) = taylor(f, x_j)
```

This is just the fact that re-centering a Taylor series from `x_i` to `x_j` gives the Taylor series at `x_j`.

### Deriving the attack

Substituting `u_i = z_i - c_i · T_i` into the ratchet relation:

```
z_4 - c_4·T_4 = shift(z_3 - c_3·T_3, x4-x3) + μ·shift(z_2 - c_2·T_2, x4-x2) + ν·shift(z_1 - c_1·T_1, x4-x1)
```

Since `shift(T_i, x4-xi) = T_4` for all `i`, every `T_i` term becomes `T_4`:

```
z_4 - c_4·T_4 = [shift(z_3, d3) + μ·shift(z_2, d2) + ν·shift(z_1, d1)] - (c_3 + μ·c_2 + ν·c_1)·T_4
```

Rearranging:

```
R = α · T_4
```

where:
- `R = z_4 - shift(z_3, x4-x3) - μ·shift(z_2, x4-x2) - ν·shift(z_1, x4-x1)` (all known)
- `α = c_4 - c_3 - μ·c_2 - ν·c_1` (all known)

If `α ≠ 0`, we recover the full 32-coefficient Taylor expansion of `f` at `x_4`, hence the entire polynomial.

## Solution

1. Make 4 queries at `x = 1, 2, 3, 4`
2. Recover `z_i = shift_taylor(w_i, -δ_i)` and `c_i = proof_chal(C, x_i, Y_i, A_i, B_i)`
3. Compute `μ` and `ν` from public query outputs
4. Compute `R` and `α`; recover `taylor(f, x_4) = R / α`
5. Convert Taylor expansion to coefficients: `f = taylor_to_coeff(T_4, x_4)`
6. Evaluate `f(admin_x)` and submit

### Solve script

```python
#!/usr/bin/env python3
from pwn import *
import hashlib, os

P = 65993754221047993367757014757310801859001451513902355017284390150045199658079
Q = 32996877110523996683878507378655400929500725756951177508642195075022599829039
N = 32

def i2b(x): return x.to_bytes(32, "big")

def htag(tag, *parts):
    h = hashlib.sha256(); h.update(tag)
    for part in parts:
        if isinstance(part, int): h.update(i2b(part))
        elif isinstance(part, bytes): h.update(len(part).to_bytes(2,"big")); h.update(part)
        elif isinstance(part, (list, tuple)):
            h.update(len(part).to_bytes(2,"big"))
            for x in part: h.update(i2b(x % Q))
    return int.from_bytes(h.digest(), "big") % Q

def proof_chal(C,x,Y,A,B): return htag(b"chal",C,x,Y,A,B)
def ratchet_mu(x,Y,A,B): mu=htag(b"ratchet",x,Y,A,B); return mu if mu else 1
def ratchet_nu(x,Y,A,B,s,t): nu=htag(b"tail",x,Y,A,B,s,t); return nu if nu else 1
def jet_delta(x,Y,A,B,s,t): return htag(b"jet",x,Y,A,B,s,t)

BINOM = [[0]*N for _ in range(N)]
for i in range(N): BINOM[i][0]=BINOM[i][i]=1
for i in range(2,N):
    for j in range(1,i): BINOM[i][j]=(BINOM[i-1][j-1]+BINOM[i-1][j])%Q

def shift_taylor(a, delta):
    out=[0]*N; pw=[1]*N
    for i in range(1,N): pw[i]=pw[i-1]*delta%Q
    for k in range(N):
        acc=0
        for j in range(k,N): acc+=BINOM[j][k]*pw[j-k]*a[j]
        out[k]=acc%Q
    return out

def vadd(a,b): return [(x+y)%Q for x,y in zip(a,b)]
def vsub(a,b): return [(x-y)%Q for x,y in zip(a,b)]
def vscale(k,a): return [(k*x)%Q for x in a]
def taylor_to_coeff(a,x): return shift_taylor(a,(-x)%Q)
def poly_eval(c,x):
    a=0
    for ci in reversed(c): a=(a*x+ci)%Q
    return a

r = remote('dyn-03.midnightflag.fr', 12159)
r.recvuntil(b'C = '); C = int(r.recvline().strip(), 16)
r.recvuntil(b'admin_x = '); admin_x = int(r.recvline().strip(), 16)

def query(x):
    r.sendlineafter(b'> ', b'1'); r.sendlineafter(b'x = ', hex(x).encode())
    r.recvuntil(b'Y = '); Y=int(r.recvline().strip(),16)
    r.recvuntil(b'A = '); A=int(r.recvline().strip(),16)
    r.recvuntil(b'B = '); B=int(r.recvline().strip(),16)
    r.recvuntil(b's = '); s=int(r.recvline().strip(),16)
    r.recvuntil(b't = '); t=int(r.recvline().strip(),16)
    r.recvuntil(b'w = '); w=[int(x,16) for x in r.recvline().strip().decode().split()]
    return {'x':x,'Y':Y,'A':A,'B':B,'s':s,'t':t,'w':w}

qs = [query(i+1) for i in range(4)]

# Recover z_i and c_i
zs = [shift_taylor(q['w'], (-jet_delta(q['x'],q['Y'],q['A'],q['B'],q['s'],q['t']))%Q) for q in qs]
cs = [proof_chal(C, q['x'], q['Y'], q['A'], q['B']) for q in qs]

# Ratchet values
mu = ratchet_mu(qs[1]['x'], qs[1]['Y'], qs[1]['A'], qs[1]['B'])
nu = ratchet_nu(qs[0]['x'], qs[0]['Y'], qs[0]['A'], qs[0]['B'], qs[0]['s'], qs[0]['t'])

# R = z4 - shift(z3, x4-x3) - mu*shift(z2, x4-x2) - nu*shift(z1, x4-x1)
x4 = qs[3]['x']
R = vsub(zs[3], vadd(shift_taylor(zs[2], (x4-qs[2]['x'])%Q),
    vadd(vscale(mu, shift_taylor(zs[1], (x4-qs[1]['x'])%Q)),
         vscale(nu, shift_taylor(zs[0], (x4-qs[0]['x'])%Q)))))

alpha = (cs[3] - cs[2] - mu*cs[1] - nu*cs[0]) % Q
T4 = vscale(pow(alpha, Q-2, Q), R)
f_coeffs = taylor_to_coeff(T4, x4)
f_admin = poly_eval(f_coeffs, admin_x)

r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'f(admin_x) = ', hex(f_admin).encode())
print(r.recvline().decode().strip())
r.close()
```

## Flag

```
MCTF{retargeted_taylor_masks_are_not_zero_knowledge}
```

## Key Lessons

- **Taylor shift is linear**: `shift_taylor(taylor(f, a), b-a) = taylor(f, b)`. This seemingly innocent identity is devastating when mask reuse creates linear relations — all polynomial unknowns collapse to the same variable.
- **Ratchet ≠ randomness**: Deriving new masks as linear combinations of old ones preserves entropy only if the polynomial structure can't be exploited. Here it leaks everything.
- **Zero-knowledge requires fresh randomness**: The system is ZK for 3 queries (fresh masks), but the 4th deterministic mask breaks it entirely — going from "zero knowledge" to "full knowledge" in one extra query.
- The attack succeeds with overwhelming probability (`α ≠ 0` since `α` is a hash-derived value mod Q).

## References

- Schnorr identification / sigma protocols
- Polynomial commitment schemes (KZG, IPA)
- Taylor series properties of polynomials over finite fields
