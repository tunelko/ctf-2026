# PQChat

**CTF:** Midnight Flag CTF 2026
**Category:** Crypto
**Author:** fun88337766
**Difficulty:** Hard

## TL;DR

Module-LWE over `Z_12289[x]/(x^512 + 1)` with K=21 secret polynomials. The secrets are structured as products of 5 base polynomials with publicly-derivable mask polynomials `h`, `g`, and the bases have disjoint spectral support across 5 NTT-domain bands. The error is sampled small **in the spectral domain** (values in {-2,-1,0,1,2}). This collapses recovery to 512 independent 1-unknown equations, each trivially solvable.

## Description

A "post-quantum chat" server operates over the ring `R_q = Z_q[x]/(x^512 + 1)` with `q = 12289`. The menu exposes:

1. **Public parameters** — includes deterministic seeds for mask polynomials `h`, `g`
2. **Handshake transcripts** (up to 48) — `(a_0, ..., a_20, b)` where `b = sum_j a_j * s_j + e`
3. **Encrypted flag** — AES-GCM, key = SHA256(s_base)[:16]
4. **Submit recovered secret** — returns flag if `s_base` matches

Parameters: `N=512, Q=12289, K=21, eta_s=7, eta_e=2`.

## Vulnerability: Three Structural Weaknesses

### 1. Masks h, g are publicly deterministic

The seeds are hardcoded constants in the source:

```python
LAYOUT_SEED = b"pqchat.layout.v7.reduction-chain"
MASK_H_SEED = b"pqchat.mask-h.v7.reduction-chain"
MASK_G_SEED = b"pqchat.mask-g.v7.reduction-chain"
```

We can fully reconstruct `h_hat[r]` and `g_hat[r]` (the NTT spectra of `h` and `g`) using `expand_mask_spectra()`.

### 2. Secret "reduction chain" structure

The 21 secrets are derived from just 5 base polynomials (`s0, t0, t1, t2, t3`):

```
s[0]  = s0            s[7]  = t0            s[10] = t1
s[1]  = h * s0        s[8]  = h * t0        s[11] = h * t1
s[2]  = g * s0        s[9]  = g * t0        s[12] = g * t1
s[3]  = h² * s0
s[4]  = hg * s0       s[13] = t2            s[17] = t3
s[5]  = g² * s0       s[14] = h * t2        s[18] = h * t3
s[6]  = h²g * s0      s[15] = g * t2        s[19] = g * t3
                       s[16] = hg * t2       s[20] = g² * t3
```

In the NTT domain, polynomial multiplication becomes pointwise. At each NTT slot `r`, `S_j[r]` is just the base value (`s0_hat[r]` or `t_i_hat[r]`) multiplied by known powers of `h_hat[r]` and `g_hat[r]`.

### 3. Disjoint spectral support + small spectral error

The 512 NTT slots are partitioned into 5 disjoint bands:

| Band | Size | Active base | Condition on (u,v) = (h_hat[r], g_hat[r]) |
|------|------|-------------|---------------------------------------------|
| band0 | 80 | t0_hat | u² + 1 ≡ 0 (mod q) |
| band1 | 80 | t1_hat | v² - σ ≡ 0 (mod q) |
| band2 | 96 | t2_hat | v ≡ u² (mod q) |
| band3 | 96 | t3_hat | uv ≡ τ (mod q) |
| live  | 160 | s0_hat | none of the above |

At each slot `r`, **only one base has a nonzero spectral value**. The others are zero by construction.

The error polynomial is generated as:
```python
e_hat = _sample_from_table(seed, b"/e-ntt", ERROR_VALUE_TABLE, n, q)  # {-2,-1,0,0,1,2}
e = spec_inverse(e_hat, q=q)  # INTT to time domain
```

So the error is small **in the NTT domain** — each `e_hat[r] ∈ {-2,-1,0,1,2}`.

### Combined effect

At each NTT slot `r`, the handshake equation reduces to:

```
B_i[r] = C_i[r] * x[r] + e_i_hat[r],    e_i_hat[r] ∈ {-2,-1,0,1,2}
```

where:
- `x[r]` is the single unknown spectral value (s0_hat or t_i_hat depending on band)
- `C_i[r]` is a known linear combination of `A_i_j[r]` weighted by powers of `h_hat[r], g_hat[r]`
- We have 48 equations for 1 unknown with tiny noise

## Solution

### Algorithm

For each NTT slot `r`:
1. Determine which band it belongs to (and thus which base polynomial is active)
2. Compute the effective coefficient `C_i[r]` for each sample
3. From the first equation with `C_i ≠ 0`, enumerate `e ∈ {-2,-1,0,1,2}`: compute `x_cand = (B_i - e) / C_i mod q`
4. Verify each candidate against other equations (residuals must also be in {-2,...,2})
5. Store the confirmed `x[r]`

After recovering all 512 spectral values of `s0_hat`, apply inverse NTT to get `s0` in coefficient domain, derive the AES key, and decrypt the flag.

### Solve Script

```python
#!/usr/bin/env python3
"""
PQChat solver — exploit disjoint spectral support + small NTT-domain error
"""

from pwn import *
import json, hashlib, os
import numpy as np
from Crypto.Cipher import AES

N, Q, K, MAX_SAMPLES = 512, 12289, 21, 48
POLY_BITS = 14
MAIN_SLOTS = 160
AUX_BAND_SLOTS = (80, 80, 96, 96)
LAYOUT_SEED = b"pqchat.layout.v7.reduction-chain"
MASK_H_SEED = b"pqchat.mask-h.v7.reduction-chain"
MASK_G_SEED = b"pqchat.mask-g.v7.reduction-chain"

def modinv(a, q=Q): return pow(a % q, q - 2, q)

def unpack_poly(hex_str):
    bits = int.from_bytes(bytes.fromhex(hex_str), 'little')
    return np.array([(bits >> (i*POLY_BITS)) & ((1<<POLY_BITS)-1) for i in range(N)], dtype=np.int64) % Q

# ---- NTT roots ----
def _prime_factors(m):
    if m <= 1: return ()
    n, out, d = m, [], 2
    while d*d <= n:
        if n % d == 0:
            out.append(d)
            while n % d == 0: n //= d
        d += 1
    if n > 1: out.append(n)
    return tuple(out)

def primitive_root(q):
    for g in range(2, q):
        if all(pow(g, (q-1)//p, q) != 1 for p in _prime_factors(q-1)):
            return g

ROOTS = (lambda z: [pow(z, 2*j+1, Q) for j in range(N)])(
    pow(primitive_root(Q), (Q-1)//(2*N), Q))
INV_ROOTS = [modinv(r) for r in ROOTS]
INV_N = modinv(N)

# ---- Layout / mask expansion (identical to server) ----
def _rank_indices(seed, tag, n):
    scored = [(hashlib.sha256(seed+tag+i.to_bytes(4,'little')).digest(), i) for i in range(n)]
    scored.sort()
    return [i for _,i in scored]

def _band_layout(seed, n):
    order = _rank_indices(seed, b"/band-layout", n)
    n0,n1,n2,n3 = AUX_BAND_SLOTS
    return order[:n0], order[n0:n0+n1], order[n0+n1:n0+n1+n2], order[n0+n1+n2:n0+n1+n2+n3], order[n0+n1+n2+n3:]

def _special_constants(q):
    g = primitive_root(q)
    ri = pow(g, (q-1)//4, q)
    sr = pow(g, (q-1)//8, q)
    return g, ri, sr, (sr*sr)%q, pow(g,73,q)

def _pick_value(seed, tag, idx, q, accept):
    c = 0
    while True:
        d = hashlib.sha256(seed+tag+idx.to_bytes(4,'little')+c.to_bytes(2,'little')).digest()
        v = (int.from_bytes(d[:2],'little') % (q-1)) + 1
        if accept(v): return v
        c += 1

def _is_band0(u,v,q,s,t): return (u*u+1)%q==0
def _is_band1(u,v,q,s,t): return (v*v-s)%q==0
def _is_band2(u,v,q,s,t): return v%q==(u*u)%q
def _is_band3(u,v,q,s,t): return (u*v-t)%q==0

def classify_slot(u,v,q):
    _,_,_,sigma,tau = _special_constants(q)
    if _is_band0(u,v,q,sigma,tau): return 0
    if _is_band1(u,v,q,sigma,tau): return 1
    if _is_band2(u,v,q,sigma,tau): return 2
    if _is_band3(u,v,q,sigma,tau): return 3
    return 4

def expand_mask_spectra():
    band0,band1,band2,band3,live = _band_layout(LAYOUT_SEED, N)
    _,ri,sr,sigma,tau = _special_constants(Q); q=Q
    h_hat,g_hat = [0]*N, [0]*N

    for idx in band0:
        bit = hashlib.sha256(MASK_H_SEED+b"/band0/u"+idx.to_bytes(4,'little')).digest()[0]&1
        u = ri if bit==0 else (-ri)%q
        v = _pick_value(MASK_G_SEED, b"/band0/v", idx, q,
            lambda x,uu=u: not _is_band1(uu,x,q,sigma,tau) and not _is_band2(uu,x,q,sigma,tau) and not _is_band3(uu,x,q,sigma,tau))
        h_hat[idx],g_hat[idx] = u,v

    for idx in band1:
        bit = hashlib.sha256(MASK_G_SEED+b"/band1/v"+idx.to_bytes(4,'little')).digest()[0]&1
        v = sr if bit==0 else (-sr)%q
        u = _pick_value(MASK_H_SEED, b"/band1/u", idx, q,
            lambda x,vv=v: not _is_band0(x,vv,q,sigma,tau) and not _is_band2(x,vv,q,sigma,tau) and not _is_band3(x,vv,q,sigma,tau))
        h_hat[idx],g_hat[idx] = u,v

    for idx in band2:
        u = _pick_value(MASK_H_SEED, b"/band2/u", idx, q,
            lambda x: x!=0 and (x*x+1)%q!=0 and ((x*x)%q)!=sr and ((x*x)%q)!=(-sr)%q and (x*((x*x)%q)-tau)%q!=0)
        h_hat[idx],g_hat[idx] = u,(u*u)%q

    for idx in band3:
        def _acc(x):
            if x==0 or (x*x+1)%q==0: return False
            vv=(tau*pow(x,-1,q))%q
            return not _is_band1(x,vv,q,sigma,tau) and not _is_band2(x,vv,q,sigma,tau)
        u = _pick_value(MASK_H_SEED, b"/band3/u", idx, q, _acc)
        h_hat[idx],g_hat[idx] = u,(tau*pow(u,-1,q))%q

    for idx in live:
        c=0
        while True:
            du=hashlib.sha256(MASK_H_SEED+b"/live/u"+idx.to_bytes(4,'little')+c.to_bytes(2,'little')).digest()
            dv=hashlib.sha256(MASK_G_SEED+b"/live/v"+idx.to_bytes(4,'little')+c.to_bytes(2,'little')).digest()
            u=(int.from_bytes(du[:2],'little')%(q-1))+1; v=(int.from_bytes(dv[:2],'little')%(q-1))+1
            if classify_slot(u,v,q)==4:
                h_hat[idx],g_hat[idx]=u,v; break
            c+=1
    return h_hat,g_hat

# ---- Per-band coefficient formulas (from server's active_coeff) ----
def main_mults(u,v,q):   # j=0..6 for s0
    u2=(u*u)%q; return [1, u, v, u2, (u*v)%q, (v*v)%q, (u2*v)%q]
def blind0_mults(u,v,q):  # j=7..9 for t0
    return [1, u, v]
def blind1_mults(u,v,q):  # j=10..12 for t1
    return [1, u, v]
def blind2_mults(u,v,q):  # j=13..16 for t2
    return [1, u, v, (u*v)%q]
def blind3_mults(u,v,q):  # j=17..20 for t3
    return [1, u, v, (v*v)%q]

def main():
    # 1. Expand public masks and compute band layout
    h_hat, g_hat = expand_mask_spectra()
    bands = _band_layout(LAYOUT_SEED, N)
    slot_type = {}
    for band_id, band_list in enumerate(bands):
        for idx in band_list:
            slot_type[idx] = band_id  # 0-3 = aux bands, 4 = live (main)

    # 2. Connect to server, collect encrypted flag + 48 handshake samples
    HOST = os.environ.get('HOST', 'dyn-01.midnightflag.fr')
    PORT = int(os.environ.get('PORT', '10220'))
    r = remote(HOST, PORT)
    r.recvuntil(b'> ')

    r.sendline(b'3')
    flag_data = json.loads(r.recvuntil(b'> ').decode().strip().split('\n')[0])

    samples = []
    for i in range(MAX_SAMPLES):
        r.sendline(b'2')
        hs = json.loads(r.recvuntil(b'> ').decode().strip().split('\n')[0])
        samples.append(([unpack_poly(h) for h in hs['a_hex']], unpack_poly(hs['b_hex'])))
        if (i+1)%10==0: print(f"  Collected {i+1}/{MAX_SAMPLES}")

    # 3. NTT-transform all sample polynomials via matrix multiply
    fwd = np.zeros((N,N), dtype=np.int64)
    for i in range(N):
        rj=1
        for j in range(N):
            fwd[i,j]=rj; rj=(rj*ROOTS[i])%Q

    ntt_samples = []
    for a_polys, b_poly in samples:
        ntt_samples.append(([fwd@a%Q for a in a_polys], fwd@b_poly%Q))

    # 4. Solve per-slot: 1 unknown, 48 equations, error in {-2,-1,0,1,2}
    s0_hat = [0]*N
    BAND_CONFIG = {
        4: (main_mults,   list(range(7))),
        0: (blind0_mults, [7,8,9]),
        1: (blind1_mults, [10,11,12]),
        2: (blind2_mults, [13,14,15,16]),
        3: (blind3_mults, [17,18,19,20]),
    }

    for slot_r in range(N):
        u,v = h_hat[slot_r], g_hat[slot_r]
        band = slot_type[slot_r]
        mult_fn, j_indices = BAND_CONFIG[band]
        mults = mult_fn(u, v, Q)

        # Compute effective coefficient c_i and observed b_i for each sample
        c_vals = np.zeros(48, dtype=np.int64)
        b_vals = np.zeros(48, dtype=np.int64)
        for i in range(48):
            ntt_a, ntt_b = ntt_samples[i]
            c = 0
            for m, j in enumerate(j_indices):
                c = (c + int(ntt_a[j][slot_r]) * mults[m]) % Q
            c_vals[i] = c
            b_vals[i] = int(ntt_b[slot_r])

        nz = [i for i in range(48) if c_vals[i]%Q != 0]
        i0 = nz[0]
        ci0_inv = modinv(int(c_vals[i0]))

        # Enumerate 5 error candidates from first equation, verify against rest
        best_x, best_score = 0, -1
        for e0 in [-2,-1,0,1,2]:
            x_cand = ((int(b_vals[i0])-e0)*ci0_inv) % Q
            score = sum(1 for idx in nz[1:20]
                        if abs(((int(b_vals[idx])-int(c_vals[idx])*x_cand)%Q+Q//2)%Q - Q//2) <= 2)
            if score > best_score:
                best_score, best_x = score, x_cand

        if band == 4:  # only need s0_hat for the flag
            s0_hat[slot_r] = int(best_x)

    # 5. Inverse NTT to recover s0 coefficients
    inv = np.zeros((N,N), dtype=np.int64)
    for j in range(N):
        for i in range(N):
            inv[j,i] = pow(INV_ROOTS[i], j, Q)
    s0_coeffs = [(int(x)*INV_N)%Q for x in (inv @ np.array(s0_hat, dtype=np.int64)) % Q]

    # 6. Derive AES key and decrypt
    key = hashlib.sha256(b''.join(int(c%Q).to_bytes(2,'little') for c in s0_coeffs)).digest()[:16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(flag_data['nonce_hex']))
    flag = cipher.decrypt_and_verify(bytes.fromhex(flag_data['ct_hex']), bytes.fromhex(flag_data['tag_hex']))
    print(f"\n[+] FLAG: {flag.decode()}")
    r.close()

if __name__ == '__main__':
    main()
```

## Flag

```
MCTF{OH_SHIT_REDUCTION_IS_ON_TOP}
```

## Key Lessons

- **Read the server code**: the entire attack depends on understanding `expand_mask_spectra()` and `Oracle.__init__()` which reveal the secret structure and public seeds
- **NTT domain analysis is essential** for ring/module-LWE: polynomial multiplication becomes pointwise, exposing structural weaknesses that are invisible in coefficient domain
- **Disjoint spectral support** means each NTT slot has at most one active secret — collapsing 21 unknowns to 1
- **Error generation matters**: sampling `e_hat` from a small table then doing INTT means the NTT-domain error is bounded, not the coefficient-domain error — this is backwards from standard LWE conventions and is the critical vulnerability
- The challenge name ("reduction chain") is a hint: the secrets form a chain of polynomial multiplications by h and g

## References

- Negacyclic NTT for `Z_q[x]/(x^n + 1)`: evaluating at roots of `x^n + 1`
- Module-LWE: [Wikipedia](https://en.wikipedia.org/wiki/Learning_with_errors)
- The spectral support structure resembles "sparse secret" attacks on LWE variants
