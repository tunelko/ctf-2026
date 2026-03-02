# GraphWalker

**Category:** CRYPTO
**Difficulty:** Hard
**Flag:** `HackOn{R4nd0ms_C4yL3y_Gr4pHs}`

## Description

> El caminante infinito del grafos...

A 48-step random walk on the Cayley graph of SL(2, P) (special linear group over F_P with P=100003). The walk produces a final matrix (TARGET) and the flag is AES-ECB encrypted with the SHA-256 of the 48-bit path bitstring.

## TL;DR

Meet-in-the-Middle (MITM) attack: split the 48-step walk into two 24-step halves. Enumerate all 2^24 left products and all 2^24 right products using numpy vectorised BFS, then match on `inv(L) * TARGET == R`.

## Analysis

**`gen.py`** (reconstructed):
- `P = 100003` (prime), two matrix sequences A and B generated from SEED_A/SEED_B via stateful SHA-256 hash chains
- `stateful_matrix_gen(state)` → yields SL(2,P) matrices (det=1) one at a time
- A random 48-bit path chooses between matrix A[i] or B[i] at each step i
- Final product = TARGET; flag encrypted with `AES-ECB(key=SHA256(path_str))`

**Attack surface**: 2^48 ≈ 2.8×10^14 paths → brute force infeasible. But MITM reduces this to 2×2^24 = 33M operations.

**Key observations**:
1. SL(2,P) is closed under multiplication: all intermediate products have det=1
2. For det=1 matrices: `inv(a,b,c,d) = (d, -b, -c, a) mod P`. O(1), no modular exponentiation needed
3. `TARGET = L * R` → `inv(L) * TARGET = R`: allows a build-and-search approach
4. With numpy vectorised operations, all 2^24 products can be computed in seconds

**Memory**: numpy arrays (2^24, 4) × int64 = 512 MB per half; sorted packed-key arrays = 256 MB. Total peak ≈ 1.3 GB.

## Solution

### Prerequisites

```bash
pip install numpy pycryptodome --break-system-packages
```

### Steps

1. Generate all 48 matrix pairs (A[0..47] and B[0..47]) from the two seeds using the same stateful SHA-256 chain as `gen.py`.

2. **Build RIGHT half** (steps 24..47): BFS-expand from the identity matrix, at each step doubling by multiplying all current products by A[idx] and B[idx] respectively. Track the 24-bit path suffix in a parallel uint32 array.

3. **Sort RIGHT half**: pack each matrix (a,b,c) into a uint64 key (`a·P² + b·P + c`; 51 bits, fits in uint64; unique for det=1 when a≠0). Sort by this key; store `d` separately for the rare `a=0` case.

4. **Build LEFT half** (steps 0..23): same BFS expansion.

5. **Match**: for every left product L, compute `needle = inv(L) * TARGET` in a single vectorised batch operation. Pack each needle's key and binary-search (numpy `searchsorted`) in the sorted right array. Verify `d` to handle potential key collisions.

6. **Decrypt**: reconstruct the 48-bit path string from the matched left and right path-bit integers, SHA-256 hash it, and AES-ECB decrypt the flag.

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — GraphWalker  (Meet-in-the-Middle on SL(2,P) 48-step walk)
# Usage: python3 solve.py

import numpy as np
import hashlib
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

P      = 100003
SEED_A = bytes.fromhex("327df81fac6c72b3a855bb549fb2e38a")
SEED_B = bytes.fromhex("a80cc5746f7213b7be71a6a406d39da2")
TARGET = (58678, 49100, 67323, 28706)
ENC    = bytes.fromhex("af8b7e84412f01b4612771fdc146fc790d897566d3b223425d726a0c6cf17aa4")
HALF   = 24

def mat_gen(state):
    counter = 0
    while True:
        h = hashlib.sha256(state + str(counter).encode()).digest()
        a = int.from_bytes(h[0:4], 'big') % P
        b = int.from_bytes(h[4:8], 'big') % P
        c = int.from_bytes(h[8:12], 'big') % P
        if a != 0:
            d = ((1 + b * c) * pow(a, P-2, P)) % P
            return hashlib.sha256(h).digest(), (a, b, c, d)
        counter += 1

mats_a = np.zeros((48, 4), dtype=np.int64)
mats_b = np.zeros((48, 4), dtype=np.int64)
sa, sb = SEED_A, SEED_B
for i in range(48):
    sa, ma = mat_gen(sa);  mats_a[i] = ma
    sb, mb = mat_gen(sb);  mats_b[i] = mb

def vmul(rows, m):
    a,b,c,d = rows[:,0], rows[:,1], rows[:,2], rows[:,3]
    x,y,z,w = m[0], m[1], m[2], m[3]
    return np.column_stack([(a*x+b*z)%P,(a*y+b*w)%P,(c*x+d*z)%P,(c*y+d*w)%P])

def vinv(rows):
    r = np.empty_like(rows)
    r[:,0] = rows[:,3]; r[:,1] = (P-rows[:,1])%P
    r[:,2] = (P-rows[:,2])%P; r[:,3] = rows[:,0]
    return r

def pack_key(rows):
    r = rows.astype(np.uint64)
    return r[:,0]*np.uint64(P*P) + r[:,1]*np.uint64(P) + r[:,2]

# Build & sort right half
r_rows  = np.array([[1,0,0,1]], dtype=np.int64)
r_paths = np.array([0], dtype=np.uint32)
for i in range(HALF):
    idx = HALF + i
    r_rows  = np.vstack([vmul(r_rows, mats_a[idx]), vmul(r_rows, mats_b[idx])])
    r_paths = np.concatenate([r_paths, r_paths | np.uint32(1 << i)])
r_keys = pack_key(r_rows); r_d = r_rows[:,3].astype(np.uint32)
order = np.argsort(r_keys, kind='stable')
r_keys = r_keys[order]; r_d = r_d[order]; r_paths = r_paths[order]
del r_rows, order

# Build left half
l_rows  = np.array([[1,0,0,1]], dtype=np.int64)
l_paths = np.array([0], dtype=np.uint32)
for i in range(HALF):
    l_rows  = np.vstack([vmul(l_rows, mats_a[i]), vmul(l_rows, mats_b[i])])
    l_paths = np.concatenate([l_paths, l_paths | np.uint32(1 << i)])

# Match
T = np.array(TARGET, dtype=np.int64)
needles = vmul(vinv(l_rows), T)
n_keys = pack_key(needles); n_d = needles[:,3].astype(np.uint32)
pos = np.searchsorted(r_keys, n_keys)
pc  = np.minimum(pos, len(r_keys) - 1)
mask = (pos < len(r_keys)) & (r_keys[pc] == n_keys) & (r_d[pc] == n_d)
for h in np.where(mask)[0]:
    lp = int(l_paths[h]); rp = int(r_paths[int(pc[h])])
    path_str = ''.join(str((lp>>j)&1) for j in range(HALF)) + \
               ''.join(str((rp>>j)&1) for j in range(HALF))
    key = sha256(path_str.encode()).digest()
    try:
        flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(ENC), 16).decode()
        print(f"FLAG: {flag}")
        open('flag.txt','w').write(flag+'\n')
        break
    except: pass
```

## Flag

```
HackOn{R4nd0ms_C4yL3y_Gr4pHs}
```
