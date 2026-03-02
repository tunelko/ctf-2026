#!/usr/bin/env python3
# solve.py — GraphWalker solver
# Meet-in-the-Middle on 48-bit SL(2,P) matrix walk (24 + 24 bits).
# Uses numpy BFS + sorted-array binary search to stay within ~1.3 GB RAM.

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
HALF   = 24          # 48-bit path split in two 24-bit halves

# ── Matrix generation (matches gen.py / common.py exactly) ──────────

def mat_gen(state):
    counter = 0
    while True:
        h = hashlib.sha256(state + str(counter).encode()).digest()
        a = int.from_bytes(h[0:4], 'big') % P
        b = int.from_bytes(h[4:8], 'big') % P
        c = int.from_bytes(h[8:12], 'big') % P
        if a != 0:                              # a invertible mod P (P prime)
            d = ((1 + b * c) * pow(a, P-2, P)) % P
            return hashlib.sha256(h).digest(), (a, b, c, d)
        counter += 1

print("[*] Generating 48 matrix pairs ...")
mats_a = np.zeros((48, 4), dtype=np.int64)
mats_b = np.zeros((48, 4), dtype=np.int64)
sa, sb = SEED_A, SEED_B
for i in range(48):
    sa, ma = mat_gen(sa);  mats_a[i] = ma
    sb, mb = mat_gen(sb);  mats_b[i] = mb

# ── Vectorised helpers ───────────────────────────────────────────────

def vmul(rows, m):
    """Multiply every row (N,4) by scalar matrix m (4,), all mod P."""
    a,b,c,d = rows[:,0], rows[:,1], rows[:,2], rows[:,3]
    x,y,z,w = m[0], m[1], m[2], m[3]
    return np.column_stack([
        (a*x + b*z) % P,
        (a*y + b*w) % P,
        (c*x + d*z) % P,
        (c*y + d*w) % P,
    ])

def vinv(rows):
    """Inverse of SL(2,P) batch: det=1, so inv(a,b,c,d)=(d,-b,-c,a)."""
    r = np.empty_like(rows)
    r[:,0] =  rows[:,3]
    r[:,1] = (P - rows[:,1]) % P
    r[:,2] = (P - rows[:,2]) % P
    r[:,3] =  rows[:,0]
    return r

def pack_key(rows):
    """Pack (a,b,c) into one uint64: a·P² + b·P + c  (< P³ ≈ 10¹⁵ < 2⁵⁰).
    For a≠0 this uniquely identifies any SL(2,P) matrix (d is forced by det=1).
    We store d separately to handle the rare a=0 case correctly."""
    r = rows.astype(np.uint64)
    return r[:,0] * np.uint64(P * P) + r[:,1] * np.uint64(P) + r[:,2]

# ── Build RIGHT half (steps 24..47) ─────────────────────────────────
print("[*] Building right half ...")
r_rows  = np.array([[1, 0, 0, 1]], dtype=np.int64)
r_paths = np.array([0],            dtype=np.uint32)

for i in range(HALF):
    idx  = HALF + i
    new0 = vmul(r_rows, mats_a[idx])          # bit i = 0  → use A
    new1 = vmul(r_rows, mats_b[idx])          # bit i = 1  → use B
    r_rows  = np.vstack([new0, new1])
    r_paths = np.concatenate([r_paths, r_paths | np.uint32(1 << i)])
    if (i + 1) % 8 == 0:
        print(f"  right step {i+1:2d}/24 : {len(r_rows):>10,} entries")

print(f"[*] Right done : {len(r_rows):,} entries")

# Sort right by packed (a,b,c) key + keep d for collision check
print("[*] Sorting right half ...")
r_keys = pack_key(r_rows)
r_d    = r_rows[:, 3].astype(np.uint32)
order       = np.argsort(r_keys, kind='stable')
r_keys      = r_keys[order]
r_d         = r_d[order]
r_paths     = r_paths[order]
del r_rows, order

# ── Build LEFT half (steps 0..23) ────────────────────────────────────
print("[*] Building left half ...")
l_rows  = np.array([[1, 0, 0, 1]], dtype=np.int64)
l_paths = np.array([0],            dtype=np.uint32)

for i in range(HALF):
    new0 = vmul(l_rows, mats_a[i])
    new1 = vmul(l_rows, mats_b[i])
    l_rows  = np.vstack([new0, new1])
    l_paths = np.concatenate([l_paths, l_paths | np.uint32(1 << i)])
    if (i + 1) % 8 == 0:
        print(f"  left  step {i+1:2d}/24 : {len(l_rows):>10,} entries")

print(f"[*] Left done  : {len(l_rows):,} entries")

# ── Match: for each L, needle = L⁻¹ · TARGET should equal R ─────────
print("[*] Matching ...")
T       = np.array(TARGET, dtype=np.int64)
l_inv   = vinv(l_rows)
needles = vmul(l_inv, T)          # (2^24, 4)  needle = inv(L) * TARGET = R

n_keys = pack_key(needles)
n_d    = needles[:, 3].astype(np.uint32)

pos  = np.searchsorted(r_keys, n_keys)
pc   = np.minimum(pos, len(r_keys) - 1)   # clipped for safe indexing
mask = ((pos < len(r_keys)) &
        (r_keys[pc] == n_keys) &
        (r_d[pc]    == n_d))
hits = np.where(mask)[0]
print(f"[*] Candidates : {len(hits)}")

for h in hits:
    lp = int(l_paths[h])
    rp = int(r_paths[int(pc[h])])
    # Reconstruct 48-bit path string (bit j of lp = path[j], bit j of rp = path[24+j])
    path_str = ''.join(
        str((lp >> j) & 1) for j in range(HALF)
    ) + ''.join(
        str((rp >> j) & 1) for j in range(HALF)
    )
    key = sha256(path_str.encode()).digest()
    try:
        flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(ENC), 16).decode()
        print(f"\n[+] FLAG: {flag}\n")
        with open('flag.txt', 'w') as f:
            f.write(flag + '\n')
        break
    except Exception as e:
        print(f"  (decryption failed: {e})")
else:
    print("[-] No valid match found.")
