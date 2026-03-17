#!/usr/bin/env python3
"""
Coke solver — Gabidulin McEliece with low distortion rank s=2.

Phase 1: Frobenius kernel attack to recover secret Gabidulin code.
Phase 2: Welch-Berlekamp decoding for Gabidulin codes.
"""

import json, hashlib
from Crypto.Cipher import AES

# ---- GF(2^64) arithmetic ----
MOD_POLY = (1 << 64) | (1 << 61) | (1 << 34) | (1 << 9) | 1
MASK64 = (1 << 64) - 1

def gf_reduce(a):
    while a.bit_length() > 64:
        a ^= MOD_POLY << (a.bit_length() - 65)
    return a & MASK64

def gf_mul(a, b):
    res = 0
    while b:
        if b & 1: res ^= a
        b >>= 1; a <<= 1
    return gf_reduce(res)

def gf_inv(a):
    if a == 0: raise ZeroDivisionError
    u, v = a, MOD_POLY; g1, g2 = 1, 0
    while u != 1:
        j = u.bit_length() - v.bit_length()
        if j < 0: u, v = v, u; g1, g2 = g2, g1; j = -j
        u ^= v << j; g1 ^= g2 << j
    return gf_reduce(g1)

def gf_square(a): return gf_mul(a, a)

def gf_frob(a, p=1):
    for _ in range(p): a = gf_square(a)
    return a

# ---- Matrix ops over GF(2^64) ----
def mat_mul_gf(A, B):
    r, m, c = len(A), len(A[0]), len(B[0])
    out = [[0]*c for _ in range(r)]
    for i in range(r):
        for k in range(m):
            if A[i][k] == 0: continue
            for j in range(c):
                if B[k][j]: out[i][j] ^= gf_mul(A[i][k], B[k][j])
    return out

def mat_rref(M):
    M = [row[:] for row in M]
    nrows, ncols = len(M), len(M[0])
    pr, pcs = 0, []
    for c in range(ncols):
        piv = next((i for i in range(pr, nrows) if M[i][c]), None)
        if piv is None: continue
        if piv != pr: M[pr], M[piv] = M[piv], M[pr]
        inv_p = gf_inv(M[pr][c])
        for j in range(ncols): M[pr][j] = gf_mul(M[pr][j], inv_p)
        for i in range(nrows):
            if i != pr and M[i][c]:
                f = M[i][c]
                for j in range(ncols): M[i][j] ^= gf_mul(f, M[pr][j])
        pcs.append(c); pr += 1
    return M, pcs, pr

def mat_frob(M):
    return [[gf_square(x) for x in row] for row in M]

def right_kernel(M):
    r, c = len(M), len(M[0])
    MT = [[M[i][j] for i in range(r)] for j in range(c)]
    aug = [MT[j] + [1 if i == j else 0 for i in range(c)] for j in range(c)]
    rref, pivots, rank = mat_rref(aug)
    return [[rref[i][r + j] for j in range(c)] for i in range(c) if all(rref[i][j] == 0 for j in range(r))]

# ---- Load challenge ----
print("[*] Loading challenge...")
with open('/home/ubuntu/midnightflagctf2026/crypto/coke/challenge_remote.json') as f:
    chall = json.loads(f.read())

K, N = 16, 48
N_SECRET, LAMBDA, DIST_RANK, T = 32, 16, 2, 8

Gpub = [[int(x, 16) for x in row] for row in chall['Gpub']]
y = [int(x, 16) for x in chall['cipher']['y']]
aes_data = chall['cipher']['aes']

# ==== PHASE 1: Frobenius kernel attack ====
print("[*] Phase 1: Frobenius kernel attack")

D_all = []
frob_cur = Gpub
for level in range(1, K):
    frob_cur = mat_frob(frob_cur)
    for i in range(K - level):
        D_all.append([frob_cur[i][j] ^ Gpub[i+level][j] for j in range(N)])
    _, _, rank_cur = mat_rref([r[:] for r in D_all])
    print(f"  D1..D{level}: rank={rank_cur}")
    if rank_cur >= LAMBDA:
        break

kernel = right_kernel(D_all)
print(f"  Kernel dimension: {len(kernel)}")

# Build projection V (N × kdim)
V = [[kernel[j][i] for j in range(len(kernel))] for i in range(N)]
GV = mat_mul_gf(Gpub, V)
n_code = len(GV[0])

# Verify Moore structure
GV_frob = mat_frob(GV)
diff = [[GV_frob[i][j] ^ GV[i+1][j] for j in range(n_code)] for i in range(K-1)]
_, _, rd = mat_rref([r[:] for r in diff])
print(f"  GV Frobenius diff rank: {rd}")
assert rd == 0, "GV is not pure Moore — need cleaning"

support = GV[0]  # g values
print(f"[+] Pure Moore code recovered, support size = {n_code}")

# Project y
yV = [0] * n_code
for j in range(n_code):
    for i in range(N):
        if y[i] and kernel[j][i]:
            yV[j] ^= gf_mul(y[i], kernel[j][i])

# ==== PHASE 2: Welch-Berlekamp decoding for Gabidulin codes ====
print("\n[*] Phase 2: Gabidulin decoding (Welch-Berlekamp)")

# Received word: r_j = yV[j] = f(g_j) + e_j
# where f(x) = sum_{i=0}^{k-1} m_i * x^{[i]} (linearized poly, q-degree < k)
# and e_j are errors with rank(e) ≤ t.
#
# Welch-Berlekamp for Gabidulin codes:
# Find linearized polynomials E (q-degree ≤ t) and V (q-degree ≤ k+t-1) such that:
#   V(g_j) = E(r_j) for all j = 0, ..., n-1
#
# E(x) = sum_{l=0}^{t} e_l * x^{[l]},  with e_t = 1 (normalization)
# V(x) = sum_{l=0}^{k+t-1} v_l * x^{[l]}
#
# The equation V(g_j) = E(r_j) becomes:
# sum_{l=0}^{k+t-1} v_l * g_j^{[l]} = sum_{l=0}^{t} e_l * r_j^{[l]}
#
# For each j, this is 1 equation in GF(2^64).
# Unknowns: v_0, ..., v_{k+t-1} (k+t = 24 unknowns) and e_0, ..., e_{t-1} (t = 8 unknowns)
# Total: 32 unknowns, 32 equations. Square system!

k, t = K, T
num_V = k + t  # 24
num_E = t      # 8 (e_t = 1 is fixed)

print(f"  Unknowns: {num_V} (V coeffs) + {num_E} (E coeffs) = {num_V + num_E}")
print(f"  Equations: {n_code}")

# Build the system: for each j:
# sum_{l=0}^{k+t-1} v_l * g_j^{[l]} - sum_{l=0}^{t-1} e_l * r_j^{[l]} = r_j^{[t]}
# (moving the known e_t * r_j^{[t]} to the RHS)

A_wb = [[0] * (num_V + num_E) for _ in range(n_code)]
b_wb = [0] * n_code

for j in range(n_code):
    # V coefficients: v_l multiplied by g_j^{[l]}
    for l in range(num_V):
        A_wb[j][l] = gf_frob(support[j], l)
    # E coefficients: -e_l multiplied by r_j^{[l]} (subtraction = XOR in char 2)
    for l in range(num_E):
        A_wb[j][num_V + l] = gf_frob(yV[j], l)
    # RHS: e_t * r_j^{[t]} = 1 * r_j^{[t]} = r_j^{[t]}
    b_wb[j] = gf_frob(yV[j], t)

# Solve
aug_wb = [A_wb[j] + [b_wb[j]] for j in range(n_code)]
rref_wb, pivots_wb, rank_wb = mat_rref(aug_wb)
print(f"  System rank: {rank_wb}/{num_V + num_E}")

if rank_wb < num_V + num_E:
    print(f"  Underdetermined — error rank might be < {t}")
    # The system is underdetermined when actual error rank < t.
    # In this case we should use t_actual < t.
    # Try to find t_actual by reducing t until the system is exactly determined.
    for t_try in range(t - 1, 0, -1):
        num_V_try = k + t_try
        num_E_try = t_try
        A_try = [[0] * (num_V_try + num_E_try) for _ in range(n_code)]
        b_try = [0] * n_code
        for j in range(n_code):
            for l in range(num_V_try):
                A_try[j][l] = gf_frob(support[j], l)
            for l in range(num_E_try):
                A_try[j][num_V_try + l] = gf_frob(yV[j], l)
            b_try[j] = gf_frob(yV[j], t_try)
        aug_try = [A_try[j] + [b_try[j]] for j in range(n_code)]
        rref_try, pivots_try, rank_try = mat_rref(aug_try)
        print(f"  t={t_try}: rank={rank_try}/{num_V_try + num_E_try}")
        if rank_try == num_V_try + num_E_try:
            # Found the right t
            rref_wb, pivots_wb, rank_wb = rref_try, pivots_try, rank_try
            num_V, num_E, t = num_V_try, num_E_try, t_try
            break

if rank_wb == num_V + num_E:
    print(f"[+] Full rank system with t={t}")
    # Extract V and E coefficients
    sol = [0] * (num_V + num_E)
    for idx, pc in enumerate(pivots_wb):
        if pc < num_V + num_E:
            sol[pc] = rref_wb[idx][num_V + num_E]

    V_coeffs = sol[:num_V]
    E_coeffs = sol[num_V:] + [1]  # append e_t = 1

    print(f"  V coefficients (q-degree < {num_V}): {[hex(x) for x in V_coeffs[:4]]}...")
    print(f"  E coefficients (q-degree {len(E_coeffs)-1}): {[hex(x) for x in E_coeffs]}")

    # Verify: V(g_j) should equal E(r_j) for all j
    ok = 0
    for j in range(n_code):
        vgj = 0
        for l in range(num_V):
            vgj ^= gf_mul(V_coeffs[l], gf_frob(support[j], l))
        erj = 0
        for l in range(len(E_coeffs)):
            erj ^= gf_mul(E_coeffs[l], gf_frob(yV[j], l))
        if vgj == erj: ok += 1
    print(f"  Verification: {ok}/{n_code} equations satisfied")

    # Now compute f = V / E (right skew division of linearized polynomials)
    # f(x) = sum_{i=0}^{k-1} m_i * x^{[i]}
    # We need: V(x) = E(f(x)) for all x in span(support)
    # Equivalently, V = E ∘ f (composition of linearized polynomials)
    #
    # In the "skew polynomial ring" F_q[x; σ] where σ = Frobenius:
    # V = E * f (skew multiplication)
    # f = E^{-1} * V (right division)
    #
    # Skew polynomial multiplication: (a * x^{[i]}) * (b * x^{[j]}) = a * b^{[i]} * x^{[i+j]}
    # So for E(x) = sum e_l * x^{[l]} and f(x) = sum m_i * x^{[i]}:
    # (E * f)(x) = sum_{l,i} e_l * m_i^{[l]} * x^{[l+i]}
    #
    # Coefficient of x^{[s]} in E*f:
    # V_s = sum_{l=0}^{min(s,deg_E)} e_l * m_{s-l}^{[l]}
    #
    # This gives us a triangular-ish system for m_i:
    # V_0 = e_0 * m_0
    # V_1 = e_0 * m_1 + e_1 * m_0^{[1]}
    # V_2 = e_0 * m_2 + e_1 * m_1^{[1]} + e_2 * m_0^{[2]}
    # ...
    # We can solve for m_i iteratively!

    print("[*] Computing f = V / E via right skew division...")
    msg = [0] * k
    for s in range(k):
        # V_s = sum_{l=0}^{min(s, len(E_coeffs)-1)} E_coeffs[l] * m_{s-l}^{[l]}
        # Isolate the l=0 term: V_s = E_coeffs[0] * m_s + (known terms)
        rhs = V_coeffs[s]
        for l in range(1, min(s + 1, len(E_coeffs))):
            if s - l >= 0 and s - l < k:
                rhs ^= gf_mul(E_coeffs[l], gf_frob(msg[s - l], l))
        # m_s = rhs / E_coeffs[0]
        if E_coeffs[0] == 0:
            print(f"[-] E_coeffs[0] = 0, cannot divide")
            break
        msg[s] = gf_mul(rhs, gf_inv(E_coeffs[0]))

    print(f"  msg[:5] = {[hex(x) for x in msg[:5]]}")

    # Verify: compute f(g_j) and check against yV - e
    codeword_check = [0] * n_code
    for j in range(n_code):
        for i in range(k):
            codeword_check[j] ^= gf_mul(msg[i], gf_frob(support[j], i))

    # Compute error
    err = [codeword_check[j] ^ yV[j] for j in range(n_code)]
    err_rank = 0
    piv = {}
    for v in err:
        x = v
        while x:
            col = x.bit_length() - 1
            if col in piv: x ^= piv[col]
            else: piv[col] = x; break
    err_rank = len(piv)
    print(f"  Error rank: {err_rank} (expected ≤ {T})")

    if err_rank <= T:
        print("[+] Decoding successful!")
    else:
        print(f"[-] Error rank too high ({err_rank} > {T})")

    # ---- Decrypt ----
    print("\n[*] Decrypting flag...")
    msg_bytes = b"".join(x.to_bytes(8, 'little') for x in msg)
    key = hashlib.sha256(msg_bytes).digest()

    nonce = bytes.fromhex(aes_data['nonce'])
    ct = bytes.fromhex(aes_data['ct'])
    tag = bytes.fromhex(aes_data['tag'])

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag)
        print(f"\n[+] FLAG: {plaintext.decode()}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        print(f"  key = {key.hex()}")
else:
    print(f"[-] System rank {rank_wb} < {num_V + num_E}, cannot solve")
