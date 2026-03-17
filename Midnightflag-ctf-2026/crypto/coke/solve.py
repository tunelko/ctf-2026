#!/usr/bin/env python3
"""
Coke solver — Gabidulin-based McEliece with low distortion rank s=2.
Attack: Frobenius distinguisher exploiting low distortion rank.

Structure: Gpub = [X | Gsec] * P
- Gsec is K×N_SECRET Moore matrix (Gabidulin code)
- X is K×LAMBDA distortion matrix with rank s=2
- P is N×N invertible binary matrix

Key insight: Applying Frobenius (squaring) to Gpub rows shifts Moore matrix rows,
but the distortion part stays low-rank. Building a "Frobenius kernel" matrix
reveals the code structure.
"""

import json
import hashlib
import secrets
import numpy as np
from Crypto.Cipher import AES

# ---- GF(2^64) arithmetic (from server) ----
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

def gf_square(a): return gf_mul(a, a)

def gf_frob(a, pow_=1):
    for _ in range(pow_): a = gf_square(a)
    return a

def gf_inv(a):
    if a == 0: raise ZeroDivisionError
    u, v = a, MOD_POLY
    g1, g2 = 1, 0
    while u != 1:
        j = u.bit_length() - v.bit_length()
        if j < 0:
            u, v = v, u; g1, g2 = g2, g1; j = -j
        u ^= v << j; g1 ^= g2 << j
    return gf_reduce(g1)

def rank_q_elems(elems):
    piv = {}
    for v in elems:
        x = v & MASK64
        while x:
            col = x.bit_length() - 1
            if col in piv:
                x ^= piv[col]
            else:
                piv[col] = x
                break
    return len(piv)

def gf_pow(a, e):
    r = 1
    while e:
        if e & 1: r = gf_mul(r, a)
        a = gf_square(a); e >>= 1
    return r

# ---- Matrix operations over GF(2^64) ----
def mat_frob(M):
    """Apply Frobenius (squaring) to every element"""
    return [[gf_square(x) for x in row] for row in M]

def mat_sub(A, B):
    """A XOR B (subtraction = addition in char 2)"""
    return [[a ^ b for a, b in zip(ra, rb)] for ra, rb in zip(A, B)]

def mat_mul_gf(A, B):
    r = len(A); m = len(A[0]); c = len(B[0])
    out = [[0]*c for _ in range(r)]
    for i in range(r):
        for k in range(m):
            if A[i][k] == 0: continue
            for j in range(c):
                if B[k][j]: out[i][j] ^= gf_mul(A[i][k], B[k][j])
    return out

def mat_vstack(A, B):
    return A + B

def mat_rref(M):
    """Row echelon form, return (rref_matrix, pivot_cols, rank)"""
    M = [row[:] for row in M]
    nrows, ncols = len(M), len(M[0])
    pivot_row = 0
    pivot_cols = []
    for c in range(ncols):
        piv = None
        for i in range(pivot_row, nrows):
            if M[i][c] != 0: piv = i; break
        if piv is None: continue
        if piv != pivot_row:
            M[pivot_row], M[piv] = M[piv], M[pivot_row]
        inv_p = gf_inv(M[pivot_row][c])
        for j in range(ncols):
            M[pivot_row][j] = gf_mul(M[pivot_row][j], inv_p)
        for i in range(nrows):
            if i != pivot_row and M[i][c] != 0:
                f = M[i][c]
                for j in range(ncols):
                    M[i][j] ^= gf_mul(f, M[pivot_row][j])
        pivot_cols.append(c)
        pivot_row += 1
    return M, pivot_cols, pivot_row

def right_kernel(M):
    """Compute right kernel of M (columns x such that M*x = 0).
    M is r×c. Returns list of column vectors (as lists)."""
    r = len(M); c = len(M[0])
    # Transpose, then find left kernel
    MT = [[M[i][j] for i in range(r)] for j in range(c)]
    # Augment MT with identity
    aug = [MT[j] + [1 if i == j else 0 for i in range(c)] for j in range(c)]
    rref, pivots, rank = mat_rref(aug)
    # Kernel vectors are rows where the first r columns are zero
    kernel = []
    for i in range(c):
        if all(rref[i][j] == 0 for j in range(r)):
            kernel.append([rref[i][r + j] for j in range(c)])
    return kernel

def left_kernel(M):
    """Compute left kernel of M (rows x such that x*M = 0)."""
    r = len(M); c = len(M[0])
    aug = [M[i] + [1 if j == i else 0 for j in range(r)] for i in range(r)]
    rref, pivots, rank = mat_rref(aug)
    kernel = []
    for i in range(r):
        if all(rref[i][j] == 0 for j in range(c)):
            kernel.append([rref[i][c + j] for j in range(r)])
    return kernel

# ---- Load challenge ----
print("[*] Loading challenge...")
with open('/home/ubuntu/midnightflagctf2026/crypto/coke/challenge_remote.json') as f:
    chall = json.loads(f.read())

params = chall['params']
Q, M_BITS = params['q'], params['m']
N_SECRET, K, LAMBDA = params['n'], params['k'], params['lam']
DIST_RANK, T = params['s'], params['t']
N = N_SECRET + LAMBDA  # 48

Gpub = [[int(x, 16) for x in row] for row in chall['Gpub']]
y = [int(x, 16) for x in chall['cipher']['y']]
aes_data = chall['cipher']['aes']

print(f"  Gpub: {K}x{N} over GF(2^{M_BITS})")
print(f"  n={N_SECRET}, k={K}, lambda={LAMBDA}, s={DIST_RANK}, t={T}")
print(f"  Note: {chall.get('note','')}")

# ---- Attack: Exploit low distortion rank ----
# Gpub = [X | Gsec] * P where X has rank s=2
# Gsec is Moore matrix: row i = [g1^(2^i), ..., g_n^(2^i)]
#
# Key property of Moore matrix: Frob(row_i) = row_{i+1}
# So Frob(Gsec[i]) = Gsec[i+1] for i < K-1
#
# For the distortion part X = A*B (K×LAMBDA, rank s):
# Frob(X[i]) is NOT simply X[i+1]
#
# Define: F_i = Frob(Gpub[i]) (apply squaring elementwise)
# Then: Frob(Gpub[i]) * P^{-1} = [Frob(X[i]) | Gsec[i+1]]
# And:  Gpub[i+1] * P^{-1} = [X[i+1] | Gsec[i+1]]
#
# So: (Frob(Gpub[i]) - Gpub[i+1]) * P^{-1} = [Frob(X[i]) - X[i+1] | 0...0]
#
# The right N_SECRET columns are zero! And the left LAMBDA columns have rank ≤ 2*s = 4.
#
# Build matrix D with rows: Frob(Gpub[i]) - Gpub[i+1] for i=0..K-2
# D has K-1=15 rows, N=48 columns.
# D * P^{-1} has its right N_SECRET=32 columns all zero.
# So right_kernel(D) has dimension ≥ N_SECRET = 32.
# Actually D * P^{-1} has rank ≤ 2*s = 4, so right kernel of D has dim ≥ 48-4 = 44.
# But we need to separate the "useful" 32-dimensional kernel from the rest.
#
# Better approach: stack multiple Frobenius levels.
# D_l = Frob^l(Gpub[i]) - Gpub[i+l]
# Each gives equations. With enough levels, the intersection of kernels
# should converge to the column space of P restricted to the secret part.

print("\n[*] Building Frobenius difference matrices...")

# D_1: rows = Frob(Gpub[i]) - Gpub[i+1] for i=0..K-2
D1 = []
Gpub_frob = mat_frob(Gpub)
for i in range(K - 1):
    row = [Gpub_frob[i][j] ^ Gpub[i+1][j] for j in range(N)]
    D1.append(row)

print(f"  D1: {len(D1)}x{N}")
_, _, rank_D1 = mat_rref([r[:] for r in D1])
print(f"  rank(D1) = {rank_D1}")

# D_2: rows = Frob^2(Gpub[i]) - Gpub[i+2]
D2 = []
Gpub_frob2 = mat_frob(Gpub_frob)
for i in range(K - 2):
    row = [Gpub_frob2[i][j] ^ Gpub[i+2][j] for j in range(N)]
    D2.append(row)

print(f"  D2: {len(D2)}x{N}")
_, _, rank_D2 = mat_rref([r[:] for r in D2])
print(f"  rank(D2) = {rank_D2}")

# Stack D1 and D2
D_stacked = D1 + D2
_, _, rank_stacked = mat_rref([r[:] for r in D_stacked])
print(f"  rank(D1+D2) = {rank_stacked}")

# Add D_3
D3 = []
Gpub_frob3 = mat_frob(Gpub_frob2)
for i in range(K - 3):
    row = [Gpub_frob3[i][j] ^ Gpub[i+3][j] for j in range(N)]
    D3.append(row)
D_stacked2 = D_stacked + D3
_, _, rank_s2 = mat_rref([r[:] for r in D_stacked2])
print(f"  rank(D1+D2+D3) = {rank_s2}")

# The rank should be at most 2*s * (number of Frobenius levels) but bounded by LAMBDA=16
# since D * P^{-1} only has nonzero entries in LAMBDA columns.
# So max rank = LAMBDA = 16.
# right_kernel dimension = N - rank = 48 - 16 = 32 = N_SECRET

print("\n[*] Computing right kernel...")
# Use the stacked matrix with enough rank
# Choose whichever stacked matrix has rank = LAMBDA = 16
# Keep stacking Frobenius levels until rank = LAMBDA (16)
D_all = list(D_stacked2)
rank_all = rank_s2
frob_prev = Gpub_frob3

for level in range(4, K):
    if rank_all >= LAMBDA:
        break
    frob_cur = mat_frob(frob_prev)
    for i in range(K - level):
        row = [frob_cur[i][j] ^ Gpub[i+level][j] for j in range(N)]
        D_all.append(row)
    _, _, rank_all = mat_rref([r[:] for r in D_all])
    print(f"  rank(D1+...+D{level+1}) = {rank_all}")
    frob_prev = frob_cur

D_use = D_all
rank_use = rank_all

print(f"  Using matrix with rank {rank_use}")

# Right kernel = column vectors v such that D_use * v = 0
# These v's span the image of P restricted to the last N_SECRET columns
kernel = right_kernel(D_use)
print(f"  Kernel dimension: {len(kernel)}")

if len(kernel) < N_SECRET:
    print(f"[-] Kernel too small ({len(kernel)} < {N_SECRET}), need more equations")
else:
    print(f"[+] Kernel dimension {len(kernel)} >= N_SECRET={N_SECRET}")

# The kernel vectors form a matrix V (N × dim_kernel) such that
# Gpub * V gives us a matrix that is essentially Gsec * P_sub
# where P_sub is the restriction of P to the secret columns.
#
# Gpub * V = [X | Gsec] * P * V
# Since D * V = 0, we know P * V has zeros in the first LAMBDA rows
# (approximately — it spans the last N_SECRET column space of P).
# So Gpub * V ≈ Gsec (up to a basis change).

# Build V matrix (N × kernel_dim) from kernel vectors (each is length N)
V = [[kernel[j][i] for j in range(len(kernel))] for i in range(N)]

# Compute Gpub * V
GV = mat_mul_gf(Gpub, V)
print(f"  Gpub * V: {len(GV)}x{len(GV[0])}")

# GV should be a K × kernel_dim matrix that is a Gabidulin code (Moore matrix)
# up to column operations. Verify Frobenius structure:
# Frob(GV[i]) should equal GV[i+1] (up to the distortion leaking through).

# Check: is Frob(GV[i]) - GV[i+1] zero or low-rank?
GV_frob = [[gf_square(x) for x in row] for row in GV]
diff_check = []
for i in range(K-1):
    diff_check.append([GV_frob[i][j] ^ GV[i+1][j] for j in range(len(GV[0]))])

_, _, rank_diff = mat_rref([r[:] for r in diff_check])
print(f"  rank(Frob(GV) - GV_shifted) = {rank_diff}")

if rank_diff == 0:
    print("[+] GV is a pure Gabidulin code! No distortion leakage.")
elif rank_diff <= DIST_RANK:
    print(f"[+] GV has distortion rank {rank_diff} — need to clean it")

    # Clean GV: find a subspace of the kernel where GV is a pure Moore matrix.
    # The idea: the kernel has dim 48 - rank_use. Some directions correspond to
    # the distortion columns of P. We need to find the N_SECRET-dimensional
    # subspace where the Frobenius structure holds.

    # Approach: compute the intersection of right kernels of diff_check
    # (the Frobenius differences of GV). This gives the "good" subspace.
    # diff_check has rank_diff columns that cause trouble.
    # right_kernel(diff_check) has dimension kernel_dim - rank_diff.

    print("[*] Cleaning: finding pure Moore subspace of GV...")
    # diff_check is (K-1) × kernel_dim
    ker2 = right_kernel(diff_check)
    print(f"  Inner kernel dimension: {len(ker2)}")

    if len(ker2) >= N_SECRET:
        # Project kernel through ker2 to get a cleaner basis
        # New kernel = V * ker2
        # V is N × kernel_dim (columns), ker2 is kernel_dim × inner_dim

        # Build V2 = V * ker2^T ... actually ker2 vectors are rows of length kernel_dim
        # We want W[i] = sum_j ker2[j][col] * kernel[col] ...
        # ker2[j] is a vector of length kernel_dim
        # new_kernel[j][i] = sum_c ker2[j][c] * kernel[c][i]
        new_kernel = []
        for vec in ker2:
            new_vec = [0] * N
            for c in range(len(kernel)):
                if vec[c] == 0: continue
                for i in range(N):
                    new_vec[i] ^= gf_mul(vec[c], kernel[c][i])
            new_kernel.append(new_vec)

        print(f"  New kernel dimension: {len(new_kernel)}")

        # Rebuild V and GV
        kernel = new_kernel
        V = [[kernel[j][i] for j in range(len(kernel))] for i in range(N)]
        GV = mat_mul_gf(Gpub, V)

        # Re-check Frobenius
        GV_frob = [[gf_square(x) for x in row] for row in GV]
        diff_check2 = []
        for i in range(K-1):
            diff_check2.append([GV_frob[i][j] ^ GV[i+1][j] for j in range(len(GV[0]))])
        _, _, rank_diff2 = mat_rref([r[:] for r in diff_check2])
        print(f"  New Frob diff rank: {rank_diff2}")

        if rank_diff2 == 0:
            print("[+] Cleaned! GV is now a pure Moore matrix.")
            rank_diff = 0
        else:
            print(f"[!] Still rank {rank_diff2}, iterating...")
            # Iterate cleaning
            for iteration in range(5):
                ker_inner = right_kernel(diff_check2)
                if len(ker_inner) < K:
                    print(f"  Iteration {iteration}: inner kernel too small ({len(ker_inner)})")
                    break
                new_kernel2 = []
                for vec in ker_inner:
                    new_vec = [0] * N
                    for c in range(len(kernel)):
                        if vec[c] == 0: continue
                        for i in range(N):
                            new_vec[i] ^= gf_mul(vec[c], kernel[c][i])
                    new_kernel2.append(new_vec)
                kernel = new_kernel2
                V = [[kernel[j][i] for j in range(len(kernel))] for i in range(N)]
                GV = mat_mul_gf(Gpub, V)
                GV_frob = [[gf_square(x) for x in row] for row in GV]
                diff_check2 = [[GV_frob[i][j] ^ GV[i+1][j] for j in range(len(GV[0]))] for i in range(K-1)]
                _, _, rank_diff2 = mat_rref([r[:] for r in diff_check2])
                print(f"  Iteration {iteration}: kernel dim={len(kernel)}, Frob rank={rank_diff2}")
                if rank_diff2 == 0:
                    rank_diff = 0
                    break
else:
    print(f"[!] Distortion rank {rank_diff} leaked into GV")

# ---- Decoding: recover message from y ----
# y = msg * Gpub + e where rank(e) = t = 8
# y * V = msg * Gpub * V + e * V = msg * GV + e * V
# GV is (essentially) a Gabidulin code of dimension K with minimum rank distance n-k+1
# e*V has rank ≤ t = 8 = T
# Since GV is a [kernel_dim, K, kernel_dim-K+1] Gabidulin code and T = 8 = (N_SECRET-K)/2
# we can decode!

# First compute y * V
yV = [0] * len(kernel)
for j in range(len(kernel)):
    acc = 0
    for i in range(N):
        if y[i] and kernel[j][i]:
            acc ^= gf_mul(y[i], kernel[j][i])
    yV[j] = acc

print(f"\n[*] yV computed ({len(yV)} elements)")

# Now we need to decode yV using the Gabidulin code GV.
# GV is a Moore matrix (up to column permutation).
# For Gabidulin decoding, we need the support (the g_i values).
#
# From GV: row 0 = [alpha_1, ..., alpha_dim] where alpha_j = g_j (some basis)
# row 1 = [alpha_1^2, ..., alpha_dim^2] (Frobenius)
# etc.
#
# If the Frobenius difference is 0, then GV IS a Moore matrix.
# The support is just GV[0].

if rank_diff == 0:
    # GV is a perfect Moore matrix
    support = GV[0][:]
    n_code = len(support)
    print(f"[+] Support extracted from GV[0], {n_code} elements")

    # Verify Moore structure
    for i in range(1, min(3, K)):
        expected = [gf_frob(x, i) for x in support]
        actual = GV[i]
        if expected == actual:
            print(f"  Row {i}: Moore structure verified")
        else:
            match = sum(1 for a, b in zip(expected, actual) if a == b)
            print(f"  Row {i}: {match}/{n_code} match")
else:
    print(f"[-] Could not clean GV to pure Moore matrix (rank_diff={rank_diff})")
    print("    Need alternative decoding approach")
    import sys; sys.exit(1)

# ---- Gabidulin decoding (Welch-Berlekamp style) ----
# Received word: yV = c + e' where c is a codeword, rank(e') ≤ t
# Support: g = support (from GV[0])
# Code: [n', k'] Gabidulin code with n'=len(support), k'=K
# t' = (n'-k')/2 error correction capacity

n_code = len(support)
k_code = K
t_code = (n_code - k_code) // 2

print(f"\n[*] Gabidulin decoding: [{n_code}, {k_code}] code, t={t_code}")

# Gabidulin decoding using the "key equation" approach
# We solve for Lambda (linearized polynomial of q-degree ≤ t) and
# Omega (linearized polynomial of q-degree < t+k) such that:
# Lambda ∘ S = Omega
# where S is the "syndrome" polynomial.

# First compute syndromes
# Syndrome S_i = sum_j yV[j] * g_j^{[i]} for i = k..n-1
# where g_j^{[i]} means Frob^i(g_j)

# Actually for Gabidulin decoding, we use a different approach.
# Let me use the "right Euclidean algorithm" for linearized polynomials.

# A linearized polynomial over GF(2^m) is: L(x) = sum_i a_i * x^{2^i}
# "Composition" of linearized polynomials corresponds to polynomial multiplication
# in the skew ring.

# For decoding, we need the syndrome:
# S(x) = sum_{j=0}^{n-1} yV[j] * (x evaluated at support[j]) ...
# Actually, let me use the matrix approach directly.

# The syndrome is computed from the parity check matrix.
# H is (n-k) × n matrix: H[i][j] = support[j]^{2^(k+i)} for i=0..n-k-1
# Syndrome s = H * yV^T (column vector)

print("[*] Computing syndromes...")
syndromes = []
for i in range(n_code - k_code):
    s = 0
    for j in range(n_code):
        h_ij = gf_frob(support[j], k_code + i)
        if yV[j] and h_ij:
            s ^= gf_mul(yV[j], h_ij)
    syndromes.append(s)

print(f"  Syndromes: {len(syndromes)} values")
print(f"  Nonzero syndromes: {sum(1 for s in syndromes if s != 0)}")

if all(s == 0 for s in syndromes):
    print("[+] Zero syndrome — yV is already a codeword!")
    # Decode directly: find msg such that msg * GV = yV
    # Solve the linear system GV * msg^T = yV^T ... but GV is K×n_code
    # We need msg (length K) such that sum_i msg[i] * GV[i][j] = yV[j]

    # Build system: K unknowns, n_code equations
    # Use first K equations (if GV has full rank K)
    aug = [GV[i][:K] + [0]*K for i in range(K)]
    # Wait, need to solve msg * GV = yV
    # That is: for each j: sum_i msg[i] * GV[i][j] = yV[j]
    # Matrix form: msg^T (K×1) satisfies GV^T * msg^T ... no.
    # GV is K×n_code. msg is 1×K. msg * GV is 1×n_code.
    # So transpose: GV^T * msg^T = yV^T
    # GV^T is n_code × K, msg^T is K×1, yV^T is n_code×1

    GVT_aug = [[GV[i][j] for i in range(K)] + [yV[j]] for j in range(n_code)]
    rref_result, pivots, rank_sys = mat_rref(GVT_aug)
    print(f"  System rank: {rank_sys}")

    if rank_sys == K:
        msg = [0] * K
        for idx, pc in enumerate(pivots):
            if pc < K:
                msg[pc] = rref_result[idx][K]

        # Verify
        check = [0] * n_code
        for i in range(K):
            if msg[i] == 0: continue
            for j in range(n_code):
                check[j] ^= gf_mul(msg[i], GV[i][j])

        if check == yV:
            print("[+] Message recovered from projected system!")
        else:
            diff = sum(1 for a, b in zip(check, yV) if a != b)
            print(f"[-] Verification failed: {diff}/{n_code} differ")

    # But this msg is in the projected space. We need the ORIGINAL msg
    # that was used with Gpub.
    # y = msg_orig * Gpub + e
    # yV = msg_orig * Gpub * V + eV = msg_orig * GV + eV
    # If syndrome is 0, then eV = 0 (error in kernel of V^T... unlikely)
    # OR our decoding absorbed the error.
    # Either way, msg found above satisfies msg * GV = yV
    # and msg_orig * GV = yV - eV
    # If eV has rank ≤ t and we decoded, msg should be msg_orig.

else:
    print("[*] Nonzero syndrome — Gabidulin decoding via linearized polynomials")

    # Gabidulin decoding: the error e has rank t over GF(2).
    # The error locator is a linearized polynomial Lambda(x) = sum_{j=0}^{t} lam_j * x^{[j]}
    # whose KERNEL (as a GF(2)-linear map on GF(2^m)) is the error space V_e.
    #
    # Key equation (Gabidulin's version):
    # sum_{j=0}^{t} lam_j * S_{i+j}^{[j]} = 0  for i = 0, ..., t-1
    # where S_i = syndromes[i] and S^{[j]} = Frob^j(S) = S^{2^j}
    #
    # Set lam_t = 1, solve for lam_0, ..., lam_{t-1}

    # Try to determine actual error rank by trying t_dec = 1, 2, ..., t_code
    # until the key equation has a consistent solution with correct kernel dim

    found_t = None
    for t_try in range(1, t_code + 1):
        A_sys = [[0]*t_try for _ in range(t_try)]
        b_sys = [0]*t_try
        for i in range(t_try):
            for j in range(t_try):
                A_sys[i][j] = gf_frob(syndromes[i + j], j)
            b_sys[i] = gf_frob(syndromes[i + t_try], t_try)

        aug_t = [A_sys[i] + [b_sys[i]] for i in range(t_try)]
        _, _, rank_t = mat_rref([r[:] for r in aug_t])

        if rank_t == t_try:
            # Solve and check kernel dimension
            rref_t, pivots_t, _ = mat_rref(aug_t)
            lam_test = [0] * t_try
            for idx, pc in enumerate(pivots_t):
                if pc < t_try:
                    lam_test[pc] = rref_t[idx][t_try]
            lam_test.append(1)

            def eval_lam_test(x):
                val = 0
                for jj in range(len(lam_test)):
                    val ^= gf_mul(lam_test[jj], gf_frob(x, jj))
                return val

            # Check kernel dimension
            M_rows = [eval_lam_test(1 << j) for j in range(64)]
            aug_k = [(M_rows[j] << 64) | (1 << j) for j in range(64)]
            piv_k = {}
            for j in range(64):
                x = aug_k[j] >> 64
                while x:
                    col = x.bit_length() - 1
                    if col in piv_k:
                        aug_k[j] ^= piv_k[col]
                        x = aug_k[j] >> 64
                    else:
                        piv_k[col] = aug_k[j]
                        break
            kdim = sum(1 for j in range(64) if (aug_k[j] >> 64) == 0 and (aug_k[j] & MASK64) != 0)
            print(f"  t={t_try}: key eq rank={rank_t}, kernel dim={kdim}")

            if kdim == t_try:
                found_t = t_try
                lam = lam_test
                break

    if found_t is None:
        # Try the "right" key equation formulation
        # Alternative: S_{i}^{[j]} instead of S_{i+j}^{[j]}
        print("[*] Trying alternative key equation formulation...")
        for t_try in range(1, t_code + 1):
            # Alternative formulation: sum_{j=0}^{t-1} lam_j * S_{i}^{[j]} = S_{i}^{[t]}
            # for i = 0..t-1
            # This is: lam_j * S_i^{2^j} = S_i^{2^t}
            A_sys = [[0]*t_try for _ in range(t_try)]
            b_sys = [0]*t_try
            for i in range(t_try):
                for j in range(t_try):
                    A_sys[i][j] = gf_frob(syndromes[i], j)
                b_sys[i] = gf_frob(syndromes[i], t_try)

            aug_t = [A_sys[i] + [b_sys[i]] for i in range(t_try)]
            _, _, rank_t = mat_rref([r[:] for r in aug_t])

            if rank_t == t_try:
                rref_t, pivots_t, _ = mat_rref(aug_t)
                lam_test = [0] * t_try
                for idx, pc in enumerate(pivots_t):
                    if pc < t_try:
                        lam_test[pc] = rref_t[idx][t_try]
                lam_test.append(1)

                def eval_lam_test2(x):
                    val = 0
                    for jj in range(len(lam_test)):
                        val ^= gf_mul(lam_test[jj], gf_frob(x, jj))
                    return val

                M_rows = [eval_lam_test2(1 << j) for j in range(64)]
                aug_k = [(M_rows[j] << 64) | (1 << j) for j in range(64)]
                piv_k = {}
                for j in range(64):
                    x = aug_k[j] >> 64
                    while x:
                        col = x.bit_length() - 1
                        if col in piv_k:
                            aug_k[j] ^= piv_k[col]
                            x = aug_k[j] >> 64
                        else:
                            piv_k[col] = aug_k[j]
                            break
                kdim = sum(1 for j in range(64) if (aug_k[j] >> 64) == 0 and (aug_k[j] & MASK64) != 0)
                print(f"  Alt t={t_try}: key eq rank={rank_t}, kernel dim={kdim}")

                if kdim == t_try:
                    found_t = t_try
                    lam = lam_test
                    eval_lambda = eval_lam_test2
                    break

    if found_t is None:
        print("[-] Could not find valid error locator")
        # Fallback: try yet another formulation
        # Gabidulin's original: sum_{j=0}^{t} lam_j * S_{i+j} = 0 where S is the "linearized syndrome"
        # Let's try the syndrome-based Berlekamp-Massey for linearized polynomials
        # Different convention: the key equation might use column syndromes differently

        # Let me try swapping the Frobenius application:
        # sum_{j=0}^{t-1} lam_j^{[i]} * S_{i+j} = S_{i+t} for i=0..t-1
        print("[*] Trying Frobenius-on-lam formulation...")
        for t_try in range(1, t_code + 1):
            A_sys = [[0]*t_try for _ in range(t_try)]
            b_sys = [0]*t_try
            for i in range(t_try):
                for j in range(t_try):
                    # lam_j^{[i]} * S_{i+j} => coefficient of lam_j is S_{i+j} but lam_j appears as lam_j^{[i]}
                    # This is nonlinear in lam_j... skip
                    pass

            # Actually let me just try the standard Gabidulin decoding
            # using the "modified syndrome" approach:
            # Build Toeplitz-like matrix from syndromes
            A_sys = [[syndromes[i+j] for j in range(t_try)] for i in range(t_try)]
            b_sys = [syndromes[i + t_try] for i in range(t_try)]

            aug_t = [A_sys[i] + [b_sys[i]] for i in range(t_try)]
            _, _, rank_t = mat_rref([r[:] for r in aug_t])

            if rank_t == t_try:
                rref_t, pivots_t, _ = mat_rref(aug_t)
                sigma = [0] * t_try
                for idx, pc in enumerate(pivots_t):
                    if pc < t_try:
                        sigma[pc] = rref_t[idx][t_try]
                sigma.append(1)

                # Evaluate: Sigma(x) = sum sigma_j * x^{[j]}
                def eval_sigma(x):
                    val = 0
                    for jj in range(len(sigma)):
                        val ^= gf_mul(sigma[jj], gf_frob(x, jj))
                    return val

                M_rows = [eval_sigma(1 << j) for j in range(64)]
                aug_k = [(M_rows[j] << 64) | (1 << j) for j in range(64)]
                piv_k = {}
                for j in range(64):
                    x = aug_k[j] >> 64
                    while x:
                        col = x.bit_length() - 1
                        if col in piv_k:
                            aug_k[j] ^= piv_k[col]
                            x = aug_k[j] >> 64
                        else:
                            piv_k[col] = aug_k[j]
                            break
                kdim = sum(1 for j in range(64) if (aug_k[j] >> 64) == 0 and (aug_k[j] & MASK64) != 0)
                print(f"  Toeplitz t={t_try}: key eq rank={rank_t}, kernel dim={kdim}")

                if kdim == t_try:
                    found_t = t_try
                    lam = sigma
                    eval_lambda = eval_sigma
                    break

    t_dec = found_t if found_t else t_code
    print(f"  Using t={t_dec}")

    # Rebuild final Lambda from the winning formulation
    if found_t:
        def eval_lambda(x):
            val = 0
            for jj in range(len(lam)):
                val ^= gf_mul(lam[jj], gf_frob(x, jj))
            return val

    # lam is already set from the search loop above
    print("[*] Finding error space (kernel of Lambda)...")

    def eval_lambda(x):
        val = 0
        for j in range(len(lam)):
            val ^= gf_mul(lam[j], gf_frob(x, j))
        return val

    # Find kernel of Lambda as GF(2)-linear map on GF(2^64)
    M_lambda_rows = [eval_lambda(1 << j) for j in range(64)]
    aug_rows = [(M_lambda_rows[j] << 64) | (1 << j) for j in range(64)]
    piv_lk = {}
    for j in range(64):
        x = aug_rows[j] >> 64
        while x:
            col = x.bit_length() - 1
            if col in piv_lk:
                aug_rows[j] ^= piv_lk[col]
                x = aug_rows[j] >> 64
            else:
                piv_lk[col] = aug_rows[j]
                break
    error_basis = [aug_rows[j] & MASK64 for j in range(64) if (aug_rows[j] >> 64) == 0 and (aug_rows[j] & MASK64) != 0]
    print(f"  Lambda kernel dimension: {len(error_basis)} (over GF(2), expected {t_dec})")

    # Now we have the error space V_e = span(error_basis) over GF(2).
    # Each error coordinate e_j ∈ V_e.
    # e_j = sum_{l=0}^{t-1} c_{j,l} * error_basis[l] where c_{j,l} ∈ GF(2)
    #
    # Substitute into syndrome equations:
    # S_i = sum_{j=0}^{n-1} e_j * support[j]^{[k+i]}
    #      = sum_{j} sum_{l} c_{j,l} * error_basis[l] * support[j]^{[k+i]}
    #      = sum_{l} error_basis[l] * (sum_{j} c_{j,l} * support[j]^{[k+i]})
    #
    # Define phi_l^{(i)} = sum_{j} c_{j,l} * support[j]^{[k+i]}
    # Then S_i = sum_{l} error_basis[l] * phi_l^{(i)}
    #
    # This is a system over GF(2^m) but c_{j,l} ∈ GF(2).
    # Actually, let's use a different approach.
    #
    # Alternative: compute the error evaluator polynomial and get errors directly.
    # Using the Welch-Berlekamp / Gao approach for Gabidulin codes.
    #
    # Or simpler: use the fact that we know Lambda.
    # Apply Lambda to each coordinate of yV:
    # Lambda(yV_j) = Lambda(c_j + e_j) = Lambda(c_j) + Lambda(e_j) = Lambda(c_j) + 0
    # since e_j ∈ ker(Lambda).
    # So Lambda(yV_j) = Lambda(c_j) where c = msg * GV is the codeword.
    #
    # c_j = sum_{i=0}^{k-1} msg_i * support[j]^{[i]}
    # Lambda(c_j) = sum_{i} msg_i * Lambda(support[j]^{[i]})
    #             = sum_{i} msg_i * sum_{l} lam_l * (support[j]^{[i]})^{[l]}
    #             = sum_{i} msg_i * sum_{l} lam_l * support[j]^{[i+l]}
    #
    # This is a codeword of a DIFFERENT Gabidulin code!
    # Define new_support[j] = support[j] (same)
    # The "Lambda-image code" has generator:
    # G'[i][j] = Lambda(support[j]^{[i]}) = sum_l lam_l * support[j]^{[i+l]}
    #
    # So Lambda(yV) is a codeword of this new code, and we can directly decode.

    print("[*] Applying Lambda to received word...")
    yV_lambda = [eval_lambda(yV[j]) for j in range(n_code)]

    # Build the Lambda-image generator matrix G'
    # G'[i][j] = sum_{l=0}^{t} lam_l * support[j]^{[i+l]}
    Gprime = [[0]*n_code for _ in range(k_code)]
    for i in range(k_code):
        for j in range(n_code):
            val = 0
            for l in range(len(lam)):
                val ^= gf_mul(lam[l], gf_frob(support[j], i + l))
            Gprime[i][j] = val

    print(f"  G' is {k_code}x{n_code}")

    # yV_lambda = msg * G' (exactly, no error!)
    # Solve: G'^T * msg^T = yV_lambda^T
    GpT_aug = [[Gprime[i][j] for i in range(k_code)] + [yV_lambda[j]] for j in range(n_code)]
    rref_result, pivots, rank_sys = mat_rref(GpT_aug)
    print(f"  System rank: {rank_sys}/{k_code}")

    msg = [0] * k_code
    for idx, pc in enumerate(pivots):
        if pc < k_code:
            msg[pc] = rref_result[idx][k_code]

    # Verify
    check = [0] * n_code
    for i in range(k_code):
        if msg[i] == 0: continue
        for j in range(n_code):
            check[j] ^= gf_mul(msg[i], Gprime[i][j])

    if check == yV_lambda:
        print("[+] Message recovered via Lambda-image decoding!")
    else:
        diff = sum(1 for a, b in zip(check, yV_lambda) if a != b)
        print(f"[-] Verification failed: {diff}/{n_code} differ")
        # Reduce t and retry

# ---- Reconstruct original message and decrypt ----
# msg was used as: key = SHA256(serialize(msg)), where serialize = 8-byte LE per element
# But msg here is in the projected space through V.
# Actually, the message vector msg is the SAME — it multiplies Gpub directly.
# y = msg * Gpub + e
# yV = msg * (Gpub * V) + eV = msg * GV + eV
# So the msg we recover from the projected system IS the original msg!

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
    print("[*] Trying to debug...")
    print(f"  msg[:5] = {[hex(x) for x in msg[:5]]}")
    print(f"  key = {key.hex()}")
