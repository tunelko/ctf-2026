#!/usr/bin/env python3
"""
PQChat solver v3 - Exploit spectral support structure

Key insight: h, g are publicly derivable. The 21 secrets are:
  s0, h*s0, g*s0, h²*s0, hg*s0, g²*s0, h²g*s0,
  t0, h*t0, g*t0,
  t1, h*t1, g*t1,
  t2, h*t2, g*t2, hg*t2,
  t3, h*t3, g*t3, g²*t3

In NTT domain, at each slot r:
  S_j[r] depends on s0_hat[r], t0_hat[r], t1_hat[r], t2_hat[r], t3_hat[r]
  multiplied by known powers of h_hat[r], g_hat[r].

But the spectra have disjoint support:
- band0 (80 slots): only t0_hat is nonzero
- band1 (80 slots): only t1_hat is nonzero
- band2 (96 slots): only t2_hat is nonzero
- band3 (96 slots): only t3_hat is nonzero
- live  (160 slots): only s0_hat is nonzero

So at each slot, there's exactly 1 unknown and 48 equations.
We solve each, then invert NTT to get s0.
"""

from pwn import *
import json
import numpy as np
import hashlib
import struct
import os
from Crypto.Cipher import AES

# ==== Parameters ====
N = 512
Q = 12289
K = 21
ETA_S = 7
ETA_E = 2
MAX_SAMPLES = 48
POLY_BITS = 14
POLY_BYTES = (N * POLY_BITS + 7) // 8

MAIN_SLOTS = 160
AUX_BAND_SLOTS = (80, 80, 96, 96)

LAYOUT_SEED = b"pqchat.layout.v7.reduction-chain"
MASK_H_SEED = b"pqchat.mask-h.v7.reduction-chain"
MASK_G_SEED = b"pqchat.mask-g.v7.reduction-chain"

MAIN_VALUE_TABLE = (-5, -4, -3, -2, -1, 0, 0, 1, 2, 3, 4, 5)
AUX_VALUE_TABLES = (
    (-6, -5, -3, -2, -1, 0, 1, 2, 3, 5, 6),
    (-6, -4, -3, -1, 0, 1, 3, 4, 6),
    (-7, -5, -3, -2, -1, 0, 1, 2, 3, 5, 7),
    (-6, -5, -4, -2, -1, 0, 1, 2, 4, 5, 6),
)
ERROR_VALUE_TABLE = (-2, -1, 0, 0, 1, 2)

# ==== Field arithmetic ====
def modinv(a, q=Q):
    return pow(a % q, q - 2, q)

# ==== Poly packing ====
def unpack_poly(hex_str):
    data = bytes.fromhex(hex_str)
    bits = int.from_bytes(data, 'little')
    return np.array([(bits >> (i * POLY_BITS)) & ((1 << POLY_BITS) - 1) for i in range(N)], dtype=np.int64) % Q

# ==== Negacyclic NTT (server-compatible) ====
def _prime_factors(m):
    if m <= 1: return ()
    n, out, d = m, [], 2
    while d * d <= n:
        if n % d == 0:
            out.append(d)
            while n % d == 0: n //= d
        d += 1
    if n > 1: out.append(n)
    return tuple(out)

def primitive_root(q):
    factors = _prime_factors(q - 1)
    for g in range(2, q):
        if all(pow(g, (q - 1) // p, q) != 1 for p in factors):
            return g

def negacyclic_roots(n, q):
    g = primitive_root(q)
    zeta = pow(g, (q - 1) // (2 * n), q)
    assert pow(zeta, n, q) == q - 1
    return [pow(zeta, 2 * j + 1, q) for j in range(n)]

# Build forward NTT matrix (or just evaluate pointwise)
print("[*] Precomputing NTT roots...")
ROOTS = negacyclic_roots(N, Q)
INV_ROOTS = [modinv(r) for r in ROOTS]
INV_N = modinv(N)

def spec_forward(poly):
    """NTT: evaluate poly at each root"""
    p = np.array(poly, dtype=np.int64)
    result = []
    for r in ROOTS:
        # Horner's method
        val = 0
        rj = 1
        for j in range(N):
            val = (val + int(p[j]) * rj) % Q
            rj = (rj * r) % Q
        result.append(val)
    return result

def spec_inverse(spec):
    """Inverse NTT"""
    s = np.array(spec, dtype=np.int64)
    result = []
    for j in range(N):
        val = 0
        for i in range(N):
            rij = pow(INV_ROOTS[i], j, Q)
            val = (val + int(s[i]) * rij) % Q
        result.append(int(val * INV_N % Q))
    return result

# ==== Layout / mask expansion (from server) ====
def _rank_indices(seed, tag, n):
    scored = []
    for i in range(n):
        digest = hashlib.sha256(seed + tag + i.to_bytes(4, "little")).digest()
        scored.append((digest, i))
    scored.sort()
    return [i for _, i in scored]

def _band_layout(seed, n):
    order = _rank_indices(seed, b"/band-layout", n)
    n0, n1, n2, n3 = AUX_BAND_SLOTS
    band0 = order[:n0]
    band1 = order[n0:n0+n1]
    band2 = order[n0+n1:n0+n1+n2]
    band3 = order[n0+n1+n2:n0+n1+n2+n3]
    live = order[n0+n1+n2+n3:]
    assert len(live) == MAIN_SLOTS
    return band0, band1, band2, band3, live

def _shake_bytes(seed, out_len):
    return hashlib.shake_256(seed).digest(out_len)

def _pick_value(seed, tag, idx, q, accept):
    counter = 0
    while True:
        digest = hashlib.sha256(seed + tag + idx.to_bytes(4, "little") + counter.to_bytes(2, "little")).digest()
        v = (int.from_bytes(digest[:2], "little") % (q - 1)) + 1
        if accept(v):
            return v
        counter += 1

def _special_constants(q):
    g = primitive_root(q)
    root_minus_one = pow(g, (q - 1) // 4, q)
    assert (root_minus_one * root_minus_one) % q == (q - 1) % q
    sigma_root = pow(g, (q - 1) // 8, q)
    sigma = (sigma_root * sigma_root) % q
    tau = pow(g, 73, q)
    return g, root_minus_one, sigma_root, sigma, tau

def _is_band0(u, v, q, sigma, tau): return (u * u + 1) % q == 0
def _is_band1(u, v, q, sigma, tau): return (v * v - sigma) % q == 0
def _is_band2(u, v, q, sigma, tau): return v % q == (u * u) % q
def _is_band3(u, v, q, sigma, tau): return (u * v - tau) % q == 0

def classify_slot(u, v, q):
    _, _, _, sigma, tau = _special_constants(q)
    if _is_band0(u, v, q, sigma, tau): return 0
    if _is_band1(u, v, q, sigma, tau): return 1
    if _is_band2(u, v, q, sigma, tau): return 2
    if _is_band3(u, v, q, sigma, tau): return 3
    return 4

def expand_mask_spectra():
    """Returns h_hat, g_hat in NTT domain"""
    band0, band1, band2, band3, live = _band_layout(LAYOUT_SEED, N)
    _, root_minus_one, sigma_root, sigma, tau = _special_constants(Q)
    q = Q

    h_hat = [0] * N
    g_hat = [0] * N

    for idx in band0:
        bit = hashlib.sha256(MASK_H_SEED + b"/band0/u" + idx.to_bytes(4, "little")).digest()[0] & 1
        u = root_minus_one if bit == 0 else (-root_minus_one) % q
        v = _pick_value(MASK_G_SEED, b"/band0/v", idx, q,
            lambda x, uu=u: not _is_band1(uu, x, q, sigma, tau) and not _is_band2(uu, x, q, sigma, tau) and not _is_band3(uu, x, q, sigma, tau))
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in band1:
        bit = hashlib.sha256(MASK_G_SEED + b"/band1/v" + idx.to_bytes(4, "little")).digest()[0] & 1
        v = sigma_root if bit == 0 else (-sigma_root) % q
        u = _pick_value(MASK_H_SEED, b"/band1/u", idx, q,
            lambda x, vv=v: not _is_band0(x, vv, q, sigma, tau) and not _is_band2(x, vv, q, sigma, tau) and not _is_band3(x, vv, q, sigma, tau))
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in band2:
        u = _pick_value(MASK_H_SEED, b"/band2/u", idx, q,
            lambda x: x != 0 and (x*x+1) % q != 0 and ((x*x) % q) != sigma_root and ((x*x) % q) != (-sigma_root) % q and (x * ((x*x) % q) - tau) % q != 0)
        v = (u * u) % q
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in band3:
        def _accept_band3(x):
            if x == 0 or (x*x+1) % q == 0: return False
            vv = (tau * pow(x, -1, q)) % q
            if _is_band1(x, vv, q, sigma, tau): return False
            if _is_band2(x, vv, q, sigma, tau): return False
            return True
        u = _pick_value(MASK_H_SEED, b"/band3/u", idx, q, _accept_band3)
        v = (tau * pow(u, -1, q)) % q
        h_hat[idx] = u
        g_hat[idx] = v

    for idx in live:
        counter = 0
        while True:
            du = hashlib.sha256(MASK_H_SEED + b"/live/u" + idx.to_bytes(4, "little") + counter.to_bytes(2, "little")).digest()
            dv = hashlib.sha256(MASK_G_SEED + b"/live/v" + idx.to_bytes(4, "little") + counter.to_bytes(2, "little")).digest()
            u = (int.from_bytes(du[:2], "little") % (q - 1)) + 1
            v = (int.from_bytes(dv[:2], "little") % (q - 1)) + 1
            if classify_slot(u, v, q) == 4:
                h_hat[idx] = u
                g_hat[idx] = v
                break
            counter += 1

    return h_hat, g_hat

# ==== Coefficient formulas (from server) ====
# In NTT domain, S_j[r] = f_j(h_hat[r], g_hat[r]) * base_hat[r]
# where base is s0 for main, t_i for blind_i

def main_coefficients(u, v, q):
    """Returns coefficients for [a0..a6] in the equation for main secret contribution.
    main_secret_coeff = a0*1 + a1*u + a2*v + a3*u² + a4*uv + a5*v² + a6*u²v
    In NTT domain: s[0..6][r] = [1, h_hat[r], g_hat[r], h_hat[r]², h_hat[r]*g_hat[r], g_hat[r]², h_hat[r]²*g_hat[r]] * s0_hat[r]
    So the coefficient of s0_hat[r] in sample equation is:
    sum_j a_j[r] * multiplier_j[r]
    where multiplier_j for j=0..6 are 1, u, v, u², uv, v², u²v
    """
    u2 = (u * u) % q
    v2 = (v * v) % q
    uv = (u * v) % q
    u2v = (u2 * v) % q
    return [1, u, v, u2, uv, v2, u2v]

def blind0_coefficients(u, v, q):
    """blind0_coeff = a7*1 + a8*u + a9*v => multipliers for t0_hat"""
    return [1, u, v]

def blind1_coefficients(u, v, q):
    """blind1_coeff = a10*1 + a11*u + a12*v"""
    return [1, u, v]

def blind2_coefficients(u, v, q):
    """blind2_coeff = a13*1 + a14*u + a15*v + a16*uv"""
    uv = (u * v) % q
    return [1, u, v, uv]

def blind3_coefficients(u, v, q):
    """blind3_coeff = a17*1 + a18*u + a19*v + a20*v²"""
    v2 = (v * v) % q
    return [1, u, v, v2]


def main():
    # Step 1: Expand public masks
    print("[*] Expanding mask spectra...")
    h_hat, g_hat = expand_mask_spectra()

    # Step 2: Compute band layout
    band0, band1, band2, band3, live = _band_layout(LAYOUT_SEED, N)

    # Create slot -> (band_type, position_in_band) mapping
    slot_type = {}  # slot -> band number (0-3 for aux, 4 for live/main)
    for idx in band0: slot_type[idx] = 0
    for idx in band1: slot_type[idx] = 1
    for idx in band2: slot_type[idx] = 2
    for idx in band3: slot_type[idx] = 3
    for idx in live: slot_type[idx] = 4

    print(f"  Band sizes: band0={len(band0)}, band1={len(band1)}, band2={len(band2)}, band3={len(band3)}, live={len(live)}")

    # Step 3: Connect to server
    HOST = os.environ.get('HOST', 'dyn-01.midnightflag.fr')
    PORT = int(os.environ.get('PORT', '10220'))
    print(f"[*] Connecting to {HOST}:{PORT}...")
    r = remote(HOST, PORT)
    r.recvuntil(b'> ')

    # Get encrypted flag
    r.sendline(b'3')
    data = r.recvuntil(b'> ')
    flag_data = json.loads(data.decode().strip().split('\n')[0])
    print(f"[+] Got encrypted flag")

    # Collect samples
    print("[*] Collecting samples...")
    samples = []
    for i in range(MAX_SAMPLES):
        r.sendline(b'2')
        data = r.recvuntil(b'> ')
        hs = json.loads(data.decode().strip().split('\n')[0])
        a_polys = [unpack_poly(h) for h in hs['a_hex']]
        b_poly = unpack_poly(hs['b_hex'])
        samples.append((a_polys, b_poly))
        if (i+1) % 10 == 0:
            print(f"  Collected {i+1}/{MAX_SAMPLES}")

    # Step 4: Compute NTT of all sample polynomials
    print("[*] Computing NTTs of samples...")

    # We need NTT of each a_polys[j] and b_poly for each sample
    # That's 48 * (21 + 1) = 1056 NTTs of size 512
    # Each NTT is O(N²) = 262144 mults... slow in pure Python
    # Let's use numpy matrix multiplication instead

    # Build forward NTT matrix
    print("[*] Building NTT matrix...")
    fwd_matrix = np.zeros((N, N), dtype=np.int64)
    for i in range(N):
        rj = 1
        for j in range(N):
            fwd_matrix[i, j] = rj
            rj = (rj * ROOTS[i]) % Q

    def fast_ntt(poly):
        """NTT using matrix multiply"""
        p = np.array(poly, dtype=np.int64)
        # Need modular matrix multiply - use python for precision
        result = (fwd_matrix @ p) % Q
        return result

    # Actually, numpy int64 can overflow with 512 terms of ~12289²
    # max value per entry: 512 * 12289 * 12289 ≈ 7.7e10 which fits in int64 (max ~9.2e18)
    # So numpy is fine!

    print("[*] NTT-transforming all samples...")
    ntt_samples = []
    for i in range(len(samples)):
        a_polys, b_poly = samples[i]
        ntt_a = [fast_ntt(a) for a in a_polys]
        ntt_b = fast_ntt(b_poly)
        ntt_samples.append((ntt_a, ntt_b))
        if (i+1) % 10 == 0:
            print(f"  NTT'd {i+1}/{len(samples)}")

    # Step 5: At each NTT slot, solve for the single unknown
    print("[*] Solving per-slot equations...")

    # For each slot r, we know:
    # B_i[r] = (sum_j A_i_j[r] * multiplier_j(h_hat[r], g_hat[r])) * base_hat[r] + E_i[r]
    #
    # At a "live" slot r (band type 4):
    #   The only nonzero base is s0_hat[r]
    #   multipliers for j=0..6 are [1, u, v, u², uv, v², u²v] where u=h_hat[r], v=g_hat[r]
    #   multipliers for j=7..20 involve t0..t3 which are 0 at live slots
    #   So: B_i[r] = (sum_{j=0}^{6} A_i_j[r] * mult_j) * s0_hat[r] + E_i[r]
    #   => c_i = sum_{j=0}^{6} A_i_j[r] * mult_j
    #   => B_i[r] = c_i * s0_hat[r] + E_i[r]
    #   Given 48 equations, solve for s0_hat[r]
    #
    # At a band0 slot r:
    #   Only t0_hat[r] is nonzero
    #   multipliers for j=7..9: [1, u, v]
    #   B_i[r] = (A_i_7[r]*1 + A_i_8[r]*u + A_i_9[r]*v) * t0_hat[r] + E_i[r]

    s0_hat = [0] * N
    t0_hat = [0] * N
    t1_hat = [0] * N
    t2_hat = [0] * N
    t3_hat = [0] * N

    solved_count = 0

    for slot_r in range(N):
        u = h_hat[slot_r]
        v = g_hat[slot_r]
        band = slot_type[slot_r]

        # Compute the "effective coefficient" c_i for each sample
        # This is the sum of A_i_j[r] * multiplier_j for the relevant j indices

        if band == 4:  # live slot -> solve for s0_hat[r]
            mults = main_coefficients(u, v, Q)  # length 7
            j_indices = list(range(7))
        elif band == 0:  # band0 -> solve for t0_hat[r]
            mults = blind0_coefficients(u, v, Q)  # length 3
            j_indices = [7, 8, 9]
        elif band == 1:
            mults = blind1_coefficients(u, v, Q)
            j_indices = [10, 11, 12]
        elif band == 2:
            mults = blind2_coefficients(u, v, Q)
            j_indices = [13, 14, 15, 16]
        elif band == 3:
            mults = blind3_coefficients(u, v, Q)
            j_indices = [17, 18, 19, 20]

        # c_i = sum_m A_i_{j_indices[m]}[r] * mults[m]
        c_vals = np.zeros(len(samples), dtype=np.int64)
        b_vals = np.zeros(len(samples), dtype=np.int64)

        for i in range(len(samples)):
            ntt_a, ntt_b = ntt_samples[i]
            c = 0
            for m, j in enumerate(j_indices):
                c = (c + int(ntt_a[j][slot_r]) * mults[m]) % Q
            c_vals[i] = c
            b_vals[i] = int(ntt_b[slot_r])

        # Now: b_vals[i] = c_vals[i] * unknown + e_i[r]  for i=0..47
        # With 48 equations and 1 unknown + noise, use majority vote:
        # For pairs where c_vals[i] != 0:
        #   candidate = b_vals[i] * c_vals[i]^(-1) mod Q
        # The correct answer should appear most frequently (or close to it)

        # Better approach: use two equations to eliminate noise
        # c_i * x + e_i = b_i
        # c_j * x + e_j = b_j
        # => (c_i - c_j) * x = b_i - b_j + (e_j - e_i)
        # e_j - e_i has range [-4, 4] (since each e in [-2,2])
        # If c_i - c_j != 0, we get x = (b_i - b_j) / (c_i - c_j) + small_noise

        # Actually simplest: just solve with the first equation where c != 0
        # Then verify with others
        # Since error e is in NTT domain, it's NOT small...
        # NTT(e)[r] = sum over j of e_j * root^j, each e_j in {-2,-1,0,0,1,2}

        # Hmm, the error is NOT small in NTT domain.
        # But with 48 equations and 1 unknown, we can use least-squares-like approach.

        # Actually: use pairs of equations to cancel noise:
        # c_i * x = b_i - e_i
        # c_j * x = b_j - e_j
        # => (c_i * b_j - c_j * b_i) = c_i * e_j - c_j * e_i
        # This doesn't help directly...

        # Better: with 48 eqns and 1 unknown, take the most consistent value.
        # Compute x_i = b_i / c_i for each i (where c_i != 0)
        # Then look for the value that makes e_i = b_i - c_i * x_i small in NTT domain.
        # But e_i in NTT domain CAN be large (up to ~1024).

        # Wait - actually, in the server code, sample_error generates error in NTT domain
        # with values from ERROR_VALUE_TABLE = (-2, -1, 0, 0, 1, 2).
        # Then it does spec_inverse to get time domain.
        # So e_hat (NTT domain) has entries in {-2, -1, 0, 0, 1, 2}!
        # That means the SPECTRAL error is small!

        # So b_i[r] = c_i[r] * x[r] + e_i_hat[r], where e_i_hat[r] in {-2,-1,0,1,2}
        # This means x_i = (b_i - e_i_hat) / c_i, and e_i_hat is tiny.
        # We can enumerate e_i_hat in {-2,-1,0,1,2} for equation i and check consistency.

        # With c_i != 0: x = (b_i - e) * c_i^(-1) for e in {-2,-1,0,1,2}
        # Use first two equations to find consistent x.

        candidates = {}
        nonzero_indices = [i for i in range(len(samples)) if c_vals[i] % Q != 0]

        if len(nonzero_indices) < 2:
            print(f"  Slot {slot_r}: not enough nonzero coefficients!")
            continue

        # Use first eq to generate 5 candidates, verify against second eq
        i0 = nonzero_indices[0]
        i1 = nonzero_indices[1]
        ci0_inv = modinv(int(c_vals[i0]))

        found = False
        for e0 in [-2, -1, 0, 1, 2]:
            x_cand = ((int(b_vals[i0]) - e0) * ci0_inv) % Q

            # Verify against second equation
            residual1 = (int(b_vals[i1]) - int(c_vals[i1]) * x_cand) % Q
            if residual1 > Q // 2:
                residual1 = residual1 - Q

            if -2 <= residual1 <= 2:
                # Further verify against more equations
                ok = 0
                for idx in nonzero_indices[2:min(10, len(nonzero_indices))]:
                    res = (int(b_vals[idx]) - int(c_vals[idx]) * x_cand) % Q
                    if res > Q // 2: res = res - Q
                    if -2 <= res <= 2:
                        ok += 1

                if ok >= min(5, len(nonzero_indices[2:10])):
                    # Good candidate
                    if band == 4:
                        s0_hat[slot_r] = int(x_cand)
                    elif band == 0:
                        t0_hat[slot_r] = int(x_cand)
                    elif band == 1:
                        t1_hat[slot_r] = int(x_cand)
                    elif band == 2:
                        t2_hat[slot_r] = int(x_cand)
                    elif band == 3:
                        t3_hat[slot_r] = int(x_cand)
                    found = True
                    solved_count += 1
                    break

        if not found:
            # Try harder: brute force all 5 candidates from first eq,
            # score against all equations
            best_x = 0
            best_score = -1
            for e0 in [-2, -1, 0, 1, 2]:
                x_cand = ((int(b_vals[i0]) - e0) * ci0_inv) % Q
                score = 0
                for idx in nonzero_indices[:20]:
                    res = (int(b_vals[idx]) - int(c_vals[idx]) * x_cand) % Q
                    if res > Q // 2: res = res - Q
                    if -2 <= res <= 2:
                        score += 1
                if score > best_score:
                    best_score = score
                    best_x = x_cand

            if best_score >= 10:
                if band == 4:
                    s0_hat[slot_r] = int(best_x)
                elif band == 0:
                    t0_hat[slot_r] = int(best_x)
                elif band == 1:
                    t1_hat[slot_r] = int(best_x)
                elif band == 2:
                    t2_hat[slot_r] = int(best_x)
                elif band == 3:
                    t3_hat[slot_r] = int(best_x)
                found = True
                solved_count += 1
            else:
                print(f"  Slot {slot_r} (band {band}): best score = {best_score}/20")

        if (slot_r + 1) % 100 == 0:
            print(f"  Solved {solved_count}/{slot_r+1} slots")

    print(f"\n[*] Solved {solved_count}/{N} slots")

    # Step 6: Inverse NTT to get s0 in coefficient domain
    print("[*] Inverse NTT to recover s0...")

    # Use matrix inverse NTT
    inv_matrix = np.zeros((N, N), dtype=np.int64)
    for j in range(N):
        for i in range(N):
            inv_matrix[j, i] = pow(INV_ROOTS[i], j, Q)

    s0_array = np.array(s0_hat, dtype=np.int64)
    s0_coeffs = (inv_matrix @ s0_array % Q * INV_N) % Q
    s0_coeffs = [int(x) for x in s0_coeffs]

    # Center representation
    s0_centered = [(x if x <= Q//2 else x - Q) for x in s0_coeffs]
    print(f"  s0 range: [{min(s0_centered)}, {max(s0_centered)}]")
    print(f"  s0[:20] = {s0_centered[:20]}")

    # Step 7: Derive key and decrypt flag
    print("[*] Deriving AES key...")
    key = hashlib.sha256(b''.join(int(c % Q).to_bytes(2, 'little') for c in s0_coeffs)).digest()[:16]

    nonce = bytes.fromhex(flag_data['nonce_hex'])
    ct = bytes.fromhex(flag_data['ct_hex'])
    tag = bytes.fromhex(flag_data['tag_hex'])

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag)
        print(f"\n[+] FLAG: {plaintext.decode()}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        print("[*] Trying to submit to server...")
        r.sendline(b'4')
        resp = r.recvuntil(b'> ')
        r.sendline(json.dumps(s0_coeffs).encode())
        resp = r.recvline(timeout=10)
        print(f"  Server response: {resp.decode()[:500]}")

    r.close()

if __name__ == '__main__':
    main()
