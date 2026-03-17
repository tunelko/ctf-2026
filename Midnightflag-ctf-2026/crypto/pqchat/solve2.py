#!/usr/bin/env python3
"""
PQChat solver v2 - solve full system to discover chain structure
"""

from pwn import *
import json
import numpy as np
import struct
import hashlib
from Crypto.Cipher import AES
import time

N = 512
Q = 12289
K = 21
POLY_BITS = 14
POLY_BYTES = 896

def unpack_poly(hex_str):
    data = bytes.fromhex(hex_str)
    bits = int.from_bytes(data, 'little')
    coeffs = []
    for i in range(N):
        val = (bits >> (i * POLY_BITS)) & ((1 << POLY_BITS) - 1)
        coeffs.append(val % Q)
    return np.array(coeffs, dtype=np.int64)

def pack_poly(coeffs):
    bits = 0
    for i in range(N):
        bits |= (int(coeffs[i]) % Q) << (i * POLY_BITS)
    return bits.to_bytes(POLY_BYTES, 'little').hex()

def poly_mul_mod(a, b, q=Q, n=N):
    """Negacyclic polynomial multiplication"""
    result = np.zeros(n, dtype=np.int64)
    for i in range(n):
        for j in range(n):
            pos = i + j
            if pos < n:
                result[pos] = (result[pos] + a[i] * b[j]) % q
            else:
                result[pos - n] = (result[pos - n] - a[i] * b[j]) % q
    return result

def poly_mul_ntt(a, b, q=Q, n=N):
    """Faster polynomial mult using numpy convolution"""
    c = np.convolve(a.astype(np.int64), b.astype(np.int64))
    result = np.zeros(n, dtype=np.int64)
    for i in range(len(c)):
        idx = i % n
        sign = 1 if (i // n) % 2 == 0 else -1
        result[idx] = (result[idx] + sign * c[i]) % q
    return result

def collect_samples():
    r = remote('dyn-01.midnightflag.fr', 14123)
    r.recvuntil(b'> ')
    
    # Get flag data
    r.sendline(b'3')
    data = r.recvuntil(b'> ')
    flag_data = json.loads(data.decode().strip().split('\n\n')[0])
    
    samples = []
    for i in range(48):
        r.sendline(b'2')
        data = r.recvuntil(b'> ')
        hs = json.loads(data.decode().strip().split('\n\n')[0])
        a_polys = [unpack_poly(h) for h in hs['a_hex']]
        b_poly = unpack_poly(hs['b_hex'])
        samples.append((a_polys, b_poly))
        if (i+1) % 10 == 0:
            print(f"Collected {i+1}/48")
    
    return r, samples, flag_data

def gauss_mod_q(M, b, q=Q):
    """Gaussian elimination mod q, working on columns"""
    n_rows, n_cols = M.shape
    # Work with augmented matrix
    # For memory efficiency, work column by column
    
    aug = np.zeros((n_rows, n_cols + 1), dtype=np.int64)
    aug[:, :n_cols] = M % q
    aug[:, n_cols] = b % q
    
    pivot_row = 0
    pivot_cols = []
    
    for col in range(n_cols):
        if pivot_row >= n_rows:
            break
        
        # Find nonzero in this column from pivot_row down
        found = -1
        for row in range(pivot_row, min(pivot_row + n_rows, n_rows)):
            if aug[row, col] % q != 0:
                found = row
                break
        
        if found == -1:
            continue
        
        # Swap
        if found != pivot_row:
            aug[[pivot_row, found]] = aug[[found, pivot_row]]
        
        # Normalize
        inv = pow(int(aug[pivot_row, col]), q - 2, q)
        aug[pivot_row] = (aug[pivot_row] * inv) % q
        
        # Eliminate
        for row in range(n_rows):
            if row != pivot_row and aug[row, col] % q != 0:
                factor = int(aug[row, col])
                aug[row] = (aug[row] - factor * aug[pivot_row]) % q
        
        pivot_cols.append(col)
        pivot_row += 1
        
        if (col + 1) % 50 == 0:
            print(f"  Col {col+1}/{n_cols}, pivots={pivot_row}")
    
    x = np.zeros(n_cols, dtype=np.int64)
    for i, col in enumerate(pivot_cols):
        x[col] = aug[i, n_cols] % q
    
    return x, len(pivot_cols)

def main():
    print("[*] Collecting samples...")
    r, samples, flag_data = collect_samples()
    print(f"[+] Got {len(samples)} samples")
    
    # First, let me try the "all same" hypothesis: s_j = s_0 for all j
    # b = (sum_j a_j) * s_0 + e
    print("\n[*] Testing hypothesis: s_j = s_0 for all j")
    
    # Build system for s_0: sum up a_j's for each sample
    M_rows = []
    b_rows = []
    
    for i in range(48):
        a_polys, b_poly = samples[i]
        # sum all a_j
        a_sum = np.zeros(N, dtype=np.int64)
        for j in range(K):
            a_sum = (a_sum + a_polys[j]) % Q
        
        # Build negacyclic matrix row-by-row (but just compute the products)
        # Instead of full matrix, just store the polynomial for verification later
        M_rows.append(a_sum)
        b_rows.append(b_poly)
    
    # Build matrix from first sample
    a_sum0 = M_rows[0]
    M0 = np.zeros((N, N), dtype=np.int64)
    for col in range(N):
        for row in range(N):
            idx = row - col
            if idx >= 0:
                M0[row][col] = a_sum0[idx] % Q
            else:
                M0[row][col] = (-a_sum0[N + idx]) % Q
    
    s0_test, pivots = gauss_mod_q(M0, b_rows[0])
    print(f"  Pivots: {pivots}")
    
    if pivots == N:
        # Verify
        pred = poly_mul_ntt(M_rows[1], s0_test)
        err = (b_rows[1] - pred) % Q
        err = np.where(err > Q//2, err - Q, err)
        max_err = np.max(np.abs(err))
        print(f"  Verification error: {max_err}")
        if max_err <= 2:
            print("[+] All-same hypothesis works!")
        else:
            print("[-] All-same hypothesis failed")
    
    # Try hypothesis: s_j = s_0 * x^j mod (x^n+1) (monomial rotation)
    # This means the secret vector has a very specific structure
    # Multiplication by x in Z[x]/(x^n+1): [c0,c1,...,cn-1] -> [-cn-1, c0, c1, ..., cn-2]
    print("\n[*] Testing hypothesis: s_j = x^(j*step) * s_0")
    
    # For this to work, we'd need to know the step.
    # With n=512, k=21, step could be n/k ≈ 24.38... not integer.
    # Maybe step = 1? Or some other value.
    
    # Actually, maybe the chain is completely different.
    # Let me try solving the full system directly.
    # 48 * 512 = 24576 equations, 21 * 512 = 10752 unknowns
    # This is doable but will take time with Python.
    
    # Actually wait - let me try using SageMath or use a faster method.
    # For now, let me try to solve a smaller system first.
    
    # Use 21 samples => 21*512 = 10752 equations = 10752 unknowns (square system)
    print("\n[*] Building full system (21 samples, 10752 unknowns)...")
    
    total_vars = K * N  # 10752
    num_samples_use = 21
    total_eqs = num_samples_use * N  # 10752
    
    # This matrix is 10752 x 10752 - too big for naive Gaussian elimination in Python
    # Let me think of a smarter approach...
    
    # Actually, since Q=12289 is small and prime, we can use the structure.
    # The system is: for each sample i:
    # b_i[t] = sum_{j=0}^{k-1} sum_{m=0}^{n-1} a_i_j[m] * s_j[(t-m) mod n] * sign(t,m)
    # This is structured - each block is a negacyclic matrix.
    
    # Alternative approach: Work in NTT domain
    # In NTT domain, polynomial multiplication becomes pointwise
    # So each "frequency" r gives independent scalar equations:
    # B_i(r) = sum_j A_ij(r) * S_j(r) + E_i(r)
    # where B, A, S, E are NTT transforms
    
    # At each frequency r, we have:
    # 48 equations for K=21 unknowns (S_0(r), ..., S_20(r))
    # This is MASSIVELY overdetermined per frequency!
    # And the error in NTT domain might not be small, but we can use least-squares
    
    print("[*] Trying NTT-domain approach...")
    
    # Compute NTT for all polynomials
    # For Z_q[x]/(x^n+1) with q=12289, n=512:
    # We need a primitive 2n-th root of unity mod q
    # q-1 = 12288 = 2^12 * 3
    # 2n = 1024
    # Need g such that g^1024 ≡ 1 mod q and g^512 ≢ 1 mod q
    
    # Find primitive root mod q
    def find_primitive_root(q):
        for g in range(2, q):
            if pow(g, (q-1)//2, q) != 1 and pow(g, (q-1)//3, q) != 1:
                return g
        return None
    
    g = find_primitive_root(Q)
    print(f"  Primitive root mod {Q}: {g}")
    
    # 2n-th root of unity: w = g^((q-1)/(2n)) mod q
    two_n = 2 * N
    assert (Q - 1) % two_n == 0, f"2n={two_n} doesn't divide q-1={Q-1}"
    w = pow(g, (Q - 1) // two_n, Q)
    print(f"  2n-th root of unity: {w}")
    print(f"  Verify w^(2n) = {pow(w, two_n, Q)}")
    print(f"  Verify w^n = {pow(w, N, Q)}")
    
    # NTT for negacyclic convolution:
    # NTT(a)[i] = sum_{j=0}^{n-1} a[j] * (w^(2i+1))^j
    # This diagonalizes the negacyclic multiplication
    
    # Precompute twiddle factors
    twiddles = np.zeros(N, dtype=np.int64)
    for i in range(N):
        twiddles[i] = pow(w, 2*i + 1, Q)
    
    def ntt(poly):
        """Compute NTT for negacyclic convolution"""
        result = np.zeros(N, dtype=np.int64)
        for i in range(N):
            tw = twiddles[i]
            val = 0
            tw_j = 1
            for j in range(N):
                val = (val + int(poly[j]) * tw_j) % Q
                tw_j = (tw_j * tw) % Q
            result[i] = val
        return result
    
    def intt(ntt_poly):
        """Compute inverse NTT"""
        n_inv = pow(N, Q - 2, Q)
        result = np.zeros(N, dtype=np.int64)
        for i in range(N):
            tw = pow(int(twiddles[i]), Q - 2, Q)  # inverse twiddle
            val = 0
            tw_j = 1
            for j in range(N):
                val = (val + int(ntt_poly[j]) * tw_j) % Q
                tw_j = (tw_j * tw) % Q
            result[i] = (val * n_inv) % Q
        return result
    
    # NTT is too slow with naive O(n^2) for 48*22 = 1056 polynomials
    # Let me use a faster NTT
    
    print("[*] Computing NTTs using fast method...")
    
    # Fast NTT using Cooley-Tukey (radix-2)
    # For negacyclic: multiply by powers of w first, then standard FFT with w^2
    
    def fast_ntt(poly, q=Q):
        """Fast NTT for negacyclic convolution"""
        n = len(poly)
        a = poly.copy().astype(np.int64)
        
        # Pre-multiply by w^i (twiddle for negacyclic)
        wi = 1
        for i in range(n):
            a[i] = (a[i] * wi) % q
            wi = (wi * w) % q
        
        # Standard NTT with root w^2
        w2 = (w * w) % q
        
        # Bit-reverse permutation
        j = 0
        for i in range(n):
            if i < j:
                a[i], a[j] = a[j], a[i]
            m = n >> 1
            while m >= 1 and j >= m:
                j -= m
                m >>= 1
            j += m
        
        # Butterfly
        length = 1
        while length < n:
            wlen = pow(int(w2), n // (2 * length), q)
            i = 0
            while i < n:
                wj = 1
                for jj in range(length):
                    u = a[i + jj]
                    v = (a[i + jj + length] * wj) % q
                    a[i + jj] = (u + v) % q
                    a[i + jj + length] = (u - v) % q
                    wj = (wj * wlen) % q
                i += 2 * length
            length <<= 1
        
        return a % q
    
    def fast_intt(ntt_poly, q=Q):
        """Fast inverse NTT"""
        n = len(ntt_poly)
        a = ntt_poly.copy().astype(np.int64)
        
        # Inverse of w^2
        w2_inv = pow(int(w * w % q), q - 2, q)
        
        # Bit-reverse permutation
        j = 0
        for i in range(n):
            if i < j:
                a[i], a[j] = a[j], a[i]
            m = n >> 1
            while m >= 1 and j >= m:
                j -= m
                m >>= 1
            j += m
        
        # Butterfly (inverse)
        length = 1
        while length < n:
            wlen = pow(int(w2_inv), n // (2 * length), q)
            i = 0
            while i < n:
                wj = 1
                for jj in range(length):
                    u = a[i + jj]
                    v = (a[i + jj + length] * wj) % q
                    a[i + jj] = (u + v) % q
                    a[i + jj + length] = (u - v) % q
                    wj = (wj * wlen) % q
                i += 2 * length
            length <<= 1
        
        # Divide by n
        n_inv = pow(n, q - 2, q)
        a = (a * n_inv) % q
        
        # Post-multiply by w^(-i) (inverse twiddle for negacyclic)
        w_inv = pow(int(w), q - 2, q)
        wi = 1
        for i in range(n):
            a[i] = (a[i] * wi) % q
            wi = (wi * w_inv) % q
        
        return a % q
    
    # Verify NTT correctness
    test_a = np.random.randint(0, Q, N, dtype=np.int64)
    test_b = np.random.randint(0, Q, N, dtype=np.int64)
    
    ntt_a = fast_ntt(test_a)
    ntt_b = fast_ntt(test_b)
    ntt_c = (ntt_a * ntt_b) % Q
    c_recovered = fast_intt(ntt_c)
    c_direct = poly_mul_ntt(test_a, test_b)
    
    diff = (c_recovered - c_direct) % Q
    print(f"  NTT verification: max diff = {np.max(diff)}")
    
    if np.max(diff) != 0:
        print("  NTT INCORRECT, debugging...")
        # Try different w
        # Maybe w should be the n-th root of -1
        # That is, w^n = -1 mod q = q-1
        print(f"  w^n mod q = {pow(int(w), N, Q)}")
        # We need w^n = -1 mod q
        # So w = g^((q-1)/n) won't work directly
        # For negacyclic NTT: w is a 2n-th root of unity, so w^n = -1 ✓
        pass
    
    # Now compute NTTs of all sample polynomials
    print("[*] Computing NTTs of all samples...")
    t0 = time.time()
    
    ntt_samples = []
    for i in range(48):
        a_polys, b_poly = samples[i]
        ntt_a = [fast_ntt(a) for a in a_polys]
        ntt_b = fast_ntt(b_poly)
        ntt_samples.append((ntt_a, ntt_b))
        if (i+1) % 10 == 0:
            print(f"  NTT {i+1}/48 ({time.time()-t0:.1f}s)")
    
    print(f"[*] NTTs computed in {time.time()-t0:.1f}s")
    
    # In NTT domain, for each frequency r (0..N-1):
    # B_i[r] = sum_{j=0}^{K-1} A_ij[r] * S_j[r] + E_i[r]
    # This is a system of 48 equations for K=21 unknowns
    # per frequency point (total N=512 independent systems)
    
    # For each frequency r, solve the 48x21 system mod Q
    # The error E_i[r] in NTT domain is NOT small (it's a linear combination of 
    # the small errors), so we need to handle this carefully.
    
    # But 48 >> 21, so we can try to find a solution that minimizes the error.
    # In exact arithmetic mod Q with no noise, we'd get exact solutions.
    
    # With noise, we can try: solve with 21 equations, verify with the rest.
    # If the noise is small enough in NTT domain, this works.
    
    # Actually, each e_i has coefficients in {-2,-1,0,1,2}
    # NTT(e_i)[r] = sum_j e_i[j] * w^((2r+1)*j)
    # This is a sum of 512 terms, each bounded by 2
    # So |NTT(e_i)[r]| could be up to 1024 in absolute value (mod Q)
    # That's significant compared to Q=12289 but still less than Q
    
    # Strategy: For each frequency r, solve with 21 equations to get S[r]
    # Then check residuals against the remaining 27 equations
    # We need to find the right 21 equations that give consistent results
    
    # Or better: use LLL/lattice reduction on each frequency
    
    # Actually simplest approach: just solve the first 21x21 system for each frequency,
    # then verify
    
    print("[*] Solving per-frequency systems...")
    S_ntt = np.zeros((K, N), dtype=np.int64)
    
    success = 0
    fail = 0
    
    for r in range(N):
        # Build 48x21 matrix A_mat and 48-vector b_vec
        A_mat = np.zeros((48, K), dtype=np.int64)
        b_vec = np.zeros(48, dtype=np.int64)
        
        for i in range(48):
            ntt_a, ntt_b = ntt_samples[i]
            for j in range(K):
                A_mat[i, j] = ntt_a[j][r]
            b_vec[i] = ntt_b[r]
        
        # Solve first 21 equations
        A21 = A_mat[:21, :].copy()
        b21 = b_vec[:21].copy()
        
        s_r, pivots = gauss_mod_q(A21, b21)
        
        if pivots == K:
            # Verify against remaining equations
            pred = (A_mat[21:] @ s_r) % Q
            residual = (b_vec[21:] - pred) % Q
            residual = np.where(residual > Q//2, residual - Q, residual)
            max_res = np.max(np.abs(residual))
            
            if max_res < Q//4:  # reasonable bound
                S_ntt[:, r] = s_r
                success += 1
            else:
                fail += 1
                if fail <= 3:
                    print(f"  Freq {r}: max residual = {max_res}")
        else:
            fail += 1
            if fail <= 3:
                print(f"  Freq {r}: only {pivots} pivots")
        
        if (r+1) % 100 == 0:
            print(f"  Freq {r+1}/{N}: {success} ok, {fail} fail")
    
    print(f"\n[*] Results: {success} ok, {fail} fail out of {N}")
    
    if success == N:
        print("[+] All frequencies solved!")
        
        # Convert back to time domain
        s_polys = []
        for j in range(K):
            s_j = fast_intt(S_ntt[j])
            s_polys.append(s_j)
            
            # Check if coefficients are small (eta_s = 7)
            s_centered = np.where(s_j > Q//2, s_j - Q, s_j)
            print(f"  s_{j}: min={np.min(s_centered)}, max={np.max(s_centered)}")
        
        # Look for chain structure
        print("\n[*] Analyzing chain structure...")
        s0 = s_polys[0]
        s0_centered = np.where(s0 > Q//2, s0 - Q, s0)
        print(f"  s_0[:20] = {s0_centered[:20]}")
        
        # Try submitting s_0 as base polynomial
        s0_list = [int(x) for x in s0]
        r.sendline(b'4')
        r.recvuntil(b'> ')
        r.sendline(json.dumps(s0_list).encode())
        resp_data = r.recvuntil(b'> ', timeout=10)
        print(f"  Submit s_0 response: {resp_data.decode()[:300]}")
    
    r.close()

if __name__ == '__main__':
    main()
