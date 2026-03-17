#!/usr/bin/env python3
"""
PQChat solver - Module-LWE with reduction chain structure
"""

from pwn import *
import json
import numpy as np
import struct
import hashlib
from Crypto.Cipher import AES

# Parameters
N = 512
Q = 12289
K = 21
ETA_S = 7
ETA_E = 2
MAX_SAMPLES = 48
POLY_BITS = 14
POLY_BYTES = 896

def unpack_poly(hex_str):
    """Unpack a polynomial from 14-bit packed hex string"""
    data = bytes.fromhex(hex_str)
    assert len(data) == POLY_BYTES, f"Expected {POLY_BYTES} bytes, got {len(data)}"
    
    coeffs = []
    # 14 bits per coefficient, little-endian bit packing
    bits = int.from_bytes(data, 'little')
    for i in range(N):
        val = (bits >> (i * POLY_BITS)) & ((1 << POLY_BITS) - 1)
        coeffs.append(val % Q)
    return np.array(coeffs, dtype=np.int64)

def pack_poly(coeffs):
    """Pack a polynomial to 14-bit packed hex string"""
    bits = 0
    for i in range(N):
        bits |= (int(coeffs[i]) % Q) << (i * POLY_BITS)
    data = bits.to_bytes(POLY_BYTES, 'little')
    return data.hex()

def poly_mul_mod(a, b, q=Q, n=N):
    """Multiply two polynomials mod (x^n + 1, q) using negacyclic convolution"""
    # Use numpy convolution then reduce
    c = np.convolve(a.astype(np.int64), b.astype(np.int64))
    # Reduce mod x^n + 1: coefficients at position >= n get subtracted
    result = np.zeros(n, dtype=np.int64)
    for i in range(len(c)):
        idx = i % n
        sign = 1 if (i // n) % 2 == 0 else -1
        result[idx] = (result[idx] + sign * c[i]) % q
    return result

def negacyclic_matrix(a, n=N, q=Q):
    """Convert polynomial a to its negacyclic multiplication matrix.
    M[i][j] = coefficient i of (a * x^j mod (x^n+1))
    So M @ s = a * s mod (x^n+1)
    """
    M = np.zeros((n, n), dtype=np.int64)
    for j in range(n):
        for i in range(n):
            # coefficient i of a(x) * x^j mod (x^n + 1)
            # This is a[i-j] if i >= j, else -a[n+i-j]
            idx = i - j
            if idx >= 0:
                M[i][j] = a[idx] % q
            else:
                M[i][j] = (-a[n + idx]) % q
    return M

def collect_samples(host='dyn-01.midnightflag.fr', port=14123, num_samples=48):
    """Connect to server and collect handshake samples"""
    r = remote(host, port)
    r.recvuntil(b'> ')
    
    # Get encrypted flag first
    r.sendline(b'3')
    data = r.recvuntil(b'> ')
    flag_data = json.loads(data.decode().strip().split('\n\n')[0])
    print(f"Flag data: {flag_data}")
    
    samples = []
    for i in range(num_samples):
        r.sendline(b'2')
        data = r.recvuntil(b'> ')
        hs_text = data.decode().strip().split('\n\n')[0]
        hs = json.loads(hs_text)
        
        # Unpack polynomials
        a_polys = [unpack_poly(h) for h in hs['a_hex']]
        b_poly = unpack_poly(hs['b_hex'])
        
        samples.append((a_polys, b_poly))
        if (i+1) % 10 == 0:
            print(f"Collected {i+1}/{num_samples} samples")
    
    return r, samples, flag_data

def solve_modular_system(A_mat, b_vec, q=Q):
    """Solve A*x = b mod q using Gaussian elimination"""
    n_rows, n_cols = A_mat.shape
    print(f"Solving {n_rows}x{n_cols} system mod {q}")
    
    # Augmented matrix
    aug = np.zeros((n_rows, n_cols + 1), dtype=np.int64)
    aug[:, :n_cols] = A_mat % q
    aug[:, n_cols] = b_vec % q
    
    pivot_row = 0
    pivot_cols = []
    
    for col in range(n_cols):
        if pivot_row >= n_rows:
            break
        
        # Find pivot
        found = -1
        for row in range(pivot_row, n_rows):
            if aug[row, col] % q != 0:
                # Check if invertible
                val = int(aug[row, col] % q)
                if pow(val, q-2, q) * val % q == 1:  # has inverse
                    found = row
                    break
        
        if found == -1:
            continue
        
        # Swap
        if found != pivot_row:
            aug[[pivot_row, found]] = aug[[found, pivot_row]]
        
        # Normalize pivot row
        inv = pow(int(aug[pivot_row, col] % q), q - 2, q)
        aug[pivot_row] = (aug[pivot_row] * inv) % q
        
        # Eliminate column
        for row in range(n_rows):
            if row != pivot_row and aug[row, col] % q != 0:
                factor = aug[row, col] % q
                aug[row] = (aug[row] - factor * aug[pivot_row]) % q
        
        pivot_cols.append(col)
        pivot_row += 1
        
        if (col + 1) % 100 == 0:
            print(f"  Processed {col+1}/{n_cols} columns, {pivot_row} pivots found")
    
    print(f"Found {len(pivot_cols)} pivots")
    
    # Extract solution
    x = np.zeros(n_cols, dtype=np.int64)
    for i, col in enumerate(pivot_cols):
        x[col] = aug[i, n_cols] % q
    
    return x, len(pivot_cols)

def main():
    print("[*] Collecting samples from server...")
    r, samples, flag_data = collect_samples(num_samples=48)
    print(f"[*] Collected {len(samples)} samples")
    
    # Build the linear system
    # Each sample: b = sum_j A_j * s_j + e  (polynomial multiplication)
    # In matrix form: b = [M(a_0) | M(a_1) | ... | M(a_20)] * [s_0; s_1; ...; s_20] + e
    # where M(a_j) is the N x N negacyclic matrix for a_j
    #
    # But option 4 says submit "secret base polynomial" of length N
    # So all s_j are derived from one base s_0
    #
    # Let's first try to solve for just s_0 assuming s_j = h^j * s_0
    # We need to figure out h...
    
    # Actually, let me try a different approach first.
    # Since we have 48 samples each giving 512 equations for 10752 unknowns,
    # total 24576 equations > 10752 unknowns, the system is overdetermined.
    # But with noise eta_e=2, exact solution won't exist.
    # 
    # However, since Q=12289 is prime and the noise is tiny (at most 2),
    # if we take enough equations, we can still solve exactly by using
    # the fact that the error is small.
    
    # Strategy: Use the first ~21 samples (21*512 = 10752 equations for 10752 unknowns)
    # to get an exact solution mod Q. If noise is 0 for most coefficients, this works.
    # If not, we need to use the structure.
    
    # Let me first try the reduction chain approach.
    # The seeds suggest that h is derived from mask_h_seed.
    # Let me derive h using SHAKE256 (common in lattice crypto)
    
    # Try multiple derivation methods for h
    def derive_poly_shake256(seed_bytes, n=N, q=Q):
        h = hashlib.shake_256(seed_bytes).digest(n * 2)
        coeffs = []
        for i in range(n):
            val = struct.unpack_from('<H', h, i*2)[0] % q
            coeffs.append(val)
        return np.array(coeffs, dtype=np.int64)
    
    # Try h as mask polynomial
    h_seed = b"pqchat.mask-h.v7.reduction-chain"
    g_seed = b"pqchat.mask-g.v7.reduction-chain"
    layout_seed = b"pqchat.layout.v7.reduction-chain"
    
    h_poly = derive_poly_shake256(h_seed)
    g_poly = derive_poly_shake256(g_seed)
    layout_poly = derive_poly_shake256(layout_seed)
    
    print(f"[*] h_poly[:5] = {h_poly[:5]}")
    print(f"[*] g_poly[:5] = {g_poly[:5]}")
    
    # Test hypothesis: s_j = h^j * s_0 mod (x^n+1, q)
    # If so, then b_i = sum_j a_{i,j} * h^j * s_0 + e_i
    #        = (sum_j a_{i,j} * h^j) * s_0 + e_i
    # Define c_i = sum_j a_{i,j} * h^j
    # Then b_i = c_i * s_0 + e_i
    
    # This gives us 48 polynomial equations in s_0 (512 unknowns)
    # 48 * 512 = 24576 equations for 512 unknowns
    # MASSIVELY overdetermined, easy to solve even with small noise
    
    print("[*] Testing reduction chain hypothesis: s_j = h^j * s_0")
    
    # Precompute h^j for j=0..20
    h_powers = [np.zeros(N, dtype=np.int64) for _ in range(K)]
    h_powers[0][0] = 1  # h^0 = 1
    for j in range(1, K):
        h_powers[j] = poly_mul_mod(h_powers[j-1], h_poly)
    
    # For each sample, compute c_i = sum_j a_{i,j} * h^j
    # Then build matrix from c_i
    
    # Build the system: M(c_i) * s_0 = b_i (approximately)
    # Stack all: big_M * s_0 = big_b
    
    print("[*] Building linear system...")
    
    num_use = 48  # Use all samples
    big_M = np.zeros((num_use * N, N), dtype=np.int64)
    big_b = np.zeros(num_use * N, dtype=np.int64)
    
    for i in range(num_use):
        a_polys, b_poly = samples[i]
        
        # c_i = sum_j a_{i,j} * h^j
        c_i = np.zeros(N, dtype=np.int64)
        for j in range(K):
            prod = poly_mul_mod(a_polys[j], h_powers[j])
            c_i = (c_i + prod) % Q
        
        # Build negacyclic matrix for c_i
        M_ci = negacyclic_matrix(c_i)
        big_M[i*N:(i+1)*N, :] = M_ci
        big_b[i*N:(i+1)*N] = b_poly
        
        if (i+1) % 10 == 0:
            print(f"  Processed {i+1}/{num_use} samples")
    
    print("[*] Solving system...")
    
    # With overdetermined system and small noise, we can try:
    # 1. Take first N equations and solve exactly
    # 2. If that fails, use more equations
    
    # Try with first N=512 equations (from first sample)
    s0_candidate, pivots = solve_modular_system(big_M[:N, :], big_b[:N])
    
    if pivots == N:
        print("[*] Got full rank solution from first sample!")
        # Verify against other samples
        errors = []
        for i in range(1, min(5, num_use)):
            predicted_b = (big_M[i*N:(i+1)*N] @ s0_candidate) % Q
            actual_b = big_b[i*N:(i+1)*N]
            err = (actual_b - predicted_b) % Q
            # Map to centered representation
            err = np.where(err > Q//2, err - Q, err)
            max_err = np.max(np.abs(err))
            errors.append(max_err)
            print(f"  Sample {i}: max error = {max_err}")
        
        if max(errors) <= ETA_E:
            print("[+] Solution verified! Errors within eta_e bound")
        else:
            print(f"[-] Errors too large: {errors}")
            print("[*] h hypothesis might be wrong, trying different approach...")
            
            # Maybe the chain is different. Let me try without the chain structure
            # and solve for all k*N unknowns at once
            s0_candidate = None
    else:
        print(f"[-] Only {pivots} pivots, system not full rank")
        s0_candidate = None
    
    if s0_candidate is not None:
        # Convert to centered representation for submission
        s0_centered = s0_candidate.copy()
        s0_centered = np.where(s0_centered > Q//2, s0_centered - Q, s0_centered)
        print(f"[*] s0 stats: min={np.min(s0_centered)}, max={np.max(s0_centered)}")
        print(f"[*] s0[:20] = {s0_centered[:20]}")
        
        # Try submitting to server
        s0_list = [int(x) for x in s0_candidate]
        r.sendline(b'4')
        r.recvuntil(b'> ')
        r.sendline(json.dumps(s0_list).encode())
        response = r.recvuntil(b'> ', timeout=10)
        print(f"[*] Server response: {response.decode()[:500]}")
        
        resp = json.loads(response.decode().strip().split('\n\n')[0])
        if resp.get('ok'):
            print("[+] SECRET ACCEPTED!")
            # Try to get the flag now
            if 'flag' in resp:
                print(f"[+] FLAG: {resp['flag']}")
            if 'key_hex' in resp:
                print(f"[+] KEY: {resp['key_hex']}")
                key = bytes.fromhex(resp['key_hex'])
                nonce = bytes.fromhex(flag_data['nonce_hex'])
                ct = bytes.fromhex(flag_data['ct_hex'])
                tag = bytes.fromhex(flag_data['tag_hex'])
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ct, tag)
                print(f"[+] FLAG: {plaintext.decode()}")
        else:
            print("[-] Secret rejected, trying to derive AES key ourselves...")
            # Try different key derivation methods
            s0_bytes = b''.join(struct.pack('<h', int(x)) for x in s0_centered)
            
            # Try SHA256 of coefficients
            key_sha256 = hashlib.sha256(s0_bytes).digest()[:16]
            try:
                nonce = bytes.fromhex(flag_data['nonce_hex'])
                ct = bytes.fromhex(flag_data['ct_hex'])
                tag = bytes.fromhex(flag_data['tag_hex'])
                cipher = AES.new(key_sha256, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ct, tag)
                print(f"[+] FLAG (SHA256): {plaintext.decode()}")
            except Exception as e:
                print(f"[-] SHA256 key failed: {e}")
                
                # Try packing as polynomial hex
                s0_hex = pack_poly(s0_candidate)
                key2 = hashlib.sha256(bytes.fromhex(s0_hex)).digest()[:16]
                try:
                    cipher = AES.new(key2, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ct, tag)
                    print(f"[+] FLAG (SHA256 packed): {plaintext.decode()}")
                except Exception as e2:
                    print(f"[-] SHA256 packed failed: {e2}")
    
    r.close()

if __name__ == '__main__':
    main()
