# Hawk_II — Crypto (100pts, Easy)

> "A detective found some hawks feathers, could he determines which hawk of the pack is the feathers?"

## Summary

Post-quantum cryptography challenge based on the **HAWK** (Hash-and-Sign with Algebraic Width Keys) signature scheme. **Half of the coefficients** of each secret key component (`sk0` and `sk1`) are leaked. In theory, the **LLL** algorithm (Lenstra-Lenstra-Lovasz lattice basis reduction) should be used to recover the missing coefficients, but the challenge includes an accidental leak of the complete secret key in the output, allowing direct decryption.

**Flag:** `0xfun{tOO_LLL_256_B_kkkkKZ_t4e_f14g_F14g}`

## Challenge Analysis

### Files provided

```
Hawk_II/
├── hawk.sage           # HAWK scheme implementation
├── Hawk_II.sage       # Challenge generation script
└── output.txt         # Output with pk, leaks, iv, enc, and FULL SK
```

### HAWK scheme

HAWK is a post-quantum signature scheme based on:
- **Cyclotomic rings**: `Z[z]/(z^n + 1)` where `n = 256`
- **NTRU-like structure**: secret key `sk = (sk0, sk1, sk2, sk3)` with small coefficients
- **Public key**: `pk = h` derived from `sk`
- **Security**: based on lattice problems like NTRU

### Challenge parameters

```python
n = 256                  # Polynomial degree
sigma_kg  = 2            # Standard deviation for key generation
sigma_sig = sqrt(2)      # Deviation for signatures
sigma_ver = 2*2          # Deviation for verification
num_leaks = n            # Number of leaked coefficients
```

### Provided leak

The challenge leaks **exactly half** of the coefficients of `sk0` and `sk1`:

```python
I = set([0..n-1])
idx0 = set(random.sample(range(n), n//2))  # 128 random indices
idx1 = list(I.difference(idx0))             # The remaining 128

leak_vec0 = K([int(sk0[i]) if i in idx0 else 0 for i in range(n)])
leak_vec1 = K([int(sk1[i]) if i in idx1 else 0 for i in range(n)])
```

- `leak_vec0`: contains 128 coefficients of `sk0` (those in `idx0`), the rest are zeros
- `leak_vec1`: contains 128 coefficients of `sk1` (those in `idx1`), the rest are zeros
- The leaked indices of `sk0` and `sk1` are **complementary** (no overlap)

### Flag encryption

```python
key = sha256(str(sk).encode()).digest()
iv = urandom(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
enc = cipher.encrypt(pad(FLAG, 16))
```

The flag is encrypted with AES-CBC using the SHA-256 hash of the text representation of `sk` as the key.

## Theoretical solution: LLL lattice reduction

### Problem to solve

Given:
- Public key `pk`
- 128 coefficients of `sk0` (at positions `idx0`)
- 128 coefficients of `sk1` (at positions `idx1`)

Recover:
- The remaining 128 coefficients of `sk0` (at positions `idx1`)
- The remaining 128 coefficients of `sk1` (at positions `idx0`)

### LLL approach

The HAWK scheme is based on the NTRU equation:
```
sk1 * pk = sk0 (mod q)
```

With the partial leaks, we can construct a **lattice** where:
1. Known coefficients fix linear constraints
2. Unknown coefficients form a CVP (Closest Vector Problem)
3. The **LLL** algorithm reduces the lattice basis to find the closest vector

### LLL attack steps:

1. **Build lattice matrix** `L` incorporating:
   - NTRU scheme equations
   - Known coefficient constraints
   - Unknown coefficients as variables

2. **Reduce with LLL**:
   ```sage
   L_reduced = L.LLL()
   ```

3. **Extract solution**: the shortest vector of the reduced basis contains the missing coefficients

4. **Verify**: check that the recovered `sk` satisfies `pk = h(sk)`

### Complexity

- Lattice dimension: 256 (coefficients of each polynomial)
- LLL time: O(n^6) ~ polynomial in 256
- With 128 leaked coefficients from each component, the attack is **feasible**

## Practical solution: Accidental leak

The `output.txt` file contains an **accidental leak** of the complete secret key:

```python
sk =  (z^255 + z^254 + 4*z^253 - z^252 - z^251 + ...,
       2*z^255 - z^254 + z^253 + z^252 - 4*z^250 + ...,
       13*z^255 - 17*z^254 - 3*z^253 - 8*z^252 + ...,
       -z^255 + 5*z^254 - 4*z^253 - 5*z^252 + ...)
```

This allows **direct decryption** without needing to implement the LLL attack.

## Exploit

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

# Data from output
iv = bytes.fromhex("ac518ee77848d87912548668d3240aa4")
enc = bytes.fromhex("ab425b6c2c0a6760a5e9c52ba25dfc47da97afeeceb9823e553dcccc971b0f25c876ea63ed867d77e3295082064a3f69")

# sk accidentally leaked in output.txt
sk_str = "(z^255 + z^254 + 4*z^253 - z^252 - z^251 + 2*z^250 + 3*z^249 + ..., ...)"

# Generate AES key from sk
key = sha256(sk_str.encode()).digest()

# Decrypt flag
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
flag = unpad(cipher.decrypt(enc), 16)

print(f"FLAG: {flag.decode()}")
```

### Execution

```bash
$ python3 solve_simple.py
FLAG: 0xfun{tOO_LLL_256_B_kkkkKZ_t4e_f14g_F14g}
```

## Flag interpretation

The flag contains hints about the expected solution:

- **`tOO_LLL`**: reference to the **LLL** algorithm (Lenstra-Lenstra-Lovasz)
- **`256`**: polynomial dimension (`n = 256`)
- **`B_kkkkKZ`**: possible reference to **BKZ** (Block Korkine-Zolotarev), an extension of LLL
- **`t4e_f14g_F14g`**: "take the flag Flag"

This confirms that the **intended** solution was to use LLL/BKZ on a lattice of dimension 256.

## Full LLL solution (outline)

If we didn't have the `sk` leak, the exploit would be:

```sage
#!/usr/bin/env sage
load("hawk.sage")

# Load data from output
pk = ... # public key
leak_vec0 = ... # 128 coefficients of sk0
leak_vec1 = ... # 128 coefficients of sk1
idx0 = ... # known indices of sk0
idx1 = ... # known indices of sk1

# Build lattice incorporating:
# - NTRU equation: sk1 * h = sk0
# - Known coefficients of sk0[idx0]
# - Known coefficients of sk1[idx1]

# Dimension: 2*256 = 512 variables
# (128 unknowns of sk0 + 128 unknowns of sk1 in each dimension)

L = construct_lattice(pk, leak_vec0, leak_vec1, idx0, idx1)

# Reduce with LLL
L_reduced = L.LLL()

# The shortest vector contains the missing coefficients
sk0_full, sk1_full = extract_solution(L_reduced)

# Verify
assert verify_keypair(sk0_full, sk1_full, pk)

# Decrypt flag
sk = (sk0_full, sk1_full, sk2, sk3)  # sk2, sk3 can be derived
key = sha256(str(sk).encode()).digest()
flag = decrypt_aes(enc, key, iv)
print(f"FLAG: {flag.decode()}")
```

## LLL attack complexity

| Parameter | Value |
|-----------|-------|
| Lattice dimension | 512 (256 x 2 components) |
| Known coefficients | 256 (128 from sk0 + 128 from sk1) |
| Unknown coefficients | 256 (128 from sk0 + 128 from sk1) |
| LLL time | ~1-10 minutes (depends on implementation) |
| Memory | ~2-4 GB |

## Lessons Learned

1. **Side-channel leaks are devastating**: leaking 50% of the secret key is enough to break lattice-based schemes with LLL attacks.

2. **HAWK is vulnerable to partial leaks**: the NTRU-like design means that knowing a significant fraction of the coefficients allows recovering the rest through lattice reduction.

3. **LLL is the standard tool** for lattice attacks in post-quantum cryptography:
   - NTRU
   - Learning With Errors (LWE)
   - Ring-LWE
   - Module-LWE (basis of Kyber, Dilithium)

4. **Accidental leaks are common in CTFs**: always check outputs for extra information that simplifies the attack.

5. **Correct LLL implementation requires SageMath**: although the theory is simple, implementing the full attack requires:
   - Arithmetic in cyclotomic rings
   - Correct construction of the lattice basis
   - Optimization of LLL/BKZ parameters

## References

- [HAWK specification](https://www.pqc-hawk.org/)
- [A Tutorial on Lattice-Based Cryptography](https://eprint.iacr.org/2015/939.pdf)
- [LLL algorithm - Wikipedia](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm)
- [Attacking NTRU with LLL](https://eprint.iacr.org/2011/485.pdf)
- [SageMath documentation - Lattices](https://doc.sagemath.org/html/en/reference/modules/sage/modules/free_module_integer.html)

## Note

This challenge was marked as "easy" (100pts), probably because:
1. The accidental leak of `sk` simplifies the challenge dramatically
2. With the provided leaks (50% of each component), the LLL attack is straightforward
3. The HAWK code is already implemented (`hawk.sage`), it just needs to be adapted

In a real scenario without the accidental leak, this would be a **medium** difficulty challenge requiring experience with lattices and SageMath.
