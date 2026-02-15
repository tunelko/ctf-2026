# Delicious Looking Problem — Crypto (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Crypto
**Difficulty:** Beginner
**Author:** Reewnat
**Flag:** `0xfun{pls_d0nt_hur7_my_b4by(DLP)_AI_kun!:3}`

---

## Description

> A delicious looking problem for starters. Always remember that the answer to life, universe and everything is 42.

## Analysis

The challenge provides `chall.py` and `output.txt`.

### Source code

```python
key = os.urandom(len(flag))  # random key of the same length as the flag

def gen():
    p, q = get_safe_prime(42)   # safe primes of 42 bits
    g = primitive_root(p, q)
    h = pow(g, bytes_to_long(key), p)
    return g, h, p

Max_samples = 67 // 8  # = 8 samples
```

8 samples `(g, h, p)` are generated where `h = g^(bytes_to_long(key)) mod p`, with safe primes of only 42 bits. The flag is encrypted with AES-ECB using `SHA256(key)`.

### Data

- 8 triples (g, h, p) with ~42-bit primes
- 48-byte AES-ECB ciphertext (flag of 32-47 bytes)

## Solution

### Step 1: Discrete Logarithm Problem (DLP)

The primes are only 42 bits, making the DLP trivial with Baby-Step Giant-Step or Pohlig-Hellman:

```python
for g, h, p in samples:
    x = discrete_log(p, h, g)  # sympy BSGS
    assert pow(g, x, p) == h
```

### Step 2: Chinese Remainder Theorem (CRT)

Each safe prime has `p-1 = 2*q` where q is prime. All q_i are distinct primes and coprime. The residues are extracted:

- `x = 1 (mod 2)` (all DLPs are odd)
- `x = x_i mod q_i` for each sample

CRT over moduli `[2, q_1, q_2, ..., q_8]` gives a unique value `x_crt` modulo `M = 2 * q_1 * ... * q_8` (~325 bits).

### Step 3: Brute-force of k

The real key is `bytes_to_long(key) = x_crt + k * M` for some k >= 0. The ciphertext size (48 bytes) limits the flag to 32-47 bytes, and x_crt requires at least 41 bytes.

For key_len = 43 bytes, there are ~1,010,023 candidates for k. All are tested:

```python
for k in range(max_k + 1):
    x_candidate = x_crt + k * M
    key = x_candidate.to_bytes(43, 'big')
    aes_key = hashlib.sha256(key).digest()
    cipher = AES.new(aes_key, AES.MODE_ECB)
    pt = unpad(cipher.decrypt(ct), 16)
    if all(32 <= b < 127 for b in pt):
        print(f"FLAG: {pt.decode()}")
```

The solution is found at **k=975590, key_len=43**.

## Notes

- The hint "42" refers to the prime size (42 bits), not the flag length
- The flag is 43 bytes, not 42
- The emoticon `:3` appears both in the code and in the flag
- The complete search of ~1M candidates takes ~2 minutes
