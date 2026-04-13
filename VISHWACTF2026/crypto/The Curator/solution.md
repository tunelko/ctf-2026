# The Curator — VishwaCTF 2026 (Crypto)

## TL;DR

Recover LCG parameters from 8 consecutive outputs, generate keystream using the low byte of each subsequent LCG state, XOR-decrypt the flag.

## Analysis

The cryptosystem has multiple layers but only the LCG stream cipher matters for the flag:

1. **LCG** with M=2^32, unknown A, C, seed, and 8 known consecutive outputs
2. **RSA** with related-message encryption (red herring for the flag)
3. **Stream cipher** using LCG low bytes as keystream

## Solution

### Step 1: Recover LCG Parameters

From consecutive outputs x0, x1, x2: `x_{n+1} = A*x_n + C mod M`

```
diff1 = (x1 - x0) mod M
diff2 = (x2 - x1) mod M
A = diff2 * modinv(diff1, M) mod M
C = (x1 - A*x0) mod M
```

Result: A = 2072692183, C = 1916465311

### Step 2: Recover Seed

```
seed = modinv(A, M) * (x1 - C) mod M = 651701731
```

### Step 3: Generate Keystream and Decrypt

The stream cipher uses the **low byte** of each LCG output starting from x9 (after the 8 public outputs):

```python
x = outputs[-1]  # x8
keystream = b''
while len(keystream) < len(encrypted_flag):
    x = (A * x + C) % M
    keystream += bytes([x & 0xFF])

plaintext = bytes([a ^ b for a, b in zip(encrypted_flag, keystream)])
```

## Flag

```
VishwaCTF{s33ds_4r3_n3v3r_s4f3_1ns1d3_pr1m3s_4nd_n01s3}
```

## Key Lessons

- LCG with known M and consecutive outputs is trivially broken via modular arithmetic
- Using only the low byte of LCG output doesn't improve security — the full state is recoverable
- The RSA related-message attack and "Backup Fragment" were red herrings
