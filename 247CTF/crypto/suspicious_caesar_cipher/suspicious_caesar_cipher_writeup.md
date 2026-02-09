# Suspicious Caesar Cipher - RSA Challenge

## Challenge Description
> We RSA encrypted the flag, but forgot to save the private key. Is it possible to recover the flag without it?

**Category:** Cryptography
**Flag:** `247CTF{aedd410dXXXXXXXXXXXXXXXX2ddd2649}`

## Analysis

### Source Code Review

```python
from Crypto.Util.number import getStrongPrime
from fractions import gcd
from secret import flag

def get_key(e=65537, bit_length=2048):
    while True:
        p = getStrongPrime(bit_length, e=e)
        q = getStrongPrime(bit_length, e=e)
        if gcd(e, (p - 1) * (q - 1)) == 1:
            return e, p * q

def encrypt(e, n, m):
    return [((ord(c) ** e) % n) for c in m]

e, n = get_key()
print("Generated key:")
print(e)
print(n)
print("Encrypted flag:")
print(encrypt(e, n, flag))
```

### Vulnerability

The critical weakness is in the `encrypt()` function:

```python
def encrypt(e, n, m):
    return [((ord(c) ** e) % n) for c in m]
```

**Each character is encrypted individually!**

This is known as "textbook RSA" applied to small messages. The problems:

1. ASCII characters have values 0-255 (very small message space)
2. RSA is deterministic - same input always produces same output
3. No padding means we can build a lookup table

### Attack: Lookup Table

Since there are only 256 possible ASCII values, we can:

1. Compute `c^e mod n` for all characters c ∈ [0, 255]
2. Build a reverse mapping: ciphertext → plaintext character
3. Decrypt each value in the encrypted flag

## Solution

```python
#!/usr/bin/env python3
# Parse the output file
with open('suspicious_caesar_cipher.out', 'r') as f:
    lines = f.read().strip().split('\n')

e = int(lines[1])
n = int(lines[2])

# Parse encrypted flag list
encrypted_str = lines[4].strip('[]')
encrypted = [int(x.strip().rstrip('L')) for x in encrypted_str.split(',')]

# Build lookup table: for each ASCII char, compute c^e mod n
lookup = {}
for c in range(256):
    ct = pow(c, e, n)
    lookup[ct] = chr(c)

# Decrypt
flag = ""
for ct in encrypted:
    flag += lookup.get(ct, "?")

print(f"Flag: {flag}")
```

## Output

```
e = 65537
n = 909193180607169730928877645070327819694835874221183905239040600481564219496549...
Encrypted values: 40 characters

Flag: 247CTF{aedd410dXXXXXXXXXXXXXXXX2ddd2649}
```

## Lessons Learned

1. **Never use textbook RSA** - Always use proper padding schemes (OAEP, PKCS#1 v1.5)
2. **RSA is not meant for small messages** - The message space must be large enough to prevent brute force
3. **Deterministic encryption is dangerous** - Same plaintext → same ciphertext enables frequency analysis and lookup attacks
4. **The name "Caesar cipher" was a hint** - Like Caesar cipher, this is a simple substitution cipher (just with RSA as the substitution function)

## Why Proper Padding Matters

With OAEP padding:
- Random padding is added to each message
- Same plaintext encrypts to different ciphertexts each time
- Padding fills the message to full block size
- Lookup tables become infeasible
