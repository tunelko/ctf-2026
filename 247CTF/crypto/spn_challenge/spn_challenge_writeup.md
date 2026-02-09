# Substitution-Permutation Network - Crypto Challenge

## Challenge Description
> We put together a substitution-flag-permutation network. We encrypted the flag with the network, but forgot to write down the key. Can you reverse the network and recover the flag plaintext?

**Category:** Cryptography
**Flag:** `247CTF{390d2b4aXXXXXXXXXXXXXXXXc609702d}`

## Analysis

### Source Code Review

```python
import random
from secret import flag

rounds = 5
block_size = 8
sa = {0: 15, 1: 2, 2: 14, ...}  # S-box A (4-bit)
sb = {0: 12, 1: 8, 2: 13, ...}  # S-box B (4-bit)

key = [random.randrange(255), random.randrange(255)] * 4  # WEAK KEY!

def en(e):
    """Apply S-boxes and P-box to each byte"""
    encrypted = []
    for i in e:
        a, b = bin_split(to_bin(ord(i)))
        sa, sb = s(to_int(a), to_int(b))
        pe = p(bin_join(...))
        encrypted.append(to_int(pe))
    return encrypted

def r(p, k):
    """Main encryption: 5 rounds of XOR + S-box + P-box"""
    keys = ks(k)  # Key schedule
    state = str_split(p)
    for b in range(len(state)):
        for i in range(rounds):
            rk = kx(to_ord(state[b]), keys[i])
            state[b] = to_chr(en(to_chr(rk)))
    return [ord(e) for es in state for e in es]
```

### Vulnerability: Weak Key Space

The critical weakness is in the key generation:

```python
key = [random.randrange(255), random.randrange(255)] * 4
```

This creates a key like `[a, b, a, b, a, b, a, b]` where:
- `a` ∈ [0, 255]
- `b` ∈ [0, 255]

**Total key space: 256 × 256 = 65,536 keys**

This is trivially brute-forceable!

### Attack Strategy

1. **Known plaintext:** Flag starts with `247CTF{` (7 known bytes)
2. **Brute force:** Try all 65,536 possible (a, b) combinations
3. **Verify:** Encrypt known plaintext and compare with ciphertext
4. **Decrypt:** Once key is found, reverse the encryption

## Solution

```python
#!/usr/bin/env python3
# Inverse S-boxes for decryption
sa_inv = {v: k for k, v in sa.items()}
sb_inv = {v: k for k, v in sb.items()}

def p_inv(a):
    """Inverse permutation"""
    result = [''] * 8
    result[5], result[2], result[3], result[1] = a[0], a[1], a[2], a[3]
    result[6], result[0], result[7], result[4] = a[4], a[5], a[6], a[7]
    return ''.join(result)

def de(e):
    """Decrypt one round: inverse P-box then inverse S-boxes"""
    decrypted = []
    for val in e:
        pe_inv = p_inv(to_bin(val))
        a, b = bin_split(pe_inv)
        sa_out, sb_out = s_inv(to_int(a), to_int(b))
        decrypted.append((sa_out << 4) | sb_out)
    return decrypted

# Brute force
encrypted = [190, 245, 36, 15, 132, 103, 116, 14, ...]
known = [ord(c) for c in "247CTF{"]

for a in range(256):
    for b in range(256):
        key = [a, b] * 4
        test_enc = r_encrypt(known + [0], key)
        if test_enc[:7] == encrypted[:7]:
            # Found key! Decrypt the flag
            decrypted = r_decrypt(encrypted, key)
            print(''.join(chr(c) for c in decrypted))
```

## Output

```
Brute forcing key (65536 possibilities)...
Found key: a=31, b=65
Key bytes: [31, 65, 31, 65, 31, 65, 31, 65]
Decrypted: 247CTF{390d2b4aXXXXXXXXXXXXXXXXc609702d}
```

## Lessons Learned

1. **Key entropy matters** - A 256-bit key space (2^256) is secure, but 2^16 = 65536 is trivially brute-forceable
2. **Never repeat key material** - Using `[a, b] * 4` drastically reduces the effective key size
3. **Known plaintext attacks** - CTF flags have predictable prefixes, enabling known-plaintext attacks
4. **SPN structure is reversible** - S-boxes and P-boxes can be inverted if you know the key

## SPN Cipher Structure

```
Plaintext Block (8 bytes)
         │
         ▼
    ┌─────────┐
    │ XOR Key │ ◄── Round Key 0
    └────┬────┘
         │
    ┌────┴────┐
    │ S-boxes │  (4-bit substitution)
    └────┬────┘
         │
    ┌────┴────┐
    │ P-box   │  (bit permutation)
    └────┬────┘
         │
    (repeat 5 rounds)
         │
         ▼
   Ciphertext Block
```

To decrypt: reverse the order (P-box⁻¹ → S-boxes⁻¹ → XOR) for each round in reverse order.
