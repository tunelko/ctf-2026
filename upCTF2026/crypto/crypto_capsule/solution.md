# xSTF's Decryption Capsule — upCTF 2026

**Category:** Crypto (AES-CBC Padding Oracle)
**Flag:** `upCTF{p4dd1ng_0r4cl3_s4ys_xSTF_1s_num3r0_un0-dqxH5Zcr60416fcd}`

## TL;DR

AES-CBC decryption service that leaks PKCS7 padding validity through distinct error messages. Padding oracle attack to **encrypt** an arbitrary plaintext without knowing the key, building the ciphertext block by block from the last to the first.

---

## Analysis

### Service

```
nc 46.225.117.62 30004
```

Accepts hex: `IV (16 bytes) || ciphertext`. Decrypts with AES-128-CBC and responds:

| Case | Response |
|------|-----------|
| Invalid padding | `"Padding is incorrect."` |
| Valid padding, wrong plaintext | `"you ain't got lil bro"` |
| Plaintext = target | `"Yeah it is!"` + flag |

**Target:** `xSTF is the best portuguese CTF team :P` (39 bytes)

### Vulnerability: CWE-209 — Information Exposure Through Error Message

```python
try:
    plaintext = unpad(decrypted, AES.block_size).decode('latin1')
except Exception as e:
    print(str(e))    # ← leak: padding valid/invalid
    continue
```

The `unpad` call throws an exception with a specific message if the padding is incorrect. This creates a **padding oracle** that allows distinguishing between valid and invalid padding.

---

## Attack

### Padding Oracle → Encrypt

The goal is not to decrypt but to **encrypt** a chosen plaintext. In AES-CBC:

```
P_i = D(K, C_i) ⊕ C_{i-1}
```

If we can discover `D(K, C_i)` (the intermediate value after decrypting a block), then:

```
C_{i-1} = D(K, C_i) ⊕ P_i
```

The padding oracle allows discovering `D(K, C_i)` byte by byte:

1. For the byte at position `j` (from the end), construct a test IV where:
   - The already-known bytes produce valid padding (`pad_value`)
   - Byte `j` is iterated from 0 to 255
2. When the oracle reports valid padding → `guess ⊕ D(K,C)[j] = pad_value`
3. Solve: `D(K,C)[j] = guess ⊕ pad_value`

### Ciphertext Construction

Target with PKCS7 padding: 39 bytes → 48 bytes (padding `\x09` × 9) → 3 blocks.

```
P = [P_0 | P_1 | P_2]    (plaintext blocks)
C = [IV  | C_1 | C_2 | C_3]  (to construct)
```

Build from back to front:

| Step | Action | Queries |
|------|--------|---------|
| 1 | C₃ = random 16 bytes | 0 |
| 2 | I₃ = D(K, C₃) via oracle | ~2048 |
| 3 | C₂ = I₃ ⊕ P₂ | 0 |
| 4 | I₂ = D(K, C₂) via oracle | ~2048 |
| 5 | C₁ = I₂ ⊕ P₁ | 0 |
| 6 | I₁ = D(K, C₁) via oracle | ~2048 |
| 7 | IV = I₁ ⊕ P₀ | 0 |

Total: ~6144 queries (128 average × 16 bytes × 3 blocks).

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
from pwn import *
import os

HOST = "46.225.117.62"
PORT = 30004
BLOCK_SIZE = 16
TARGET = b"xSTF is the best portuguese CTF team :P"

def pad(data):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def send_payload(r, iv, ct):
    r.sendlineafter(b">", (iv + ct).hex().encode())
    return r.recvline(timeout=5).decode().strip()

def find_intermediate(r, ct_block):
    intermediate = [0] * BLOCK_SIZE
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - pos
        test_iv = bytearray(BLOCK_SIZE)
        for k in range(pos + 1, BLOCK_SIZE):
            test_iv[k] = intermediate[k] ^ pad_val
        for guess in range(256):
            test_iv[pos] = guess
            resp = send_payload(r, bytes(test_iv), ct_block)
            if "ain't" in resp or "Yeah" in resp:
                if pos == BLOCK_SIZE - 1 and pad_val == 1:
                    v = bytearray(test_iv); v[pos-1] ^= 1
                    if "ain't" not in send_payload(r, bytes(v), ct_block):
                        continue
                intermediate[pos] = guess ^ pad_val
                break
    return bytes(intermediate)

target_padded = pad(TARGET)
pt_blocks = [target_padded[i*16:(i+1)*16] for i in range(3)]

r = remote(HOST, PORT)
r.recvuntil(b"transmission...")

ct_blocks = [os.urandom(16)]
for i in range(2, -1, -1):
    inter = find_intermediate(r, ct_blocks[0])
    ct_blocks.insert(0, bytes(a^b for a,b in zip(inter, pt_blocks[i])))

resp = send_payload(r, ct_blocks[0], b''.join(ct_blocks[1:]))
print(resp)
print(r.recvall(timeout=3).decode())
```

```
$ python3 solve.py
[+] Opening connection to 46.225.117.62 on port 30004: Done
Yeah it is!
upCTF{p4dd1ng_0r4cl3_s4ys_xSTF_1s_num3r0_un0-dqxH5Zcr60416fcd}
```

---

## Key Lessons

1. **Padding oracle = arbitrary encryption**: it doesn't just allow decryption — it also allows encrypting any plaintext without knowing the key
2. **Distinct error messages**: being able to distinguish "valid padding" from "invalid padding" is enough for the attack to work. Here the difference between `"Padding is incorrect."` and `"you ain't got lil bro"` is the oracle
3. **Mitigation**: use `AES-GCM` or `AES-CCM` (authenticated encryption), or verify an HMAC before attempting `unpad`. Never leak padding errors to the user
4. **False positives**: when searching for the last byte, padding `\x02\x02` passes as valid in addition to `\x01`. Verifying by flipping another byte rules out these collisions
5. **Complexity**: O(256 × blocksize × num_blocks) = ~6K queries, executable in <2 minutes against a remote server

## References

- [Vaudenay (2002) — Security Flaws Induced by CBC Padding](https://www.iacr.org/cryptodb/archive/2002/EUROCRYPT/2850/2850.pdf)
- [PadBuster — Automated Padding Oracle Attacks](https://github.com/AonCyberLabs/PadBuster)
- [CWE-209: Information Exposure Through an Error Message](https://cwe.mitre.org/data/definitions/209.html)
