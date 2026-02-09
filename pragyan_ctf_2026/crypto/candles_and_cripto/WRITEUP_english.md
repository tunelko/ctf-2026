# Candles and Crypto

**CTF/platform:** Pragyan CTF 2026

**Category:** Crypto

**Difficulty:** Medium (63+ solves)

**Description:** Your friend's birthday is in one hour. The CandlesCake Shop approval system is stuck. Can you forge a transaction signature?

**Remote:** `ncat --ssl candles.ctf.prgy.in 1337`

**Flag:** `p_ctf{3l0w-tH3_c4Ndl35.h4VE=-tHe_CaK3!!}`

---

## Challenge Description

> Your friend's birthday is in one hour now. It is 11 PM sharp! You try to order a cake
> from CandlesCake Shop, but their online platform is completely broken. The approval system
> is stuck, and every transaction gets rejected unless it's properly signed. You're running
> out of time. Can you figure out how to get the cake delivered before midnight?

**Connection:** `ncat --ssl candles.ctf.prgy.in 1337`

**Files provided:** `server.py`, `public.pem`

---

## Server Analysis

### Complete source code (deobfuscated)

```python
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61   # 128-bit prime (2^128 - 159)
S = 48                                    # suffix length
A = b"I approve the agreement:\n"         # approval prefix
B = b"I authorize the transaction:\n"     # transaction prefix

def p(x):
    """Padding: adds one byte with len(x) & 0xFF"""
    return x + bytes([len(x) & 255])

def g(x, a, b):
    """Polynomial hash: x^3 + a*x^2 + b*x mod P"""
    return (pow(x, 3, P) + a * pow(x, 2, P) + b * x) % P

def s(h):
    """RSA signature: h^d mod n"""
    return pow(h, d, n)

def v(h, u):
    """RSA verification: u^e mod n == h"""
    return pow(u, e, n) == h
```

### Server flow

The server offers 3 options:

1. **Sign approval** (only 1 time):
   - Reads a 48-byte suffix (printable ASCII: 32-126)
   - Constructs `x = bytes_to_long(p(A + suffix))`
   - Calculates `h = g(x, a, b)` and returns RSA signature `sig = h^d mod n`
   - Reveals `L = m*(a-b) mod P` and `X = m` (where `m` is random)
   - This allows recovering `a - b = L * X^(-1) mod P`

2. **Execute transaction**:
   - Reads a 48-byte suffix
   - Constructs `x = bytes_to_long(p(B + suffix))`
   - Reads a signature (hex) from user
   - Verifies: `sig^e mod n == g(x, a, b)`
   - If it passes, prints the flag

3. **Exit**

### Cryptographic parameters

- **RSA**: 2048-bit `n`, `e = 65537` (public key provided in `public.pem`)
- **Polynomial hash**: operates in `Z_P` with `P = 2^128 - 159`
- **`a`, `b`**: random polynomial parameters, renewed each session

---

## Solution Process

### Phase 1: Reconnaissance and parameter recovery

From the signature oracle (option 1) we get:

- `sig1` — RSA signature of `h1 = g(x1, a, b)`
- `L = m*(a-b) mod P`, `X = m` — reveals `a - b`

With the public key we can recover `h1 = sig1^e mod n`, and knowing `x1` (the message we choose), we solve the system:

```
h1 = x1^3 + a*x1^2 + b*x1   (mod P)
a - b = known
```

Substituting `b = a - (a-b)`:

```
h1 = x1^3 + a*x1^2 + (a - (a-b))*x1   (mod P)
h1 = x1^3 + a*(x1^2 + x1) - (a-b)*x1  (mod P)

a = (h1 - x1^3 + (a-b)*x1) * (x1^2 + x1)^(-1)   (mod P)
b = a - (a-b)                                       (mod P)
```

**Result:** We fully recover `a` and `b`.

### Phase 2: Failed attempts (rabbit holes)

With `a` and `b` recovered, we need to forge a signature for a transaction message. We tried several approaches:

| Attempt | Idea | Why it failed |
|---------|------|---------------|
| **Hash collision** | Find suffix where `g(x_trans) = g(x_appr)` to reuse `sig1` | Space P ~ 2^128, collision probability negligible in linear search |
| **Low-exponent attack** | If `h^e < n`, the signature is the integer e-th root | `h` ~ 128 bits, `e = 65537`, `h^e` >> `n` (2048 bits). Not viable |
| **Factor n** | Obtain `d` to sign anything | 2048-bit n, not factorable (FactorDB, Pollard p-1, Fermat, RsaCtfTool failed) |
| **Algebraic relation** | Express `h2` as multiplicative function of `h1` | Cubic polynomial doesn't produce useful RSA-homomorphic relations |
| **Cubic equation** | Solve `g(x) = h1` to find colliding `x` | Requires Sage/cubic roots mod P; resulting values don't produce valid 48-byte suffixes |

### Phase 3: The key vulnerability (breakthrough)

**Critical observation:** The polynomial can be factored:

```
g(x, a, b) = x^3 + a*x^2 + b*x  (mod P)
            = x * (x^2 + a*x + b) (mod P)
```

**Consequence:** If `x ≡ 0 (mod P)`, then `g(x, a, b) = 0` **regardless of `a` and `b`**.

If the hash is `h = 0`, then the RSA verification becomes:

```
sig^e mod n == 0
```

And `sig = 0` satisfies this trivially: `0^65537 mod n = 0`.

**This means we don't even need option 1 (signature). We only need to find a suffix that makes `x ≡ 0 (mod P)`.**

### Phase 4: Construct the suffix

We need a suffix `suf` of 48 bytes (all printable ASCII, 32-126) such that:

```python
x = bytes_to_long(p(B + suf))
x ≡ 0  (mod P)
```

Where:
- `B = b"I authorize the transaction:\n"` (29 bytes)
- `suf` = 48 bytes
- `p(msg)` adds one byte: `bytes([len(msg) & 0xFF])` = `bytes([(29+48) & 0xFF])` = `bytes([77])` = `b'M'`
- Total message: 78 bytes → `x = bytes_to_long(78_bytes)`

#### Brute force strategy

The total message has 78 bytes. The first 29 bytes are fixed (prefix `B`), the last byte is fixed (`M`), and we control the 48 middle bytes.

**Idea:** Fix the upper 32 bytes of the suffix (random printable) and calculate the lower 16 bytes so that `x ≡ 0 (mod P)`.

```python
msg = B + upper_32_bytes + lower_16_bytes + b'M'   # 78 bytes total
x = bytes_to_long(msg)
```

We decompose `x` into high part (fixed) and low part (to solve):

```
x = high_part * 256^17 + low_part
```

Where `low_part` is the last 17 bytes (16 suffix bytes + 1 padding byte).

For `x ≡ 0 (mod P)`:

```
low_part ≡ -high_part * 256^17  (mod P)
```

We calculate `low_part` and extract the 16 suffix bytes. If all are in range [32, 126], we have a valid suffix.

**Probability per attempt:** Each suffix byte must fall in 95 values out of 256 possible:

```
Pr = (95/256)^16 ≈ 1.7 × 10^(-7)
```

**Expected attempts:** ~6 million (~30 seconds of execution).

### Phase 5: Implementation

```python
#!/usr/bin/env python3
"""
Candles and Crypto — Final Exploit
Pragyan CTF 2026

Attack: Polynomial hash zero → trivial signature
g(x,a,b) = x(x^2 + ax + b) mod P
If x ≡ 0 (mod P) → h = 0 → sig = 0 passes verification
"""
import os
import struct
import time
from Crypto.Util.number import bytes_to_long

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61

B = b"I authorize the transaction:\n"  # 29 bytes
SUFFIX_LEN = 48
TOTAL_MSG = B  # + suffix(48) → p() adds 1 byte

def find_suffix():
    """
    Find 48-byte printable suffix such that
    bytes_to_long(p(B + suffix)) ≡ 0 (mod P)
    """
    # p(B + suffix) = B + suffix + bytes([77])  (len=77, 77&0xFF=77='M')
    padding_byte = bytes([(len(B) + SUFFIX_LEN) & 0xFF])  # b'M'

    # Fixed part: B (29 bytes) + suffix_upper (32 bytes)
    # Variable part: suffix_lower (16 bytes) + padding (1 byte = 'M')

    # x = bytes_to_long(B + suffix_upper + suffix_lower + b'M')
    # x = high * 256^17 + bytes_to_long(suffix_lower + b'M')
    # We want x ≡ 0 (mod P)
    # bytes_to_long(suffix_lower + b'M') ≡ -high * 256^17 (mod P)

    shift = pow(256, 17, P)   # 256^17 mod P
    inv_256 = pow(256, -1, P) # To extract bytes

    attempts = 0
    start = time.time()

    while True:
        # Generate random 32 upper bytes (printable ASCII)
        upper = bytes([ord('!') + (b % 95) for b in os.urandom(32)])

        high = bytes_to_long(B + upper)
        target = (-high * shift) % P  # value the lower 17 bytes must have

        # target = bytes_to_long(suffix_lower(16) + b'M')
        # Extract: subtract the 'M' byte and divide by 256
        remaining = (target - padding_byte[0]) % P

        if remaining % 256 != 0:
            # remaining must be divisible by 256 (padding byte is LSB)
            # Actually, we need remaining = suffix_lower_as_int * 256 + ord('M')
            # So suffix_lower_as_int = (target - ord('M')) / 256
            pass

        suffix_lower_int = (target - padding_byte[0]) * pow(256, -1, P) % P

        # Verify it fits in 16 bytes
        if suffix_lower_int >= 256**16:
            attempts += 1
            continue

        # Convert to 16 bytes big-endian
        lower = suffix_lower_int.to_bytes(16, 'big')

        # Check printability
        if all(32 <= c <= 126 for c in lower):
            suffix = upper + lower
            elapsed = time.time() - start
            print(f"[!] FOUND in {attempts} attempts ({elapsed:.1f}s)")
            print(f"[+] Suffix: {suffix}")

            # Verification
            msg = B + suffix
            padded = msg + padding_byte
            x = bytes_to_long(padded)
            assert x % P == 0, "ERROR: x is not 0 mod P!"
            print("[+] Verification: x mod P = 0 ✓")

            return suffix

        attempts += 1
        if attempts % 1_000_000 == 0:
            elapsed = time.time() - start
            rate = attempts / elapsed
            print(f"[*] {attempts/1e6:.0f}M attempts ({rate:.0f}/s)...")

    return None


if __name__ == "__main__":
    # Step 1: Find valid suffix
    print("[*] Searching for suffix where x ≡ 0 (mod P)...")
    suffix = find_suffix()

    if suffix:
        # Save suffix
        with open('/tmp/candles_suffix.bin', 'wb') as f:
            f.write(suffix)
        print(f"[+] Suffix saved to /tmp/candles_suffix.bin")

        # Step 2: Connect and send
        from pwn import *

        io = remote('candles.ctf.prgy.in', 1337, ssl=True)
        io.recvuntil(b'> ')
        io.sendline(b'2')
        io.recvuntil(b'Suffix:')
        io.sendline(suffix)
        io.recvuntil(b'Signature:')
        io.sendline(b'0')  # sig = 0 because h = 0

        response = io.recvall(timeout=5)
        print(f"\n[*] Response: {response.decode()}")
        io.close()
```

### Phase 6: Execution

```
$ python3 exploit.py
[*] Searching for suffix where x ≡ 0 (mod P)...
[*] 1M attempts (343478/s)...
[*] 2M attempts (344521/s)...
...
[*] 10M attempts (343891/s)...
[!] FOUND in 10108778 attempts (29.4s)!
[+] Suffix: b"k<B>6N6H>s%~2hF8g/@%n/'-H@#5uGcZK~IBih02[cn*+@\\z"
[+] Verification: x mod P = 0 ✓

[+] Opening connection to candles.ctf.prgy.in on port 1337: Done
[*] Response:

Authorized 🎂
p_ctf{3l0w-tH3_c4Ndl35.h4VE=-tHe_CaK3!!}
```

---

## Attack Summary

```
┌──────────────────────────────────────────────────┐
│         CANDLES AND CRYPTO — ATTACK FLOW         │
├──────────────────────────────────────────────────┤
│                                                  │
│  1. Analyze polynomial hash:                     │
│     g(x,a,b) = x³ + ax² + bx (mod P)            │
│              = x(x² + ax + b) (mod P)            │
│                     ↓                            │
│  2. Observe: if x ≡ 0 (mod P) → h = 0           │
│                     ↓                            │
│  3. RSA: 0^e mod n = 0 → sig = 0 is valid       │
│                     ↓                            │
│  4. Brute force: find printable suffix           │
│     such that bytes_to_long(msg) ≡ 0 (mod P)     │
│                     ↓                            │
│  5. Send suffix + sig=0 → FLAG                   │
│                                                  │
└──────────────────────────────────────────────────┘
```

---

## Key Concepts and Learnings

### 1. Polynomial factorization as attack tool

The hash `g(x) = x^3 + ax^2 + bx` **has no independent term**. This allows factorization:

```
g(x) = x * (x^2 + ax + b)
```

Any multiple of modulus `P` produces hash zero. This is a fundamental design vulnerability: a secure polynomial hash should include a constant term (e.g. `g(x) = x^3 + ax^2 + bx + c`), making it impossible to force `g(x) = 0` by controlling only `x`.

### 2. RSA with hash = 0

The verification `sig^e mod n == h` with `h = 0` always passes with `sig = 0`, since `0^k = 0` for any `k > 0`. This is a degenerate case that real signature schemes prevent:

- **PKCS#1 v1.5**: Padding ensures the signed value is never 0
- **PSS**: Padding randomization prevents degenerate values
- **EdDSA**: Uses a completely different scheme

### 3. Brute force technique with partial bytes

To find a printable suffix that satisfies a modular condition:

1. **Fix high bytes** (random, printable)
2. **Calculate low bytes** (deterministic, via modular arithmetic)
3. **Verify printability** of calculated bytes

Success probability per attempt is `(95/256)^k` where `k` is the number of calculated bytes. With `k = 16`, this gives ~1.7e-7, requiring ~6M attempts (tens of seconds).

### 4. The signature oracle was a red herring

The server offers a signature (option 1) and reveals parameters `L` and `X`. This allows recovering `a` and `b`, which is useful for more complex approaches. But the optimal attack **needs neither the signature nor the parameters**, since `h = 0` works regardless of `a` and `b`.

---

## Documented Failed Attempts

These failed attempts are valuable as reference for future challenges:

1. **RSA factorization** (2048-bit `n`): We tried FactorDB, Pollard p-1 (B=10^6), Fermat, and RsaCtfTool. None succeeded — `n` was a correctly generated RSA modulus.

2. **Hash collision**: We searched for suffixes where `g(x_trans) = g(x_appr)` to reuse the signature. With `P ~ 2^128`, collision probability by linear search is negligible.

3. **Low-exponent attack**: Although `h < P < 2^128`, the exponent `e = 65537` makes `h^e >> n`, invalidating the integer e-th root attack.

4. **RSA homomorphic relation**: We tried to express `h2 = f(h1)` to exploit RSA's multiplicative property (`sig(a*b) = sig(a)*sig(b)`). The cubic polynomial doesn't produce useful multiplicative relations.

5. **Thematic suffixes** (birthday, timestamps): We tried suffixes based on the challenge story ("birthday at midnight"). None produced special hashes.

---

## References

- **RSA Signature Forgery**: [Wikipedia - RSA Digital Signatures](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Signing_messages)
- **Polynomial Hash Functions**: Vulnerable when `g(0) = 0` (no constant term)
- **PKCS#1 v1.5 / PSS**: Padding schemes that prevent degenerate signatures
- **Brute force with printable constraints**: Common CTF technique where messages need to satisfy arithmetic and format conditions simultaneously
- **Modular arithmetic for byte construction**: Given `x ≡ target (mod P)`, construct `x` byte by byte by fixing high bytes and calculating low bytes

---

## Exploit Files

- `server (1).py` — Server source code (provided)
- `public.pem` — RSA public key (provided)
- `/root/ctf/exploits/candles_crypto_exploit.py` — Final exploit (server submission)

**Flag:** `p_ctf{3l0w-tH3_c4Ndl35.h4VE=-tHe_CaK3!!}`
