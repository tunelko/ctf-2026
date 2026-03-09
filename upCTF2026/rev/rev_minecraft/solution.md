# Minecraft Enterprise — upCTF 2026

**Category:** Reversing (Keygen)
**Flag:** `upCTF{m1n3cr4ft_0n_th3_b4nks-QEbqBNzJ0f64bd0c}`

## TL;DR

License key validator: parses `XXXXX-XXXXX-XXXXX-XXXXX`, permutes the 20 chars (swap halves + swap adjacent pairs), then verifies that `HMAC-SHA256("IMNOTTHEKEY", first_10_permuted)` base32-encoded equals the last 10 permuted chars. Keygen: choose any first half, compute expected second half, reverse the permutation.

---

## Analysis

### Binary

```
ELF 64-bit, statically linked, stripped, no PIE, no canary
5.1 MB — includes OpenSSL (HMAC, SHA256) statically linked
```

### Key Format

```
XXXXX-XXXXX-XXXXX-XXXXX
23 chars total: 20 alphanumeric + 3 dashes at positions 6, 12, 18
All chars converted to uppercase during parsing
```

### Validation Pipeline

```
Input: p[0..19] (20 chars after removing dashes)
         ↓
[1] Permute:
    Step 1: swap first 10 ↔ last 10
    Step 2: swap each adjacent pair (0↔1, 2↔3, ...)
    Result: permuted[0..9]  = p11 p10 p13 p12 p15 p14 p17 p16 p19 p18
            permuted[10..19] = p1  p0  p3  p2  p5  p4  p7  p6  p9  p8
         ↓
[2] HMAC-SHA256(key="IMNOTTHEKEY", data=permuted[0..9])
         ↓
[3] Take first 7 bytes → big-endian uint56 → >>6 → 50 bits
         ↓
[4] Base32 encode (A-Z, 2-7) → 10 chars (MSB first)
         ↓
[5] strncmp(base32_result, permuted[10..19], 10) == 0 → VALID
```

### Key Observations

- The AES S-box at `0x7e24c0` is used in a seed computation loop (64 iterations) but the seed (`0x12345678` transformed) is never actually used for validation — it's a red herring/dead code
- The checksum loop `sum(i² % 13 for i in range(24))` = 151, also unused
- The actual validation is purely: HMAC first half → base32 == second half
- `"IMNOTTHEKEY"` string at `0x7c002e` — both the HMAC key and a hint

---

## Keygen

```python
import hmac, hashlib

BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def compute_second_half(first10):
    h = hmac.new(b"IMNOTTHEKEY", first10.encode(), hashlib.sha256).digest()
    val = int.from_bytes(h[:7], 'big') >> 6  # 50 bits
    result = [''] * 10
    for i in range(9, -1, -1):  # binary writes backwards
        result[i] = BASE32[val & 0x1f]
        val >>= 5
    return ''.join(result)

# Choose any first half for the permuted key
first_half = "AAAAAAAAAA"
second_half = compute_second_half(first_half)

# Reverse permutation
permuted = list(first_half + second_half)
for i in range(0, 20, 2):
    permuted[i], permuted[i+1] = permuted[i+1], permuted[i]
original = permuted[10:] + permuted[:10]

k = ''.join(original)
key = f"{k[0:5]}-{k[5:10]}-{k[10:15]}-{k[15:20]}"
# → C34X3-6THXM-AAAAA-AAAAA
```

```
$ echo "C34X3-6THXM-AAAAA-AAAAA" | nc 46.225.117.62 30023
Enter Key (format: XXXXX-XXXXX-XXXXX-XXXXX): Flag: upCTF{m1n3cr4ft_0n_th3_b4nks-QEbqBNzJ0f64bd0c}
```

---

## Key Lessons

1. **HMAC as license check**: the second half of the key is a truncated HMAC of the first half — common in software licensing schemes
2. **Red herrings in reversing**: the AES S-box loop and checksum computation are dead code designed to waste time
3. **Base32 encoding direction matters**: the binary writes base32 chars from position 9→0, extracting LSBs first — getting this wrong reverses the output
4. **GDB for empirical verification**: comparing HMAC output in GDB vs Python instantly confirmed the algorithm (SHA256) and caught the encoding direction bug

## References

- [HMAC-SHA256 in software licensing](https://en.wikipedia.org/wiki/HMAC)
- [RFC 4648 — Base32 Encoding](https://tools.ietf.org/html/rfc4648)
