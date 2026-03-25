# randcrypt — BSidesSF CTF 2026

| Field | Value |
|-------|-------|
| **Category** | Crypto |
| **Points** | 856 |
| **Author** | symmetric |
| **Flag** | `CTF{antirng_is_rng_backwards_in_time}` |

## Description

> Everyone knows key management is the hardest part of encryption. That's why we've switched to randomized keys to thwart an entire class of attacks!

We're given `randcrypt.c` (the encryption source code) and `flag.jxl.enc` (147600 bytes).

## TL;DR

The encryption appends an EOF block that leaks the PRNG state in the clear. Since the custom PRNG (`rng_next`) is a bijection, we invert it step-by-step to recover the full keystream and decrypt the file.

## Analysis

### Encryption Scheme

`randcrypt.c` implements a stream cipher:

1. **Key**: 128-bit random from `/dev/urandom` (unknown to us)
2. **PRNG**: `state = rng_next(key)`, then `state = rng_next(state)` for each block
3. **Encryption**: `ciphertext_block = plaintext_block XOR state`
4. **EOF handling**: after all data, reads one more block (gets 0 bytes → block = 0), XORs with state, writes it
5. **Length block**: writes `total_len XOR next_state` as final block

### The PRNG: `rng_next`

Four rounds of xorshift + multiply + add on 128-bit values:

```c
// Each round:
x = (x << shift) ^ x;      // xorshift (invertible)
x *= odd_constant;           // multiplication mod 2^128 (invertible)
x += constant;               // addition mod 2^128 (invertible)
```

Shifts: 7 (left), 13 (right), 19 (left), 23 (right). All operations are **bijections** on Z/2^128.

## Vulnerability: EOF Block Leaks State

The critical flaw is in the EOF handling (line 206):

```c
block ^= state;  // block = 0 (from empty EOF read), so output = state!
```

When `fread` returns 0 at EOF, the buffer is zeroed (`memset(buf, 0, 16)`), so `block = 0`. XORing with `state` gives `0 XOR state = state` — the **raw PRNG state is written to the ciphertext**.

The EOF block is the **second-to-last** 16-byte block in the encrypted file:
- `enc[-32:-16]` = state at position N+1 (EOF block)
- `enc[-16:]` = total_len XOR state at position N+2 (length block)

## Exploitation

### Step 1: Extract State and Length

```python
state_eof = int.from_bytes(enc[-32:-16], 'big')  # 0xeb8bcd4a015b8f2bb6fca5efaaf0dcec
state_len = rng_next(state_eof)
total_len = int.from_bytes(enc[-16:], 'big') ^ state_len  # 147557
```

### Step 2: Invert the PRNG

Each operation in `rng_next` has a mathematical inverse:

| Forward | Inverse |
|---------|---------|
| `x = (x << k) ^ x` | Iterative: recover low bits first, compute shifted, XOR back |
| `x = (x >> k) ^ x` | Iterative: recover high bits first |
| `x *= c` | `x *= c^(-1) mod 2^128` (exists because c is odd) |
| `x += c` | `x -= c` |

```python
def rng_prev(state):
    x = state
    # Undo Round 4 (reverse order)
    x = (x - c4_add) % 2**128
    x = (x * c4_mul_inv) % 2**128
    x = inv_xor_rshift(x, 23)
    # Undo Rounds 3, 2, 1 similarly...
    return x
```

Verification: `rng_prev(rng_next(x)) == x` for all x.

### Step 3: Walk Back to State 1

The encryption uses states 1 through 9224 (for 9223 data blocks + 1 EOF block). Walk back 9223 steps:

```python
state = state_eof  # state_9224
for i in range(9223):
    state = rng_prev(state)
# state is now state_1
```

### Step 4: Decrypt

```python
state = state_1
for each 16-byte block in enc[:-32]:  # exclude EOF and length blocks
    plaintext_block = enc_block XOR state
    state = rng_next(state)
truncate(plaintext, total_len)  # 147557 bytes
```

Result: valid JPEG XL codestream containing the flag image.

## Key Takeaways

- **Bijective PRNGs are invertible**: xorshift, multiply-by-odd, and add are all bijections on Z/2^n. Combining bijections gives a bijection. "Cryptographic quality" claims don't make a non-cryptographic construction secure
- **XOR with zero leaks state**: the EOF handling XORs a zero block with the PRNG state, writing the raw state to the output — a fatal information leak
- **One leaked state breaks everything**: since the PRNG is invertible, a single known state allows computing ALL past and future states
- **Length authentication doesn't help**: the length block uses XOR with the next state, which is computable from the leaked state

## Exploit Code

```python
def rng_next(state):
    x = state
    M = (1 << 128) - 1
    x = ((x << 7) ^ x) & M
    x = (x * 0xc7d966554fdd88952bd67b67587a550d) & M
    x = (x + 0xaad7d93a4256e8156b2b70757a011d80) & M
    # ... rounds 2-4 similarly
    return x

def rng_prev(state):
    # Reverse round 4, 3, 2, 1
    # Subtract constant, multiply by modular inverse, invert xorshift
    ...

# Extract leaked state from EOF block
state_eof = int.from_bytes(enc[-32:-16], 'big')
total_len = int.from_bytes(enc[-16:], 'big') ^ rng_next(state_eof)

# Walk back to state_1
state = state_eof
for _ in range(9223):
    state = rng_prev(state)

# Decrypt all blocks
state_1 = state
plaintext = decrypt_blocks(enc[:-32], state_1)[:total_len]
# → valid flag.jxl with flag image
```

## Files

- `randcrypt.c` — encryption source code
- `flag.jxl.enc` — encrypted file (147600 bytes)
- `flag.jxl` — decrypted JPEG XL (147557 bytes)
- `flag_decoded.png` — converted flag image
- `randcrypt_flag.txt` — `CTF{antirng_is_rng_backwards_in_time}`
