# jengacrypt — BSidesSF 2026 (Rev, 75pts)

## TL;DR

Bit-level permutation cipher that "Jenga-rotates" bits based on a key. Reverse all rotations in reverse order to decrypt.

## Flag

```
CTF{a-scary-teetering-algorithm}
```

## Description

We're given a stripped x86-64 ELF binary (`jengacrypt`) and an encrypted file (`encrypted.bin`, 33 bytes). The encryption command was:

```bash
cat flag.txt | ./jengacrypt take-a-block-from-the-bottom-and-put-it-on-top encrypt > encrypted.bin
```

Running with `decrypt` prints: *"Sorry! Decrypt access has been lost! You're gonna have to figure it out yourself!"*

## Analysis

The binary has 4 key functions:

| Address | Role |
|---------|------|
| `0x4010d0` | `main` — reads stdin, dispatches encrypt/decrypt |
| `0x401286` | `get_key_bit(key, key_len, index)` — returns bit from key at `index % (key_len * 8)` |
| `0x4012b7` | `rotate_bit(data, pos, total_bits)` — removes bit at `pos`, shifts remaining left, appends removed bit at end |
| `0x401369` | `encrypt(data, size_bits, key, key_len)` — main encryption loop |

### Encryption loop (`0x401369`)

The input data is treated as a flat bit array (`size_bits = len(data) * 8`). A position cursor `r14` starts at 0 and a key-bit counter `r13` starts at 0. The loop limit is `(size_bits - 1)` rounded down to a multiple of 3.

Each iteration reads one key bit (cycling through the key) and performs:

- **key_bit = 0**: `rotate(data, pos, N)` then `rotate(data, pos+1, N)`, advance `pos` by 1
- **key_bit = 1**: `rotate(data, pos+1, N)`, advance `pos` by 2

The `rotate` operation is the Jenga move: take a bit from somewhere in the middle and put it on top (end).

### Bit addressing

`get_key_bit` uses `bit_pos = (~remainder) & 7` which reverses the bit order within each byte (bit 0 of byte is the MSB, matching the natural left-to-right bit layout).

## Vulnerability (CWE-327: Use of a Broken Crypto Algorithm)

This is a pure permutation cipher — no diffusion, no substitution. Each bit in the output is just a rearranged bit from the input. Given the key, every rotation is deterministic and fully reversible.

## Exploit

The inverse of `rotate(pos)` (remove bit at `pos`, append to end) is: take the last bit, insert it at `pos`, shift everything else right.

Collect all rotation operations during forward encryption, then apply their inverses in reverse order.

```python
def get_key_bit(key_bytes, key_len, bit_index):
    key_len_bits = key_len * 8
    if key_len_bits == 0:
        return 0
    remainder = bit_index % key_len_bits
    byte_idx = remainder >> 3
    bit_pos = (~remainder) & 7
    return (key_bytes[byte_idx] >> bit_pos) & 1

def rotate_bit(bits, pos, total_bits):
    if total_bits == 0 or pos >= total_bits:
        return
    if pos >= total_bits - 1:
        pos = total_bits - 1
    saved = bits[pos]
    for i in range(pos, total_bits - 1):
        bits[i] = bits[i + 1]
    bits[total_bits - 1] = saved

def unrotate_bit(bits, pos, total_bits):
    if total_bits == 0 or pos >= total_bits:
        return
    if pos >= total_bits - 1:
        pos = total_bits - 1
    saved = bits[total_bits - 1]
    for i in range(total_bits - 1, pos, -1):
        bits[i] = bits[i - 1]
    bits[pos] = saved

def decrypt(data_bytes, key_str):
    key_bytes = key_str.encode()
    key_len = len(key_bytes)
    size_bits = len(data_bytes) * 8

    bits = []
    for b in data_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    rbp = size_bits - 1
    rbp -= rbp % 3

    # Collect forward operations
    ops = []
    r14, r13 = 0, 0
    while r14 < rbp:
        kb = get_key_bit(key_bytes, key_len, r13)
        if kb == 0:
            ops.append(r14)
            ops.append(r14 + 1)
            r14 += 1
        else:
            ops.append(r14 + 1)
            r14 += 2
        r13 += 1

    # Reverse all operations
    for pos in reversed(ops):
        unrotate_bit(bits, pos, size_bits)

    result = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        result.append(b)
    return bytes(result)

with open('encrypted.bin', 'rb') as f:
    enc = f.read()

key = "take-a-block-from-the-bottom-and-put-it-on-top"
print(decrypt(enc, key).decode())
# CTF{a-scary-teetering-algorithm}
```

## Approaches Discarded

None — straightforward reversing.

## Key Lessons

- Permutation-only ciphers are trivially reversible once the permutation sequence is known.
- The "Jenga" metaphor maps directly to the algorithm: remove a bit from the middle, place it at the end.
- When decrypt is disabled in the binary, just reverse-engineer encrypt and invert it.
