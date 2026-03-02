# Secret Archive 2

**Category:** MISC
**Difficulty:** Medium
**Points:** —
**Flag:** `HackOn{act_i_d0nt_n33d_a_gf_sh3_w0uld_ru1n_my_l1fe}`

## Description

> Esta versión es mucho más segura, pero se me ha vuelto a olvidar la clave, la apunté en un papel hace unos años y bueno...

## TL;DR

A stripped ELF binary validates a key read from `private_key.txt`. The key is reversed, each character encoded as its decimal ASCII value, then compared against an XOR-obfuscated target. Recovering the key (`i_need_a_gf`) allows decryption of the flag via a second XOR layer.

## Analysis

The binary (`chall`) is a stripped PIE ELF x86-64 with two execution paths:

1. **Default (no args)**: Prints animated messages and writes hex-encoded bytes to `private_key.txt` (a red herring: just the flag prefix "Hack0n{").
2. **Validation (`./chall private_key.txt`)**: Reads the key file and validates it.

### Key Validation Logic (fcn.000015bd)

1. Read content from `private_key.txt`, strip newline
2. **Reverse** the string (fcn.000013d9)
3. **Decimal encode**: convert each character to `"%d "` format (fcn.0000130f), e.g. `'A'` → `"65 "`
4. XOR-decode a 40-byte target from `.data` at 0x40c0 using key 0x55
5. `strcmp()` the encoded result against the target
6. If match → XOR-decrypt and print the flag (fcn.0000148a)

### Recovering the Key

The XOR-decoded target string is:
```
102 103 95 97 95 100 101 101 110 95 105
```

These are ASCII codes for the **reversed** key: `fg_a_deen_i`

Reversing back: **`i_need_a_gf`**

### Flag Decryption (fcn.0000148a)

On successful validation, a hardcoded 51-byte encrypted buffer is XOR-decrypted using the original key (repeating cyclically):

```
output[i] = encrypted[i] XOR key[i % len(key)]
```

## Solution

### Steps

1. Disassemble the binary with radare2
2. Identify the two code paths (generate vs validate) in main()
3. Reverse the key validation: XOR-decode target → parse decimal ASCII → reverse string
4. Recover key: `i_need_a_gf`
5. Decrypt flag by XOR-ing the embedded 51-byte buffer with the key

### Solve Script

```python
#!/usr/bin/env python3
import struct

# XOR-decode target (40 bytes at 0x40c0 ^ 0x55)
encoded = bytes([
    0x64,0x65,0x67,0x75,0x64,0x65,0x66,0x75,
    0x6c,0x60,0x75,0x6c,0x62,0x75,0x6c,0x60,
    0x75,0x64,0x65,0x65,0x75,0x64,0x65,0x64,
    0x75,0x64,0x65,0x64,0x75,0x64,0x64,0x65,
    0x75,0x6c,0x60,0x75,0x64,0x65,0x60,0x75
])
target = bytes([b ^ 0x55 for b in encoded]).decode()
reversed_key = ''.join(chr(int(n)) for n in target.strip().split())
key = reversed_key[::-1]  # "i_need_a_gf"

# Decrypt flag from embedded buffer
buf = bytearray()
buf += struct.pack('<Q', 0x00240a2a0e0d3e21)
buf += struct.pack('<Q', 0x0b550a000039133c)
buf += struct.pack('<Q', 0x3e3602546c0f0010)
buf += struct.pack('<Q', 0x386c092c3b030231)
buf += struct.pack('<Q', 0x2a163a01022a5911)
buf += struct.pack('<Q', 0x540200100b383150)
dw = struct.pack('<I', 0x22010354)
buf[47] = dw[0]; buf.append(dw[1]); buf.append(dw[2]); buf.append(dw[3])

key_bytes = key.encode()
flag = ''.join(chr(buf[i] ^ key_bytes[i % len(key_bytes)]) for i in range(len(buf)))
print(flag)
```

## Flag

```
HackOn{act_i_d0nt_n33d_a_gf_sh3_w0uld_ru1n_my_l1fe}
```
