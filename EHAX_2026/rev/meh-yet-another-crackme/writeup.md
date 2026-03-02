# meh yet another crackme

**Category:** REV
**Flag:** `EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}`

## Description

> meh yet another crackme challenge

## TL;DR

RISC-V 64-bit statically linked crackme with 3 validation layers (XOR decode, checksum+product, custom hash). The XOR layer directly reveals the flag since all checks are consistent.

## Analysis

The binary is a stripped RISC-V 64-bit ELF, statically linked. It reads 35 bytes of input and runs 3 checks:

1. **XOR decode check**: Decodes a hardcoded 35-byte array using `data[i] ^ (i*7 mod 256) ^ 0xa5` and compares byte-by-byte against input.
2. **Structure check**: Verifies `EH4X{...}` prefix/suffix, sum of all bytes equals 0xCAB, and product of bytes at indices [5,10,15,20,25,30] mod 0x3B9ACA07 equals 0x1FB53791.
3. **Hash check**: Custom 64-bit hash (mixing with shifts, multiplies, XOR with constants 0x5851f42d4c957f2d and 0xebfa848108987eb0) must equal 0x81cf06f4a08cb5ef.

Anti-debug: timing check using a 100,000-iteration busy loop; exits if elapsed time > 0xC351.

## Solution

The XOR decode in check 1 directly reveals the flag. All other checks are redundant verifications.

```python
xor_data = [224,234,159,232,194,255,191,225,194,253,150,219,130,141,244,168,138,166,179,20,93,105,77,53,126,105,76,123,19,90,20,23,40,113,54]
decoded = []
key = 0
for b in xor_data:
    decoded.append(b ^ key ^ 0xa5)
    key = (key + 7) & 0xff
print(bytes(decoded).decode())  # EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}
```

## Flag

```
EH4X{y0u_gu3ss3d_th4t_r1sc_cr4ckm3}
```
