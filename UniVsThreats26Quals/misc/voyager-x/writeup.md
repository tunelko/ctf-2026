# Voyager's Last Command

**Category:** CRYPTO
**Flag:** `UVT{v0y4g3r_s1gn3d_1t5_0wn_d34th}`

## Description

> Year 2387. You have established an uplink to the Voyager-X probe via an emergency telemetry relay. The probe's PRNG has suffered a fault.

## TL;DR

ECDSA on secp256k1 with LCG-generated nonces (known multiplier `a`, unknown offset `b`). 3 signatures eliminate `b` and yield a linear equation in the private key `d`.

## Analysis

The oracle provides:
- secp256k1 curve, LCG multiplier `a`, public key `Q`, AES-128-ECB encrypted flag
- Up to 3 ECDSA signatures on chosen messages
- AES key = `SHA-256(d, big-endian)[:16]`

Nonces follow: `k_{i+1} = a * k_i + b (mod n)`

From ECDSA: `k_i = s_i^{-1} * (z_i + r_i * d) mod n`

The LCG gives us `k3 - a*k2 = k2 - a*k1` (both equal `b`), so:

`k3 - (a+1)*k2 + a*k1 = 0 mod n`

Substituting `k_i = e_i + c_i * d` where `c_i = s_i^{-1} * r_i` and `e_i = s_i^{-1} * z_i`:

`d = -(e3 - (a+1)*e2 + a*e1) / (c3 - (a+1)*c2 + a*c1) mod n`

## Solution

```bash
pip install ecdsa pycryptodome --break-system-packages
python3 solve.py
```

## Flag

```
UVT{v0y4g3r_s1gn3d_1t5_0wn_d34th}
```
