# Deep-Space Transmission

## Challenge Info
- **Category**: Crypto
- **Competition**: UniVsThreats 2026 Quals
- **Flag**: `UVT{0rb1t4l_c0ngru3nc3_m4k35_pr3d1ct4ble_k3y5}`

## Analysis

The encryption scheme chains multiple crypto primitives:

1. **Epoch derivation**: SHA-256 hash of `HH:MM:SS` → first 16 hex chars = `epoch_hash`
2. **LCG parameters**: Position of Halley's comet at the epoch time (via Skyfield) → SHA-512 hashes give `a` and `b`
3. **Truncated LCG**: 512-bit state, outputs top 192 bits at non-consecutive steps [0, 4, 10, 18, 28]
4. **AES-CBC encryption**: Key = SHA-256(final_state after step 29)
5. **DSA signatures**: TAP protocol signs each telemetry value with DSA (RFC 5114 params), **same nonce k** for all

## Vulnerabilities

### 1. Epoch time bruteforce (86,400 combinations)
Date is known (2026-01-26), only H:M:S unknown. SHA-256 prefix comparison → found `04:12:55` instantly.

### 2. DSA nonce reuse (bonus, not needed)
All 5 signatures share the same `r` value → same `k` nonce. This leaks the DSA private key `x_tap`, but TAP signatures are a red herring for flag recovery.

### 3. Truncated LCG → Lattice CVP
The core vulnerability. Given 5 truncated outputs (192 of 512 bits), recover the full state using a lattice attack.

**Setup**: State at step `i`: `s_i = A_i * s_0 + B_i mod p`, where `A_i = a^i`, `B_i = b*(a^i - 1)/(a-1) mod p`.
Each observation: `t_i = s_i >> 320`, so `s_i = t_i * 2^320 + e_i` with `0 ≤ e_i < 2^320`.

Eliminating `s_0` via step 0 gives 4 relations: `A_i * e_0 - e_i ≡ c_i (mod p)`.

**Lattice (Kannan CVP embedding)**:
```
[ p  0  0  0  0  0 ]
[ 0  p  0  0  0  0 ]
[ 0  0  p  0  0  0 ]
[ 0  0  0  p  0  0 ]
[A1 A2 A3 A4  1  0 ]
[c1 c2 c3 c4  0  1 ]
```

After LLL, the row with last element ±1 gives `(-e_1, -e_2, -e_3, -e_4, -e_0, 1)`, recovering all error terms.

**Feasibility**: Error vectors are 320 bits, lattice determinant ~p^4 ≈ 2^2048, expected shortest vector ~2^341 > 2^320. LLL is sufficient.

## Exploitation Steps

1. Bruteforce `epoch_hash` → `04:12:55`
2. Compute Halley's comet position at 2026-01-26 04:12:55 UTC → derive `a, b`
3. Build 6×6 Kannan lattice from truncated LCG relations
4. LLL reduction → recover `e_0` → reconstruct `s_0`
5. Advance LCG to step 29 → `final_state`
6. AES key = SHA-256(final_state) → decrypt flag

## Exploit Script (solve.py)

```python
#!/usr/bin/env python3
"""Deep-Space Transmission - Truncated LCG lattice attack"""
import hashlib, os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from fpylll import IntegerMatrix, LLL

def find_epoch_time(target_hash):
    for h in range(24):
        for m in range(60):
            for s in range(60):
                if hashlib.sha256(f"{h:02d}:{m:02d}:{s:02d}".encode()).hexdigest()[:16] == target_hash:
                    return h, m, s

def derive_ab(year, month, day, hour, minute, second):
    from skyfield.api import load
    from skyfield.data import mpc
    from skyfield.constants import GM_SUN_Pitjeva_2005_km3_s2 as GM_SUN
    with load.open('CometEls.txt') as f:
        comets = mpc.load_comets_dataframe(f).set_index('designation', drop=False)
    row = comets.loc['1P/Halley']
    ts = load.timescale()
    t = ts.utc(year, month, day, hour, minute, second)
    sun = load('de421.bsp')['sun']
    halley = sun + mpc.comet_orbit(row, ts, GM_SUN)
    x, y, z = sun.at(t).observe(halley).position.au
    coord = f"{x:.10f}_{y:.10f}_{z:.10f}"
    return bytes_to_long(hashlib.sha512((coord+"_A").encode()).digest()), \
           bytes_to_long(hashlib.sha512((coord+"_B").encode()).digest())

def solve_truncated_lcg(a, b, p, steps, t_vals, U):
    two_U = 1 << U
    a_inv_m1 = pow(a - 1, -1, p)
    def compose(n):
        A = pow(a, n, p); return A, (b * (A - 1) * a_inv_m1) % p
    n = len(steps) - 1
    coeffs, constants = [], []
    for i in range(1, n + 1):
        A_i, B_i = compose(steps[i])
        coeffs.append(A_i)
        constants.append((t_vals[i]*two_U - A_i*t_vals[0]*two_U - B_i) % p)
    dim = n + 2
    M = IntegerMatrix(dim, dim)
    for i in range(n): M[i, i] = p
    for i in range(n): M[n, i] = coeffs[i]
    M[n, n] = 1
    for i in range(n): M[n+1, i] = constants[i]
    M[n+1, n+1] = 1
    LLL.reduction(M)
    for i in range(dim):
        row = [M[i, j] for j in range(dim)]
        if abs(row[n+1]) == 1:
            e_0 = -row[n+1] * row[n]
            if 0 <= e_0 < two_U:
                s_0 = (t_vals[0]*two_U + e_0) % p
                if all(((compose(steps[j])[0]*s_0+compose(steps[j])[1])%p)>>U == t_vals[j]
                       for j in range(len(steps))):
                    return s_0, compose

# Challenge data
epoch_hash = "8b156702c993b9b5"
p = 10035410270612815279389330410121900529620495869479898461384631211745452304638984576440553552006414411373806160282016417372459090604747980402493134112626213
t_vals = [1129223615711367884405014640005288172041367198689786688285,
          579514026315281536883405991880758556036404753274817543322,
          1279648546218423539959079224022586160480305721841176089544,
          1946366015289015629063708515503091199628321083313573104031,
          3902208990133988884490762855871313599751888895643028675415]
iv = bytes.fromhex("ba04a327ffd0c69205ff5dcb5f463d9c")
ct = bytes.fromhex("1879e4d0f174c9a6d2be99b6f632cc0f3ea89989e69dbd080761cb616b37d8eba37635de6c6475d741f69450c8259590")

hour, minute, second = find_epoch_time(epoch_hash)
a, b = derive_ab(2026, 1, 26, hour, minute, second)
s_0, compose = solve_truncated_lcg(a, b, p, [0,4,10,18,28], t_vals, 320)
A_29, B_29 = compose(29)
final_state = (A_29 * s_0 + B_29) % p
aes_key = hashlib.sha256(long_to_bytes(final_state)).digest()
flag = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
print(f"FLAG: {flag.decode()}")
```

## Other Files
- `encrypt.py` — Original challenge code

## Key Takeaways
- Truncated LCGs are classically broken by lattice reduction (Frieze et al., Stern)
- 192/512 = 37.5% of bits known, with 5 samples → plenty for CVP
- Non-consecutive steps don't add security, just require composing the LCG multiplier
- DSA nonce reuse is a distraction (though it leaks the signing key)
- Astronomically-derived keys sound cool but are deterministic once the time is known
