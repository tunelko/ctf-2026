# LH | RH — upCTF 2026

**Category:** Crypto (RSA / Algebraic Factorization)
**Flag:** `upCTF{H0p3_y0u_d1dnt_us3_41_1_sw3ar_th1s_1s_n1ce...If you are CR7 and you solved this, I love you}`

## TL;DR

RSA where `q` is the decimal rotation of `p`: `p = L||R`, `q = R||L` (each half is 143 digits). The algebraic relation `n = LR·(T-1)² + T·S²` (with `T = 10¹⁴³`, `S = L+R`) allows solving for `S` via modular square root, and then recovering `L`,`R` with a quadratic equation.

---

## Analysis

### Key Generation

```python
CR7 = 143
p = getPrime(948)                              # 286 decimal digits
q = int(str(p)[CR7:] + str(p)[:CR7])           # rotation: R||L
# q must be prime and 286 digits long
```

`p` is split into:
- **L** = first 143 decimal digits
- **R** = last 143 decimal digits

Therefore: `p = L||R`, `q = R||L`.

### Data

```
n = 131847774950810081363787...68406683  (572 digits)
e = 65537
c = 249577568143078299236272...8548661
```

---

## Mathematics

### Formalization

Let `T = 10¹⁴³`:

```
p = L·T + R
q = R·T + L
```

### Expansion of n

```
n = p·q = (LT + R)(RT + L)
        = LR·T² + L² + R²·T + ...
```

Expanding fully:

```
n = LR·T² + L²·T + R²·T + LR
  = LR·(T² + 1) + T·(L² + R²)
```

Using `L² + R² = (L+R)² - 2LR`:

```
n = LR·(T² + 1) + T·((L+R)² - 2LR)
  = LR·(T² + 1 - 2T) + T·(L+R)²
  = LR·(T-1)² + T·S²
```

where **S = L + R**.

### Solving for S

Isolating `LR`:

```
LR = (n - T·S²) / (T-1)²
```

For `LR` to be an integer: `(T-1)² | (n - T·S²)`, that is:

```
T·S² ≡ n  mod (T-1)²
S² ≡ n·T⁻¹  mod (T-1)²
```

We compute `target = n·T⁻¹ mod (T-1)²`. Since `S ~ 10¹⁴³` and `(T-1)² ~ 10²⁸⁶`, we have `S² / (T-1)² ∈ {0,1,2,3,...}`, so:

```
S² = target + k·(T-1)²    for k = 0, 1, 2, ...
```

We try each `k` until we find a perfect square. **Found at k=1.**

### Recovering L, R

With `S` and `LR` known, `L` and `R` are roots of:

```
x² - S·x + LR = 0
```

```
Discriminant = S² - 4·LR  (perfect square ✓)
L = (S + √D) / 2
R = (S - √D) / 2
```

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
import gmpy2
from Crypto.Util.number import long_to_bytes

n = 131847...406683  # (truncated)
e = 65537
c = 249577...548661  # (truncated)

T = 10**143
T1sq = (T - 1) ** 2

# S² ≡ n·T⁻¹ mod (T-1)²
target = (n * pow(T, -1, T1sq)) % T1sq

for k in range(10):
    s, exact = gmpy2.iroot(target + k * T1sq, 2)
    if exact:
        S = int(s)
        LR = (n - T * S**2) // T1sq
        disc, exact_d = gmpy2.iroot(S**2 - 4 * LR, 2)
        if exact_d:
            L = (S + int(disc)) // 2
            R = (S - int(disc)) // 2
            p = L * T + R
            q = R * T + L
            assert p * q == n
            d = pow(e, -1, (p-1)*(q-1))
            print(long_to_bytes(pow(c, d, n)).decode())
            break
```

```
$ python3 solve.py
upCTF{H0p3_y0u_d1dnt_us3_41_1_sw3ar_th1s_1s_n1ce...If you are CR7 and you solved this, I love you}
```

### Intermediate Values

```
S = L + R = 110829140066465106636516860897167921417015459910175772481803204826399216196215749580333675252974768724877589637635138851576557297180466718613956
L = 97275014637416280164243208153387038564687178010864756461604456150371992870896601636956965832389802334466211420957229444574008481706334656644879
R = 13554125429048826472273652743780882852328281899311016020198748676027223325319147943376709420584966390411378216677909407002548815474132061969077
```

---

## Key Lessons

1. **Algebraic relations between primes**: when `p` and `q` are derived from each other (rotation, reflection, etc.), the relationship introduces exploitable structure in `n`
2. **Reduction to modular square root**: the identity `n = LR·(T-1)² + T·S²` reduces the factorization to finding a modular square root + solving a quadratic equation
3. **Small k**: `S² = target + k·(T-1)²` with `k` bounded by `S²/(T-1)² < 5`, so at most ~5 attempts suffice
4. **Do not use generic factorizers**: the algebraic structure allows factoring in milliseconds what Fermat or GNFS could not solve in reasonable time for 948-bit primes

## References

- [Number Theory for RSA Challenges](https://crypto.stackexchange.com/questions/tagged/rsa)
- [Integer Factorization via Algebraic Relations](https://en.wikipedia.org/wiki/Integer_factorization)
