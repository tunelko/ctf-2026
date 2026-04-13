# Broadcast

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | crypto                         |
| Dificultad  | Easy                           |

## Descripcion
> We sent the same announcement to three servers for redundancy. Each server has its own RSA key. Intercept all three — maybe you can piece something together.

## TL;DR
Hastad's broadcast attack con `e=3`. Los 3 ciphertexts son identicos → `m^3 < n` → cube root directo sin CRT.

## Vulnerabilidad
**CWE-327**: RSA con exponente publico `e=3` y mismo plaintext enviado a multiples recipientes. Si `m^e < n`, el cifrado es simplemente `c = m^e` (sin modular reduction), y se puede recuperar `m` con raiz cubica entera.

## Solve

```python
from Crypto.Util.number import long_to_bytes
import gmpy2

c = 475436441896018898725156479190091126537849994697426945980826369...  # same for all 3
m, exact = gmpy2.iroot(c, 3)
assert exact
print(long_to_bytes(int(m)).decode())
```

## Flag
```
kashiCTF{h4st4d_s4ys_sm4ll_3xp0n3nts_k1ll_RSA_br04dc4sts}
```

## Key Lessons
- `e=3` + small message → ciphertext IS just `m^3`, invertible with integer cube root
- Cuando los 3 ciphertexts son iguales, ni siquiera hace falta CRT — cube root directa
