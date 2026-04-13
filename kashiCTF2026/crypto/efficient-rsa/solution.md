# Efficient RSA (Generating Primes)

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | KashiCTF 2026                  |
| Categoría   | crypto                         |
| Dificultad  | Easy/Medium                    |
| Puntos      | 100                            |
| Autor       | 1C3_B34R                       |

## Descripcion
> Generating primes is expensive. I optimized my key generation to be twice as fast. The modulus is 4096 bits — perfectly secure.

## TL;DR
RSA con `n = p²` (un solo primo reutilizado). `isqrt(n)` recupera `p`, `phi(p²) = p*(p-1)`, decrypt RSA → AES key → flag.

## Analisis inicial

```bash
$ cat output.txt
schema_version = 3
key_bits       = 4096
n_hash         = 4fcafa2a...

n  = 0x752a94a1...  (4096 bits)
e  = 65537

ct  = MVoAMG4K...  (base64, RSA ciphertext)
iv  = XSCnpZLyN1Oin7F67hOKWQ==
flag_ct = n+H1n3ez...  (AES-CBC encrypted flag)
ct2 = 40441400...  (auxiliary, unused)
```

Estructura: RSA encrypts AES key → AES-CBC encrypts flag.

## Vulnerabilidad identificada

**CWE-326: Inadequate Encryption Strength** — RSA key generation reutiliza el mismo primo: `n = p * p`.

La pista es clara: *"optimized my key generation to be twice as fast"* = generar **un** primo en lugar de dos.

### Verificacion

```python
p = gmpy2.isqrt(n)
assert p * p == n  # ✓ n es cuadrado perfecto
# p tiene 2048 bits
```

## Proceso de resolucion

### Paso 1: Factorizar n

```python
import gmpy2
p = gmpy2.isqrt(n)
assert p * p == n
```

`isqrt` es O(log n) — instantáneo.

### Paso 2: Calcular phi y clave privada

Para `n = p²`, la función de Euler es:

```
phi(p²) = p² - p = p*(p-1)
```

**Nota**: NO es `(p-1)²`. La fórmula general para potencias de primos es `phi(p^k) = p^(k-1) * (p-1)`.

```python
phi = int(p) * (int(p) - 1)
d = inverse(e, phi)
```

### Paso 3: Decrypt RSA → AES key

```python
ct_bytes = base64.b64decode(ct_b64)
ct_int = int.from_bytes(ct_bytes, 'big')
pt_int = pow(ct_int, d, n)
pt_bytes = long_to_bytes(pt_int)
# Sin padding PKCS#1 → directamente 16 bytes AES key
# aes_key = 3a59a95d070450f5f1c070743cc7aa37
```

### Paso 4: Decrypt AES-CBC → flag

```python
iv = base64.b64decode("XSCnpZLyN1Oin7F67hOKWQ==")
flag_ct = base64.b64decode("n+H1n3ez...")
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
flag = cipher.decrypt(flag_ct)  # + strip PKCS7 padding
```

## Exploit final

```python
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import AES
import base64, gmpy2

p = gmpy2.isqrt(n)
phi = int(p) * (int(p) - 1)
d = inverse(e, phi)

ct_int = int.from_bytes(base64.b64decode(ct_b64), 'big')
aes_key = long_to_bytes(pow(ct_int, d, n))

iv = base64.b64decode("XSCnpZLyN1Oin7F67hOKWQ==")
flag_ct = base64.b64decode("n+H1n3ez...")
flag = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(flag_ct)
flag = flag[:-flag[-1]]  # PKCS7 unpad
```

## Flag
```
kashiCTF{wh3n_0n3_pr1m3_1s_n0t_3n0ugh_p_squared_1s_w0rs3}
```

## Key Lessons
- "Twice as fast" key generation = un solo primo → `n = p²`, factorizable con `isqrt`
- `phi(p²) = p*(p-1)`, NOT `(p-1)²`
- Hybrid RSA+AES es patrón común en CTFs: RSA protege la clave simétrica, AES protege el flag
- `ct2` (auxiliary ciphertext) fue un red herring — no necesario para la solución
