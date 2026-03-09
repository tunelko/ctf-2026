# Árvore Genealógica — upCTF 2026

**Category:** Crypto (RSA)
**Flag:** `upCTF{0_m33s1_é_p3qu3n1n0-NabVBQub6d93ced9}`

## TL;DR

RSA with a weak prime: `p = 2^777 - 85839`. An interactive family tree gives clues distributed among family members that point to searching for a prime factor near `2^777` with a distance less than 100000. Decrypting the RSA yields a code that is sent to the "bank" API to obtain the flag.

---

## Analysis

### Reconnaissance

Web page at `http://46.225.117.62:30002/` with a family tree of "Papi Cris" (CR7). Each family member has data and information. A second page (`banco.html`) accepts a secret code via `POST /api/verify-code`.

### RSA Data (Papi Cris)

```
n = 62588453799692202130100034143393250692737558576552488033940824429938816661660797018...203307
e = 0x10001
c = 62318722105864475633070267247974102130492586860223395750014121141640728228140922787...113502
```

`n` is 1554 bits long — product of two primes of ~777 bits.

### Key Clues

| Family member | Clue | Interpretation |
|----------|-------|----------------|
| **Primo Ricardo** (The Mathematician) | "número da sorte 777, perto de 2\*\*777" | One prime factor is close to `2^777` |
| **Prima Sofia** (The Researcher) | "até 100000 era perto" + "descobrir um que o outro é óbvio" | The distance to the prime is < 100000. Finding one gives `q = n/p` |

### Discarded Clues

| Family member | Data | Reason |
|----------|------|--------|
| Irmão Rafinha | `Fortnite_Pass = 'f1e2d3c4b5a69788796a5b4c3d2e1f0a9'` | Does not divide `n`, not used in decryption |
| Avó Bastarda | "Roubou 2€" | Narrative with no cryptographic value |

---

## Exploit

### Factorization

Descending search from `2^777`, testing primes that divide `n`:

```python
import gmpy2

base = gmpy2.mpz(2)**777
candidate = base
for k in range(100001):
    if gmpy2.is_prime(candidate):
        if gmpy2.mpz(n) % candidate == 0:
            p = int(candidate)  # found at k = 85839
            break
    candidate -= 1

q = n // p
```

**Result:** `p = 2^777 - 85839` (found at ~85839 iterations, <1 second)

### RSA Decryption

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
code = long_to_bytes(m).decode()
# → "S3cr3t_to_p4pis_f0rtune"
```

### Obtaining the Flag

```bash
curl -X POST http://46.225.117.62:30002/api/verify-code \
  -H 'Content-Type: application/json' \
  -d '{"code":"S3cr3t_to_p4pis_f0rtune"}'
```

```json
{
  "success": true,
  "flag": "upCTF{0_m33s1_é_p3qu3n1n0-NabVBQub6d93ced9}",
  "message": "Bem-vindo ao seu cofre secreto, papi cris!"
}
```

---

## solve.py

```python
#!/usr/bin/env python3
import gmpy2
from Crypto.Util.number import long_to_bytes

n = 6258845379969220213...203307  # (truncated)
e = 0x10001
c = 6231872210586447563...113502  # (truncated)

# Factor: p near 2^777, within 100000
base = gmpy2.mpz(2)**777
candidate = base
for k in range(100001):
    if gmpy2.is_prime(candidate) and gmpy2.mpz(n) % candidate == 0:
        p = int(candidate)
        break
    candidate -= 1

q = n // p
d = pow(e, -1, (p-1)*(q-1))
code = long_to_bytes(pow(c, d, n)).decode()
print(f"Code: {code}")  # S3cr3t_to_p4pis_f0rtune
# Submit to /api/verify-code for flag
```

---

## Key Lessons

1. **Primes close to powers of 2**: choosing RSA primes of the form `2^k ± δ` with small `δ` is fatal — a linear search from `2^k` is trivial
2. **Distributed clues**: the necessary information was spread across multiple nodes of the family tree — "primos" (cousins/primes) is the double meaning in Portuguese that gives the challenge its name
3. **Red herrings**: the `Fortnite_Pass` and other family data do not contribute to the attack — filtering signal from noise is part of the challenge
4. **Two-step verification**: decrypting RSA only yields an intermediate code; the real flag is obtained via the API — simulating a more realistic scenario

## References

- [RSA with weak primes — FactHacks](https://facthacks.cr.yp.to/)
- [Fermat's factorization method](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
