# BrOWSER Boss Fight — UMassCTF 2026 (WEB)

## TL;DR
Multi-step web challenge: bypass client-side JS, find key in Server header, set cookie to defeat Bowser.

## Steps
1. Homepage has a door/key form. JS replaces any input with "WEAK_NON_KOOPA_KNOCK" → bypass with curl
2. Server header reveals: `"King Koopa, if you forget the key, check under_the_doormat!"`
3. POST `key=under_the_doormat` → redirects to `/bowsers_castle.html` (need session cookie)
4. Castle says "I removed the axe!" → set cookie `hasAxe=true`
5. Request castle page with `hasAxe=true` cookie → victory page with flag

```bash
curl -c cookies -X POST http://HOST/password-attempt -d "key=under_the_doormat"
curl -b cookies -b "hasAxe=true" http://HOST/bowsers_castle.html
```

## Flag
```
UMASS{br0k3n_1n_2_b0wz3r5_c4st13}
```
