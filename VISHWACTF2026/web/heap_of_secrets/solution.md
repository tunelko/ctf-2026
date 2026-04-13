# Heap of Secrets — VishwaCTF 2026

| Field | Value |
|-------|-------|
| Category | Web |
| URL | `https://heap.vishwactf.com/` |
| Flag | `VishwaCTF{h34p_5n4p5h0t_1s_D3ep_M3m0ry}` |

## TL;DR

Flag is XOR-decoded from `/api/init` response and stored in a JS heap object. Read the client-side JS to find the decode logic: `trace_vector[i] ^ session_seed`.

## Analysis

The page is a fake "NodeWatch" telemetry dashboard. The hint says the flag is "already in your browser" and to "take a snapshot" — referring to Chrome DevTools heap snapshots.

The inline JavaScript reveals the flow:

```javascript
async function initSession() {
  const res  = await fetch("/api/init");
  const data = await res.json();

  const key     = data.session_seed;           // XOR key
  const decoded = data.trace_vector.map(b => b ^ key);  // decode
  const token   = decoded.map(c => String.fromCharCode(c)).join("");

  const session = new SessionContext(...);
  session.license_token = token;  // flag stored here in heap
  // ...
}
```

`/api/init` returns:
```json
{"session_seed": 72, "trace_vector": [30,33,59,32,...], ...}
```

The flag is `trace_vector` XOR'd with `session_seed`, stored as `license_token` in a `SessionContext` object on the JS heap.

## Solution

```python
import requests
data = requests.get("https://heap.vishwactf.com/api/init").json()
flag = ''.join(chr(b ^ data['session_seed']) for b in data['trace_vector'])
print(flag)
```

## Intended Path (Heap Snapshot)

1. Open the page in Chrome
2. DevTools → Memory → Take heap snapshot
3. Search for `SessionContext` or `license_token`
4. Read the decoded flag string from the retained object

## Key Lessons

- Secrets decoded client-side are never secret — they live in the JS heap
- Chrome heap snapshots expose all allocated JS objects including "hidden" strings
- Reading the source code is faster than taking snapshots
