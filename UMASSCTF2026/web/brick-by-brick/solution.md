# Brick by Brick — UMassCTF 2026 (WEB)

## TL;DR
robots.txt → internal docs → LFI via `?file=` parameter → read dashboard source → flag in PHP define.

## Steps
1. `robots.txt` reveals `/internal-docs/` with 3 documents
2. `it-onboarding.txt` says: use `?file=` parameter, admin creds in `config.php`
3. LFI: `/?file=config.php` → reveals DB creds, admin dashboard at `/dashboard-admin.php`
4. LFI: `/?file=dashboard-admin.php` → reads PHP source, flag hardcoded as `define('FLAG', '...')`

## Flag
```
UMASS{4lw4ys_ch4ng3_d3f4ult_cr3d3nt14ls}
```
