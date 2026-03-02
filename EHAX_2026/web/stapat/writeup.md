# Stapat

**Category:** WEB
**Flag:** `EH4X{1_h4v3_4ll_th3_c3t1f1c4t35}`

## Description

> https://stapat.xyz/

## TL;DR

The main page says "Please visit our stores". Testing alternative vhosts with `Host: store.stapat.xyz` returns the flag directly as plain text (32 bytes).

## Analysis

- The main page (`stapat.xyz`) is a pink landing page with "Welcome bby" and "Please visit our stores" — a hint to search for a `store` vhost.
- Nginx returns different responses depending on the `Host` header:
  - `www.stapat.xyz` → the HTML landing page (1164 bytes)
  - `store.stapat.xyz` → plain text with the flag (32 bytes)
  - Any other random subdomain → also the flag (wildcard catch-all of the default vhost)
- DNS wildcard `*.stapat.xyz` resolves to the same IP (`40.81.242.97`).
- The nginx version on the landing page (`1.24.0`) differs from the 404s of the default server (`1.29.5`), which confirms multiple server blocks.

## Solution

```bash
curl -H "Host: store.stapat.xyz" https://stapat.xyz/
# EH4X{1_h4v3_4ll_th3_c3t1f1c4t35}
```

## Flag

```
EH4X{1_h4v3_4ll_th3_c3t1f1c4t35}
```
