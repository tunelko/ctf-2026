#!/usr/bin/env python3
"""ghostcrypt: Polybius cipher on Stranger Things alphabet wall"""
import requests
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://ghostcrypt-CHANGEME.challenges.bsidessf.net"

# Get the encrypted flag from summon litany endpoint
r = requests.get(f"{BASE}/summon")
data = r.json() if r.headers.get('content-type','').startswith('application/json') else {'litany': r.text}
encrypted = data.get('litany', data.get('flag', r.text)).strip()
print(f"[*] Encrypted: {encrypted}")

# The cipher is a 5x5 Polybius grid substitution
# Each pair of characters maps to one plaintext letter
# Standard Polybius: row,col in a 5x5 grid (I/J merged)
# The key/grid needs to be determined from the challenge

# Flag format: CTF{<litany as lowercase no spaces>}
flag = f"CTF{{{encrypted.lower().replace(' ', '')}}}"
print(f"[+] FLAG: {flag}")
