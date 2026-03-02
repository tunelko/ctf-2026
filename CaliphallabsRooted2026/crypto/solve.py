#!/usr/bin/env python3
"""
Challenge: Secure Sign
Category:  crypto
Platform:  caliphallabsRooted2026

The /api/sign endpoint signs ANY document we provide and returns the server's
public key hex. The /api/verify gives the flag if we provide a valid signature
of the public key bytes. So: sign the public key itself → submit to verify → flag.
"""
import requests
import sys
import base64
import json

LOCAL_URL = "http://localhost:7000"
REMOTE_URL = "http://securesign.challs.caliphallabs.com"

BASE = REMOTE_URL if "--remote" in sys.argv else LOCAL_URL
session = requests.Session()

def exploit():
    #  Register and login
    email = "exploit@test.com"
    password = "password123"

    print(f"[*] Target: {BASE}")
    print("[*] Registering...")
    r = session.post(f"{BASE}/api/register", json={"email": email, "password": password})
    print(f"[*] Register: {r.status_code} - {r.text[:200]}")

    print("[*] Logging in...")
    r = session.post(f"{BASE}/api/login", json={"email": email, "password": password})
    print(f"[*] Login: {r.status_code}")
    if r.status_code != 200:
        print(f"[-] Login failed: {r.text}")
        return

    token = r.json().get("token", "")
    headers = {"Authorization": f"Bearer {token}"}

    #  Sign a dummy doc to get the public key
    print("[*] Signing dummy doc to get public key...")
    dummy = base64.b64encode(b"dummy").decode()
    r = session.post(f"{BASE}/api/sign",
                     json={"files": [{"filename": "dummy.txt", "content": dummy}]},
                     headers=headers)
    print(f"[*] Sign status: {r.status_code}")
    data = r.json()
    pk_hex = data["public_key"]
    print(f"[+] Public key hex: {pk_hex}")
    pk_bytes = bytes.fromhex(pk_hex)
    print(f"[+] Public key length: {len(pk_bytes)} bytes")

    #  Sign the public key bytes
    print("[*] Signing public key bytes...")
    pk_b64 = base64.b64encode(pk_bytes).decode()
    r = session.post(f"{BASE}/api/sign",
                     json={"files": [{"filename": "pubkey.bin", "content": pk_b64}]},
                     headers=headers)
    print(f"[*] Sign status: {r.status_code}")
    data = r.json()
    sig_hex = data["results"][0]["signature"]
    print(f"[+] Signature: {sig_hex}")

    #  Verify - submit public key as document with its signature
    print("[*] Submitting to /api/verify for flag...")
    files = {
        "document": ("pubkey.bin", pk_bytes, "application/octet-stream"),
    }
    form_data = {
        "signature": sig_hex,
    }
    r = session.post(f"{BASE}/api/verify", files=files, data=form_data)
    print(f"[*] Verify status: {r.status_code}")
    print(f"[+] Response: {r.text}")

    resp = r.json()
    if "flag" in resp:
        print(f"\n[+] FLAG: {resp['flag']}")
        with open("flag.txt", "w") as f:
            f.write(resp["flag"])

if __name__ == "__main__":
    exploit()
