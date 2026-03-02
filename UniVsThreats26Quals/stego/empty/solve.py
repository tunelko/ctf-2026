#!/usr/bin/env python3
# solve.py — Empty stego solver
# Usage: python3 solve.py

import struct
from PIL import Image
import numpy as np

# Step 1: Extract ZIP password from empty.png blue channel LSB (every 3rd pixel)
img = Image.open('files/empty.png')
data = np.array(img)
blue = data[:,:,2].flatten()
sampled = blue[::3]  # every 3rd pixel
lsb = sampled & 1
bits = ''.join(str(b) for b in lsb)
password_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
password_str = password_bytes.decode('ascii', errors='ignore').strip('\xff\x00')
# Extract password value
pwd = password_str.split('=')[1].split(';')[0]
print(f"[+] ZIP Password: {pwd}")

# Step 2: Extract hidden ZIP from zero-width characters in empty.js
with open('files/empty.js', 'r', encoding='utf-8') as f:
    content = f.read()

idx = content.find('VOID_PAYLOAD')
payload_start = content.find('`', idx) + 1
payload_end = content.find('`', payload_start)
payload = content[payload_start:payload_end]

zwc = [c for c in payload if c in '\u200b\u200c']
bits = ''.join('0' if c == '\u200b' else '1' for c in zwc)
zip_data = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))

with open('/tmp/hidden.zip', 'wb') as f:
    f.write(zip_data)
print(f"[+] Extracted hidden ZIP: {len(zip_data)} bytes")

# Step 3: Extract ZIP with password using 7z
import subprocess
subprocess.run(['7z', 'x', '/tmp/hidden.zip', f'-p{pwd}', '-o/tmp/extracted', '-y'],
               capture_output=True)

# Step 4: Read flag from flag.png (appended after IEND chunk)
with open('/tmp/extracted/flag.png', 'rb') as f:
    raw = f.read()

# Flag is in strings after IEND
iend = raw.find(b'IEND')
trailing = raw[iend:]
import re
m = re.search(rb'(UVT\{[^}]+\})', trailing)
if m:
    flag = m.group(1).decode()
else:
    # Also check full file
    m = re.search(rb'(UVT\{[^}]+\})', raw)
    flag = m.group(1).decode() if m else "FLAG NOT FOUND"

print(f"\nFLAG: {flag}")
