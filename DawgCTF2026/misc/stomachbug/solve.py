#!/usr/bin/env python3
"""DawgCTF 2026 - Stomachbug (misc) - Extract PNG from streaming hex, nested QR codes"""
import subprocess, re, base64
from pyzbar.pyzbar import decode
from PIL import Image

# 1. Grab hex data from the "vomiting" server
result = subprocess.run(["curl", "-s", "--max-time", "30", "https://stomachbug.umbccd.net"],
                       capture_output=True, text=True)

# 2. Extract hex chunks |NNN|hexdata, deduplicate by index
chunks = {}
for m in re.finditer(r'\|(\d+)\|([0-9a-f]+)', result.stdout):
    idx = int(m.group(1))
    if idx not in chunks:
        chunks[idx] = m.group(2)

# 3. Reassemble PNG
hex_data = "".join(chunks[i] for i in range(max(chunks) + 1))
with open("/tmp/qr1.png", "wb") as f:
    f.write(bytes.fromhex(hex_data))

# 4. Decode outer QR → inner PNG (fix UTF-8 encoding)
img1 = Image.open("/tmp/qr1.png")
raw = decode(img1)[0].data
png2 = raw.decode('utf-8').encode('latin-1')
with open("/tmp/qr2.png", "wb") as f:
    f.write(png2)

# 5. Decode inner QR → base64 flag
img2 = Image.open("/tmp/qr2.png")
b64 = decode(img2)[0].data.decode()
flag = base64.b64decode(b64).decode()
print(f"Flag: {flag}")
