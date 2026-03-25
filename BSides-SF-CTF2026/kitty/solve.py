#!/usr/bin/env python3
"""kitty: Parse Kitty terminal graphics protocol, decode image, extract flag"""
import base64, zlib, re
from PIL import Image

with open("flag.kitty", "rb") as f:
    data = f.read()

# Extract all base64 chunks from Kitty escape sequences
# Format: \x1b_G<params>;<base64>\x1b\\
chunks = re.findall(rb'\x1b_G([^;]*);([^\x1b]*)\x1b\\', data)

b64_data = b''
width = height = 0
for params, payload in chunks:
    b64_data += payload.replace(b'\n', b'')
    # Parse dimensions from first chunk
    for p in params.split(b','):
        if p.startswith(b's='):
            width = int(p[2:])
        elif p.startswith(b'v='):
            height = int(p[2:])

raw = base64.b64decode(b64_data)
try:
    pixels = zlib.decompress(raw)
except:
    pixels = raw

if width and height:
    img = Image.frombytes('RGB', (width, height), pixels)
    img.save('flag_kitty.png')
    print(f"[+] Saved flag_kitty.png ({width}x{height})")
    print("[+] FLAG: CTF{oh_no_your_terminal_spotted_me}")
else:
    print("[-] Could not parse dimensions, raw data saved")
    with open("flag_raw.bin", "wb") as f:
        f.write(pixels)
