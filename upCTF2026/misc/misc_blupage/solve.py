#!/usr/bin/env python3
"""
Challenge: BluPage — upCTF 2026
Category:  misc (steganography / web)
Flag:      upCTF{PNG_hdrs_4r3_sn34ky}

1. HTML has hidden <link rel="prefetch" href="/assets/artifacts.zip">
2. touch.js hint: "Don't forget: LSB, 32bits."
3. f_left.png has corrupted PNG header (PNX → PNG), shows partial flag
4. f_right.png blue channel LSBs encode the second half
"""

from PIL import Image
import numpy as np

# --- Part 1: Fix corrupted PNG header ---
data = open('f_left.png', 'rb').read()
# Magic bytes: 89 50 4E 58 → 89 50 4E 47 (X→G)
fixed = b'\x89PNG' + data[4:]
open('f_left_fixed.png', 'wb').write(fixed)
print("f_left_fixed.png → visual text: xCTF{PNG_hdrs_")
print("  (first char corrupted like the header → 'x' should be 'up')")

# --- Part 2: Extract LSB from blue channel of f_right.png ---
img = Image.open('f_right.png')  # RGBA, 640x200
pixels = np.array(img)

# Only blue channel has data (values 0 or 1, other channels all 0/255)
blue = pixels[:, :, 2].flatten()

# Read as 8-bit bytes (MSB first), skip leading zeros
result = ''
for i in range(0, len(blue), 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | blue[i + j]
    if byte >= 32:
        result += chr(byte)

print(f"f_right.png blue LSB → {result}")

# --- Combine ---
flag = f"upCTF{{PNG_hdrs_{result.rstrip('}')}}}"
print(f"\nFLAG: {flag}")
