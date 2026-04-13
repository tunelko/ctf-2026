#!/usr/bin/env python3
"""DawgCTF 2026 - Dust to Dust (rev) - Reverse binary image compression"""
from PIL import Image

with open("output.txt", "rb") as f:
    data = f.read()

# Remove trailing ~ (0x7E), split lines by } (0x7D)
if data[-1] == 0x7E:
    data = data[:-1]
lines = data.split(b'\x7D')

# Decode: each byte - 0x20 = 6-bit value → top 3 bits = row0, bottom 3 = row1
rows = []
for line in lines:
    if not line: continue
    top, bot = [], []
    for b in line:
        bits = format(b - 0x20, '06b')
        top.append(bits[:3])
        bot.append(bits[3:])
    rows.append("".join(top))
    rows.append("".join(bot))

# Render as image (0=black pixel, 1=white)
h, w = len(rows), len(rows[0])
img = Image.new('1', (w, h))
for y, row in enumerate(rows):
    for x, bit in enumerate(row):
        img.putpixel((x, y), 1 if bit == '0' else 0)
img.save("flag.png")
print(f"Saved {w}x{h} image to flag.png")
