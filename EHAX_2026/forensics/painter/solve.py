#!/usr/bin/env python3
from PIL import Image, ImageDraw

import os
DATA_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(DATA_DIR, 'mouse_data.txt')) as f:
    lines = [l.strip() for l in f if l.strip()]

x, y = 500, 500
points = []

for line in lines:
    if len(line) != 14:
        continue
    btn = int(line[0:2], 16)
    dx = int(line[2:4], 16) | (int(line[4:6], 16) << 8)
    if dx > 32767: dx -= 65536
    dy = int(line[6:8], 16) | (int(line[8:10], 16) << 8)
    if dy > 32767: dy -= 65536
    x += dx
    y += dy
    points.append((x, y, bool(btn & 0x01)))

draw_pts = [(p[0], p[1]) for p in points if p[2]]
min_x = min(p[0] for p in draw_pts) - 20
min_y = min(p[1] for p in draw_pts) - 20
max_x = max(p[0] for p in draw_pts) + 20
max_y = max(p[1] for p in draw_pts) + 20
w, h = max_x - min_x, max_y - min_y
print(f"Size: {w}x{h}, drawing points: {len(draw_pts)}")

img = Image.new('RGB', (w, h), 'white')
d = ImageDraw.Draw(img)
prev = None
for px, py, drawing in points:
    if drawing:
        ax, ay = px - min_x, py - min_y
        if prev:
            d.line([prev, (ax, ay)], fill='black', width=2)
        prev = (ax, ay)
    else:
        prev = None

img.save(os.path.join(DATA_DIR, 'mouse_drawing.png'))
print("Saved mouse_drawing.png")
