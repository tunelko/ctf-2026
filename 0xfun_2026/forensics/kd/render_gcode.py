#!/usr/bin/env python3
"""Render G-code top-down view to see the flag"""
from PIL import Image, ImageDraw
import re

GCODE = '/home/ubuntu/0xfun/ctf/challenges/forensics/3D.gcode'

# Parse all movement coordinates with extrusion
moves = []
x, y, z = 0.0, 0.0, 0.0
extruding = False
layer = -1

min_x, max_x = float('inf'), float('-inf')
min_y, max_y = float('inf'), float('-inf')

print("[*] Parsing G-code...")
with open(GCODE, 'r') as f:
    for line in f:
        line = line.strip()
        if line.startswith(';LAYER:'):
            layer = int(line.split(':')[1])
            continue
        if line.startswith(';') or not line:
            continue

        # Parse G0 (travel) and G1 (extrusion) moves
        if line.startswith('G0 ') or line.startswith('G1 '):
            cmd = line.split()[0]
            new_x, new_y, new_z = x, y, z
            has_e = False

            for part in line.split():
                if part.startswith('X'):
                    new_x = float(part[1:])
                elif part.startswith('Y'):
                    new_y = float(part[1:])
                elif part.startswith('Z'):
                    new_z = float(part[1:])
                elif part.startswith('E'):
                    e_val = float(part[1:])
                    has_e = True

            # G1 with E = extrusion (only if E is increasing)
            if cmd == 'G1' and has_e:
                moves.append((x, y, new_x, new_y, new_z, layer))
                min_x = min(min_x, x, new_x)
                max_x = max(max_x, x, new_x)
                min_y = min(min_y, y, new_y)
                max_y = max(max_y, y, new_y)

            x, y, z = new_x, new_y, new_z

print(f"[+] {len(moves)} extrusion moves")
print(f"[+] X: {min_x:.1f} - {max_x:.1f}, Y: {min_y:.1f} - {max_y:.1f}")
print(f"[+] Layers: 0-{layer}")

# Render top-down view (all layers overlaid)
scale = 5
width = int((max_x - min_x + 10) * scale)
height = int((max_y - min_y + 10) * scale)

print(f"[*] Image: {width}x{height}")

# Top-down view of ALL layers
img = Image.new('RGB', (width, height), 'white')
draw = ImageDraw.Draw(img)

for x1, y1, x2, y2, z_val, lay in moves:
    px1 = int((x1 - min_x + 5) * scale)
    py1 = height - int((y1 - min_y + 5) * scale)
    px2 = int((x2 - min_x + 5) * scale)
    py2 = height - int((y2 - min_y + 5) * scale)
    draw.line([(px1, py1), (px2, py2)], fill='black', width=1)

img.save('/home/ubuntu/0xfun/ctf/challenges/forensics/gcode_topdown.png')
print("[+] Saved gcode_topdown.png")

# Render only the first layer (layer 0) - usually shows the base
img0 = Image.new('RGB', (width, height), 'white')
draw0 = ImageDraw.Draw(img0)
for x1, y1, x2, y2, z_val, lay in moves:
    if lay == 0:
        px1 = int((x1 - min_x + 5) * scale)
        py1 = height - int((y1 - min_y + 5) * scale)
        px2 = int((x2 - min_x + 5) * scale)
        py2 = height - int((y2 - min_y + 5) * scale)
        draw0.line([(px1, py1), (px2, py2)], fill='black', width=1)

img0.save('/home/ubuntu/0xfun/ctf/challenges/forensics/gcode_layer0.png')
print("[+] Saved gcode_layer0.png")

# Render a middle layer
mid = 386
img_mid = Image.new('RGB', (width, height), 'white')
draw_mid = ImageDraw.Draw(img_mid)
for x1, y1, x2, y2, z_val, lay in moves:
    if lay == mid:
        px1 = int((x1 - min_x + 5) * scale)
        py1 = height - int((y1 - min_y + 5) * scale)
        px2 = int((x2 - min_x + 5) * scale)
        py2 = height - int((y2 - min_y + 5) * scale)
        draw_mid.line([(px1, py1), (px2, py2)], fill='black', width=1)

img_mid.save('/home/ubuntu/0xfun/ctf/challenges/forensics/gcode_layer_mid.png')
print(f"[+] Saved gcode_layer_mid.png (layer {mid})")

# Front view (X-Z)
img_front = Image.new('RGB', (width, int((200) * scale)), 'white')
draw_front = ImageDraw.Draw(img_front)
for x1, y1, x2, y2, z_val, lay in moves:
    px1 = int((x1 - min_x + 5) * scale)
    pz1 = img_front.height - int((z_val) * scale)
    px2 = int((x2 - min_x + 5) * scale)
    pz2 = pz1
    if 0 <= pz1 < img_front.height:
        draw_front.line([(px1, pz1), (px2, pz2)], fill='black', width=1)

img_front.save('/home/ubuntu/0xfun/ctf/challenges/forensics/gcode_front.png')
print("[+] Saved gcode_front.png (front view X-Z)")

# Side view (Y-Z)
img_side = Image.new('RGB', (int((max_y - min_y + 10) * scale), int((200) * scale)), 'white')
draw_side = ImageDraw.Draw(img_side)
for x1, y1, x2, y2, z_val, lay in moves:
    py1 = int((y1 - min_y + 5) * scale)
    pz1 = img_side.height - int((z_val) * scale)
    py2 = int((y2 - min_y + 5) * scale)
    pz2 = pz1
    if 0 <= pz1 < img_side.height:
        draw_side.line([(py1, pz1), (py2, pz2)], fill='black', width=1)

img_side.save('/home/ubuntu/0xfun/ctf/challenges/forensics/gcode_side.png')
print("[+] Saved gcode_side.png (side view Y-Z)")
