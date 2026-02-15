#!/usr/bin/env python3
"""
GCode Challenge - Solve
Extracts the flag from the 3D.gcode file by rendering the front view (X-Z)
of the flag.stl mesh, filtering only WALL-OUTER and filling the letters.

Flag: 0xfun{this_monkey_has_a_flag}
"""
from PIL import Image, ImageDraw
import numpy as np

GCODE_PATH = "3D.gcode"

# --- Step 1: Parse the GCode and extract WALL-OUTER segments from flag.stl ---
segments = []
current_mesh = None
current_type = None
x, y, z = 0, 0, 0

with open(GCODE_PATH, "r") as f:
    for line in f:
        line = line.strip()
        if line.startswith(";MESH:"):
            current_mesh = line.split(":", 1)[1]
            continue
        if line.startswith(";TYPE:"):
            current_type = line.split(":", 1)[1]
            continue

        if line.startswith("G0 ") or line.startswith("G1 "):
            nx, ny, nz = x, y, z
            has_e = False
            e_val = 0
            for part in line.split():
                if part.startswith("X"):
                    nx = float(part[1:])
                elif part.startswith("Y"):
                    ny = float(part[1:])
                elif part.startswith("Z"):
                    nz = float(part[1:])
                elif part.startswith("E"):
                    has_e = True
                    e_val = float(part[1:])

            # Only WALL-OUTER extrusions from the flag.stl mesh
            if (
                current_mesh == "flag.stl"
                and current_type == "WALL-OUTER"
                and line.startswith("G1")
                and has_e
                and e_val > 0
            ):
                segments.append((x, z, nx, nz))

            x, y, z = nx, ny, nz

print(f"[+] WALL-OUTER segments from flag.stl: {len(segments)}")

# --- Step 2: Render front view (X horizontal, Z vertical) ---
all_x = [s[0] for s in segments] + [s[2] for s in segments]
all_z = [s[1] for s in segments] + [s[3] for s in segments]
min_x, max_x = min(all_x), max(all_x)
min_z, max_z = min(all_z), max(all_z)

scale = 50
margin = 80
w = int((max_x - min_x) * scale) + 2 * margin
h = int((max_z - min_z) * scale) + 2 * margin

img = Image.new("L", (w, h), 255)
draw = ImageDraw.Draw(img)

for x1, z1, x2, z2 in segments:
    px1 = int((x1 - min_x) * scale) + margin
    pz1 = h - (int((z1 - min_z) * scale) + margin)
    px2 = int((x2 - min_x) * scale) + margin
    pz2 = h - (int((z2 - min_z) * scale) + margin)
    draw.line([(px1, pz1), (px2, pz2)], fill=0, width=4)

img.save("flag_outline.png")
print(f"[+] Outline saved: flag_outline.png ({w}x{h})")

# --- Step 3: Fill letters (column by column) for better readability ---
arr = np.array(img)
filled = np.ones_like(arr) * 255

for col in range(w):
    black_rows = np.where(arr[:, col] < 128)[0]
    if len(black_rows) > 0:
        groups = []
        start = black_rows[0]
        prev = black_rows[0]
        for r in black_rows[1:]:
            if r - prev > 20:  # separate groups (different text lines)
                groups.append((start, prev))
                start = r
            prev = r
        groups.append((start, prev))
        for top, bot in groups:
            filled[top : bot + 1, col] = 0

filled_img = Image.fromarray(filled)
filled_img.save("flag_filled.png")
print(f"[+] Fill saved: flag_filled.png")
print(f"[+] Flag: 0xfun{{this_monkey_has_a_flag}}")
