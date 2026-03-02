#!/usr/bin/env python3
"""
EHAXctf - Validator (Reversing)
Solver: Newton fractal bitmap decoder

The validator binary implements Newton's method for f(z) = z^3 - 1.
It checks if a given complex number converges to root z=1 in exactly 12 iterations.
The 2600 data points encode a 130x20 bitmap where valid points = pixels ON.
The bitmap renders the flag in a 5-row block font.
"""
import math

def newton_z3(x0, y0):
    """Newton method for z^3-1. Returns iteration count when converged to root z=1."""
    x, y = x0, y0
    iters = 0
    for i in range(50):
        fx = x**3 - 3*x*y**2 - 1
        fy = 3*x**2*y - y**3
        dpx = 3*(x**2 - y**2)
        dpy = 6*x*y
        denom = dpx**2 + dpy**2
        if denom < 1e-9:
            break
        step_x = (fx*dpx + fy*dpy) / denom
        step_y = (fy*dpx - fx*dpy) / denom
        x -= step_x
        y -= step_y
        iters += 1
        if abs(x - 1.0) < 1e-6 and abs(y) < 1e-6:
            break
    return iters

# Load signal data
with open('signal_data.txt') as f:
    lines = f.readlines()

# Build bit array: 1 if converges to z=1 in exactly 12 iterations
bits = []
for line in lines:
    parts = line.strip().split(',')
    x0, y0 = float(parts[0]), float(parts[1])
    iters = newton_z3(x0, y0)
    bits.append(1 if iters == 12 else 0)

print(f"Total points: {len(bits)}, Valid (12 iters): {sum(bits)}")

# Render as 130x20 grid (the correct dimensions for readable text)
WIDTH, HEIGHT = 130, 20
print(f"\n=== Bitmap {WIDTH}x{HEIGHT} ===")
for row in range(HEIGHT):
    line = ""
    for col in range(WIDTH):
        idx = row * WIDTH + col
        line += "█" if bits[idx] else " "
    # Only print non-empty rows
    if any(c == '█' for c in line):
        print(line)

print(f"\nFlag: EH4X{{n3WT0n_W45_R1GHT}}")
print("Message: NEWTON WAS RIGHT")
