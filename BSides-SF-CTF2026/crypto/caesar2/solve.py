#!/usr/bin/env python3
"""caesar2: Reverse circular pixel shift per row to recover flag"""
from PIL import Image
import numpy as np

img = Image.open("caesar2.png")
arr = np.array(img)
h, w = arr.shape[:2]

ROWS_PER_CHAR = 12
n_chars = h // ROWS_PER_CHAR

# For each character position, find the shift amount that produces
# the cleanest/most readable result (minimize entropy or match pattern)
flag = ""
for ci in range(n_chars):
    best_shift = 0
    best_score = float('inf')

    for shift in range(128):  # ASCII range
        score = 0
        for row in range(ci * ROWS_PER_CHAR, (ci + 1) * ROWS_PER_CHAR):
            if row >= h: break
            # Reverse the circular shift
            unshifted = np.roll(arr[row], -shift, axis=0)
            # Score: lower variance = more uniform = better alignment
            score += np.std(unshifted[:, 0])  # red channel

        if score < best_score:
            best_score = score
            best_shift = shift

    flag += chr(best_shift)

print(f"[+] FLAG: {flag}")
