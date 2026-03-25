# caesar2 — BSidesSF 2026 (Forensics Crypto, 516pts)

## TL;DR

Each row of the image is circularly shifted (rotated) by N columns, where N is the ASCII value of the corresponding flag character. 12 rows per character.

## Flag

```
CTF{math$_1s_bl1$$}
```

## Description

Given two PNG images (300x241 RGB): `bliss.png` (Windows XP wallpaper) and `bliss_shifted.png` (same image with circular row shifts applied). Hint: "What oddly specific shifts..."

## Steps

1. **Identify the cipher** — The pixel VALUE differences between images are noisy, but testing circular ROW shifts reveals exact matches with zero error
2. **Extract shifts** — For each of the 241 rows, find the circular column shift `s` such that `np.roll(orig[r], s) == shifted[r]`
3. **Decode** — Groups of 12 consecutive rows share the same shift value. Convert shifts to ASCII:
   - 67→C, 84→T, 70→F, 123→{, 109→m, 97→a, 116→t, 104→h, 36→$, 95→_, 49→1, 115→s, 95→_, 98→b, 108→l, 49→1, 36→$, 36→$, 125→}

## Solve Script

```python
from PIL import Image
import numpy as np

orig = np.array(Image.open('bliss.png'))
shifted = np.array(Image.open('bliss_shifted.png'))

chars = []
for r in range(0, 241, 12):
    for s in range(300):
        if np.array_equal(np.roll(orig[r], s, axis=0), shifted[r]):
            if s > 0:
                chars.append(chr(s))
            break

print(''.join(chars))
# CTF{math$_1s_bl1$$}
```

## Key Insight

- "Caesar" cipher on an image = circular column rotation per row, not pixel value shift
- "Oddly specific shifts" = the rotation amounts ARE the flag bytes (ASCII values)
- The initial pixel-value diff analysis is a red herring — the shift is positional, not arithmetic
