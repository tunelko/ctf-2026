# Deep Down — UMassCTF 2026 (MISC)

## TL;DR
GIF palette steganography: two palette entries with identical RGB values but different indices. The flag is written in the "deep" water area using the minority index, invisible to the eye.

## Analysis
- GIF 100x70, 12 frames, 8-color palette
- Palette entries `[1]=(11,41,71)` and `[3]=(11,41,71)` are **identical colors**
- Entry `[3]` is the dominant water color (2452 pixels)
- Entry `[1]` appears only in the bottom water area (y=54-66, 259 pixels)
- The 259 pixels of index `[1]` spell out the flag in pixel art

## Solution
```python
from PIL import Image
import numpy as np

img = Image.open('CHALL.gif')
img.seek(0)
raw = np.array(img)  # palette indices

# Visualize index 1 pixels (hidden in identical-color water)
mask = (raw == 1).astype(np.uint8) * 255
Image.fromarray(mask).resize((800, 560), Image.NEAREST).save('flag.png')
```

## Flag
```
UMASS{1N_A_G1774}
```
