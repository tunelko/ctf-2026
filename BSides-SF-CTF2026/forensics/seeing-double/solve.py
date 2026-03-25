#!/usr/bin/env python3
"""
Seeing Double - BSidesSF CTF 2026 - Forensics
Flag hidden in row-interlaced image: odd rows contain watermarked version.
Amplify odd-even difference to reveal text.
"""
from PIL import Image
import numpy as np

img = Image.open("flag.png")
arr = np.array(img, dtype=np.float32)

even = arr[0::2, :, :]
odd  = arr[1::2, :, :]

diff = (odd - even) * 20 + 128
diff = np.clip(diff, 0, 255).astype(np.uint8)

Image.fromarray(diff).save("diff_amplified.png")
print("Saved diff_amplified.png — flag visible diagonally: CTF{mmyyeeyyeess}")
