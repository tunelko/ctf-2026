# Analog Nostalgia — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Hardhack
**Points:** 50
**Difficulty:** Beginner
**Flag:** `0xfun{AN4L0G_IS_N0T_D3AD_JUST_BL4NKING}`

---

## Description

A file `vga_data.raw` is provided containing an analog VGA signal captured in raw format.

## Analysis

### File structure

The file contains a raw VGA signal with:

- **Header:** 25 initial bytes
- **Data:** 420,000 samples of 5 bytes each:
  - Byte 0: R channel (6 bits, 0-63)
  - Byte 1: G channel (6 bits, 0-63)
  - Byte 2: B channel (6 bits, 0-63)
  - Byte 3: HSYNC (horizontal synchronization)
  - Byte 4: VSYNC (vertical synchronization)

### Standard VGA timing (640x480)

The 640x480 VGA signal uses a total timing of **800 samples per line** and **525 lines per frame**:

- 800 x 525 = 420,000 samples (matches exactly)
- Active zone: 640x480 pixels (the rest is blanking/sync)

### Rendering

1. Organize the 420,000 samples into an 800x525 grid
2. Extract the 640x480 pixels from the active zone (discarding blanking)
3. Scale RGB values from 6 bits to 8 bits: `value_8bit = value_6bit * 255 / 63`
4. Render as an image

### Result

The rendered image shows a Woody and Buzz Lightyear (Toy Story) meme with the flag text.

## Solution

```python
#!/usr/bin/env python3
import struct
from PIL import Image

with open('vga_data.raw', 'rb') as f:
    header = f.read(25)
    data = f.read()

# 5 bytes per sample: R, G, B, HSYNC, VSYNC
total_samples = len(data) // 5  # 420,000

# VGA 640x480 -> 800x525 total
W_TOTAL, H_TOTAL = 800, 525
W_ACTIVE, H_ACTIVE = 640, 480

img = Image.new('RGB', (W_ACTIVE, H_ACTIVE))
pixels = img.load()

for y in range(H_TOTAL):
    for x in range(W_TOTAL):
        idx = (y * W_TOTAL + x) * 5
        if x < W_ACTIVE and y < H_ACTIVE and idx + 2 < len(data):
            r = int(data[idx] * 255 / 63)
            g = int(data[idx+1] * 255 / 63)
            b = int(data[idx+2] * 255 / 63)
            pixels[x, y] = (r, g, b)

img.save('frame.png')
print("[+] Image saved: frame.png")
# -> Meme with visible flag: 0xfun{AN4L0G_IS_N0T_D3AD_JUST_BL4NKING}
```

## Flag

```
0xfun{AN4L0G_IS_N0T_D3AD_JUST_BL4NKING}
```

## Notes

- The `0` (zero) characters in the flag use leetspeak: AN4L0G = ANALOG, N0T = NOT, D3AD = DEAD, BL4NKING = BLANKING
- The name "Analog Nostalgia" refers to VGA being an analog interface, replaced by digital HDMI/DisplayPort
- The sibling challenge "Digital Transition" uses TMDS (DVI/HDMI digital protocol)

## Files

- `vga_data.raw` — Raw VGA signal (25 bytes header + 420,000 x 5 bytes)
- `frame.png` — Rendered image with the flag
