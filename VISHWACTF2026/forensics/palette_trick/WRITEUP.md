# Palette Trick — VishwaCTF 2026

| Field | Value |
|-------|-------|
| **CTF** | VishwaCTF 2026 |
| **Category** | Forensics |
| **Challenge** | Palette Trick |
| **Flag** | `VishwaCTF{P4l3tt3_1nd3x_S3cr3t}` |
| **Files** | `wheel.png` |

## TL;DR

31x1 indexed PNG where each palette entry encodes one flag character in its R (red) channel value. Read palette entries 0–30 in order → flag.

## Analysis

### File Properties

```
wheel.png: PNG image data, 31 x 1, 8-bit colormap, non-interlaced
Size: 877 bytes
```

Key detail: **8-bit colormap** = indexed color mode (`P` mode in PIL). Pixels don't store RGB directly — they store an index into a color lookup table (palette).

### Pixel Data

All 31 pixels use sequential indices:

```
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
```

This is the hint — pixels themselves are trivial. The data is in the **palette mapping**.

### Palette Table

Each palette entry has the flag character's ASCII value in the R channel, with G and B set to zero:

| Index | R | G | B | Char |
|-------|---|---|---|------|
| 0 | 86 | 0 | 0 | V |
| 1 | 105 | 0 | 0 | i |
| 2 | 115 | 0 | 0 | s |
| 3 | 104 | 0 | 0 | h |
| 4 | 119 | 0 | 0 | w |
| 5 | 97 | 0 | 0 | a |
| 6 | 67 | 0 | 0 | C |
| 7 | 84 | 0 | 0 | T |
| 8 | 70 | 0 | 0 | F |
| 9 | 123 | 0 | 0 | { |
| 10–29 | ... | 0 | 0 | P4l3tt3_1nd3x_S3cr3 |
| 30 | 125 | 0 | 0 | } |

Visually the image appears as a thin strip of dark reds (varying R, zero G/B), hiding the data in plain sight.

## Solution

```python
from PIL import Image

img = Image.open('wheel.png')
palette = img.getpalette()
flag = ''.join(chr(palette[i * 3]) for i in range(31))
print(flag)
# VishwaCTF{P4l3tt3_1nd3x_S3cr3t}
```

## Key Takeaways

1. **Indexed PNG steganography**: Data hidden in the palette table rather than pixel values — most stego tools analyze pixel data and miss palette metadata entirely
2. **The challenge hint was literal**: "the flag is hidden in the order of colors in the index table" — palette entries read sequentially spell the flag
3. **Quick identification**: `file` output showing "8-bit colormap" immediately signals to inspect the palette, not raw pixels

## Files

```
palette_trick/
├── wheel.png    # Original challenge image
├── flag.txt     # Captured flag
└── WRITEUP.md   # This file
```
