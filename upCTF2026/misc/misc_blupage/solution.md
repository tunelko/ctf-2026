# BluPage — upCTF 2026

**Category:** MISC (Steganography / Web)
**Flag:** `upCTF{PNG_hdrs_4r3_sn34ky}`

## TL;DR

Web page with a hidden `<link rel="prefetch">` pointing to `/assets/artifacts.zip`. The ZIP contains two images: `f_left.png` with a corrupted PNG header that, once fixed, shows the first half of the flag, and `f_right.png` with binary data encoded in the Blue channel (LSB steganography) revealing the second half.

---

## Analysis

### Web Reconnaissance

```
http://46.225.117.62:30019/
```

Static page served by nginx. The HTML contains:

```html
<link rel="prefetch" href="/assets/artifacts.zip" as="fetch" crossorigin>
<link rel="stylesheet" href="/static/style.css">
...
<script src="/static/touch.js"></script>
```

The file `touch.js` contains the key hint:

```javascript
console.log("Don't forget: LSB, 32bits.");
```

### artifacts.zip

```
f_left.png   — 6973 bytes, corrupted PNG header
f_right.png  —  913 bytes, valid PNG 640×200 RGBA
```

### f_left.png — Corrupted Header

```
Offset  Hex             ASCII
00000:  89 50 4E 58     .PNX    ← should be 89 50 4E 47 (.PNG)
```

The byte at position 3 is `0x58` (`X`) instead of `0x47` (`G`). After correcting it, the image shows the text:

```
xCTF{PNG_hdrs_
```

The initial `x` is "corrupted" in the same way as the header — the flag format is `upCTF{...}`.

### f_right.png — Blue Channel LSB

640×200 RGBA image, visually black. Channel analysis:

| Channel | min | max | unique values |
|---------|-----|-----|---------------|
| R       | 0   | 0   | 1             |
| G       | 0   | 0   | 1             |
| **B**   | **0** | **1** | **2**    |
| A       | 255 | 255 | 1             |

Only the Blue channel contains data: exactly values 0 and 1. These are directly the message bits. Sequential reading (MSB first, 8 bits per byte):

```
Bits: ...00110100 01110010 00110011 01011111 01110011 01101110...
ASCII:     4        r        3        _        s        n
```

Result: `4r3_sn34ky}`

### Complete Flag

```
f_left (visual, fixed):         upCTF{PNG_hdrs_
f_right (blue channel LSB):     4r3_sn34ky}
─────────────────────────────────────────────
Flag:                           upCTF{PNG_hdrs_4r3_sn34ky}
```

---

## Vulnerability

**CWE-540: Inclusion of Sensitive Information in Source Code** — hidden resource in `<link rel="prefetch">` publicly accessible.

Combined with basic steganography (LSB in color channel) and PNG header corruption as an obfuscation element.

---

## Exploit

### solve.py

```python
#!/usr/bin/env python3
from PIL import Image
import numpy as np

# Part 1: Fix corrupted PNG header (PNX → PNG)
data = open('f_left.png', 'rb').read()
fixed = b'\x89PNG' + data[4:]
open('f_left_fixed.png', 'wb').write(fixed)
# Visual text: xCTF{PNG_hdrs_ → upCTF{PNG_hdrs_

# Part 2: Extract LSB from blue channel
img = Image.open('f_right.png')
blue = np.array(img)[:, :, 2].flatten()  # values are 0 or 1

result = ''
for i in range(0, len(blue), 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | blue[i + j]
    if byte >= 32:
        result += chr(byte)

print(f"upCTF{{PNG_hdrs_{result.rstrip('}')}}}")
```

```bash
python3 solve.py
# upCTF{PNG_hdrs_4r3_sn34ky}
```

---

## Key Lessons

1. **Inspect the full HTML**: `<link rel="prefetch">` is not visible on the rendered page but loads publicly accessible resources
2. **`file` doesn't lie**: when `file` says "data" instead of "PNG image data", the header is corrupted — check the magic bytes
3. **Individual channels**: a "completely black" image can carry data in a single color channel (here Blue, consistent with "Blu" in "BluPage")
4. **The JS hint**: `console.log()` in production is a classic OPSEC mistake — here `"LSB, 32bits"` points directly to the extraction method

## References

- [PNG Specification — Header](http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html)
- [LSB Steganography](https://en.wikipedia.org/wiki/Steganography#Digital_steganography)
