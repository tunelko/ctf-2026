# Stegalirius (1/2) — Misc Write-up

**CTF:** Midnight Flag CTF 2026
**Category:** Misc
**Points:** 100
**Flag:** `MCTF{4H4H_QRGOESBRR}`

---

## TL;DR

Animated GIF with 219 frames, each containing a QR code with a Base64 chunk. Concatenating all chunks yields a hidden JPEG (200x201px) that contains the flag visible as text in the image.

---

## Solution

### Step 1 — Extract frames from the GIF
```bash
mkdir -p frames
convert midnight_live.gif frames/frame_%04d.png
# → 219 frames
```

### Step 2 — Read the QR from each frame
Each QR contains a Base64 chunk. The first frame has prefix `B64:jpg:`.

```bash
for f in frames/frame_*.png; do
    zbarimg --quiet "$f" 2>/dev/null
done | sed 's/QR-Code://' > all_chunks.txt
```

### Step 3 — Reconstruct the JPEG
```python
import base64

chunks = open('all_chunks.txt').readlines()
b64 = ''
for i, line in enumerate(chunks):
    line = line.strip()
    if i == 0 and line.startswith('B64:jpg:'):
        line = line[len('B64:jpg:'):]
    b64 += line

data = base64.b64decode(b64 + '==')
open('hidden.jpg', 'wb').write(data)
```

### Step 4 — Read the flag with OCR
The JPEG (200x201) contains text rendered on a black background. Invert and scale for OCR:

```python
from PIL import Image
import numpy as np

img = Image.open('hidden.jpg')
arr = np.array(img)
inv = 255 - arr  # invert (white on black → black on white)

# Extract text region (rows 68-85)
section = Image.fromarray(inv[68:85, :].astype(np.uint8))
section.resize((section.width*6, section.height*6), Image.NEAREST).save('ocr.png')
```

```bash
tesseract ocr.png stdout -l eng --psm 8
# → MCTF{4H4H_QRGOESBRR}
```

---

## Flag

```
MCTF{4H4H_QRGOESBRR}
```
