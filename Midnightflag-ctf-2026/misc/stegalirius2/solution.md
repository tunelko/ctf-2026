# Stegalirius (2/2) — Write-up

**CTF:** Midnight Flag CTF 2026
**Category:** Misc
**Flag:** `MCTF{Is0r1sN0tThat1sTheQuest10n!?}`

---

## TL;DR

232MB Python script (`mctf.py`) encodes a PNG image using Python's integer interning trick. Each 8-bit group uses `eval(str(N)) is eval(str(N))` — evaluates to `True` (bit=1) when N≤256 (CPython interns small integers, same object), `False` (bit=0) when N>256 (new objects). Decoded PNG contains a magazine-style image with the flag embedded as text.

---

## Artifacts

- `stegalirius2.zip` → `mctf.py` (232MB, ~5.7M lines)
- `/tmp/stegalirius2/out.jpg` — decoded PNG (767×768, RGBA)

---

## Vulnerability / Trick

**CPython Integer Interning:**

```python
eval(str(207)) is eval(str(207))  # True → bit=1 (207 ≤ 256, same cached object)
eval(str(282)) is eval(str(282))  # False → bit=0 (282 > 256, new objects each time)
```

Python caches (interns) integers from -5 to 256. For numbers outside that range, each `eval()` creates a new integer object, so `is` comparison fails.

---

## Decoding

```python
import re

current_group = []
bits_per_group = []

with open('mctf.py', 'r') as f:
    for line in f:
        line = line.strip()
        m = re.match(r'__ \+= str\(int\(eval\(str\((\d+)\)\) is eval\(str\(\d+\)\)\)\)', line)
        if m:
            n = int(m.group(1))
            bit = 1 if n <= 256 else 0
            current_group.append(bit)
        elif line.startswith("_ += [int(''.join(__), 2)]"):
            if current_group:
                bits_per_group.append(current_group)
            current_group = []

byte_values = []
for group in bits_per_group:
    val = int(''.join(str(b) for b in group), 2)
    byte_values.append(val)

with open('out.jpg', 'wb') as f:
    f.write(bytes(byte_values))
```

Produces a 572,256-byte PNG file (despite .jpg extension).

---

## Flag Extraction

The PNG contains a magazine-style layout with the flag text embedded in the image. OCR on the inverted image reveals:

```
tesseract full_inv_rgb.png stdout -l eng --psm 6 \
  -c tessedit_char_whitelist='MCTFabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}!?_'
```

Output: `MCTF{IsOrisNOotTha sTheQuest10n!?}`

OCR artifacts corrected:
- `IsOris` → `IsOrIs` (lowercase 'i' misread as uppercase 'I')
- `NOot` → `NOt` (double-O OCR artifact)
- `Tha` + `s` (line break) → `ThatIs`

**Shakespeare reference:** "To be, or not to be, that is the question"
→ `IsOrIsNOtThatIsTheQuest10n` (leet: `io` → `10` in "question")

---

## Flag

```
MCTF{Is0r1sN0tThat1sTheQuest10n!?}
```

---

## Key Lessons

1. **Python integer interning** (N≤256 vs N>256) can encode binary data in identity comparisons.
2. Large "source code" files may encode binary blobs pixel by pixel.
3. OCR artifacts from line breaks and font rendering require manual correction using context (here: Shakespeare quote).
