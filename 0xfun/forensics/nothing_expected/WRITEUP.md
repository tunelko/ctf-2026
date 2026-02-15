# Nothing Expected — Forensics (50 pts)

**CTF:** 0xFun CTF 2026
**Category:** Forensics
**Difficulty:** Beginner
**Author:** x03e
**Flag:** `0xfun{th3_sw0rd_0f_k1ng_4rthur}`

---

## Description

> Here's a small drawing I put together. There isn't really anything in it, as you can tell.

## Analysis

A `file.png` file is provided (584x784, RGBA). The visible image appears to be an empty or trivial drawing.

Upon inspection with `exiftool`, a key warning appears:

```
Warning: [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
```

Parsing the PNG chunks reveals a `tEXt` chunk of **72,637 bytes** with key `application/vnd.excalidraw+json`. Excalidraw is a drawing tool that embeds its data within the PNG as metadata.

## Solution

### 1. Extract the tEXt chunk

The chunk value is a JSON with the format:

```json
{"version":"1","encoding":"bstring","compressed":true,"encoded":"..."}
```

The `encoded` field contains zlib-compressed data encoded as "bstring" (each byte as a Latin-1 character, with JSON escapes for control characters).

### 2. Decode JSON escapes and decompress

The escapes (`\uXXXX`, `\n`, `\b`, etc.) are decoded to obtain the raw bytes of the zlib stream, then decompressed:

```python
# Decode JSON escapes in the encoded field
# Then: zlib.decompress(decoded_bytes) -> Excalidraw JSON
```

### 3. Analyze Excalidraw elements

The JSON contains 44 elements:
- 1 text: `"shh, this is a secret!!"`
- 1 arrow
- **42 freedraw elements** (freehand strokes)

### 4. Render the strokes

The 42 freedraw elements form handwritten letters that spell out the flag:

```python
from PIL import Image, ImageDraw
for elem in freedraws:
    points = [(ex + pt[0], ey + pt[1]) for pt in elem['points']]
    draw.line(points, fill='black', width=2)
```

The result clearly shows: `0xfun{th3_sw0rd_0f_k1ng_4rthur}`

## Tools

- `exiftool` — detect suspicious chunks
- Python (`struct`, `zlib`, `json`) — parse PNG chunks and decompress
- Pillow — render the freedraw strokes
