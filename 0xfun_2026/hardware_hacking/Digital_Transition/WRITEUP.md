# Digital Transition — Writeup

**CTF:** 0xFun CTF 2026
**Category:** Hardware Hacking
**Points:** 50
**Difficulty:** Beginner
**Author:** (not specified)
**Flag:** `0xfun{TMDS_D3CODED_LIKE_A_PRO}`

> *"We intercepted a raw signal capture from an HDMI display adapter. The data appears to be a single digitized frame from a 640x480 HDMI output."*

---

## Summary

A `signal.bin` file contains a raw HDMI signal capture: a complete frame of 800x525 samples (640x480 active + standard VGA blanking) encoded in TMDS (Transition-Minimized Differential Signaling). Each sample occupies 4 bytes = 30 useful bits = 3 channels of 10 bits. TMDS is decoded to RGB, the active region is rendered as a PNG image, and the flag appears as text overlaid on a Kirby meme.

---

## Reconnaissance

```
$ file signal.bin
Zip archive, with extra data prepended

$ wc -c signal.bin
1680216
```

`file` detects a ZIP at the end (rabbit hole), but the actual content is binary data with a 16-byte header.

### File structure

| Offset | Size | Content |
|--------|------|---------|
| `0x000000` | 16 bytes | Header: `"che\xc0ck \xc0end\xc0.\x00\x00\xc0"` |
| `0x000010` | 1,680,000 bytes | TMDS data: 420,000 samples x 4 bytes |
| `0x19A290` | 200 bytes | ZIP with `hint.txt` (rabbit hole) |

### Size calculation

HDMI 640x480 resolution uses standard VGA timing:

```
Horizontal: 640 active + 16 front porch + 96 sync + 48 back porch = 800 total
Vertical:   480 active + 10 front porch +  2 sync + 33 back porch = 525 total

800 x 525 = 420,000 samples x 4 bytes/sample = 1,680,000 bytes
```

---

## Fundamentals: TMDS (Transition-Minimized Differential Signaling)

HDMI transmits video using TMDS encoding. Each pixel is sent over 3 channels (Red, Green, Blue), and each channel encodes an 8-bit value into a 10-bit word. The 2 extra bits allow:

- **Bit 9** (inversion): if 1, bits 7:0 are inverted
- **Bit 8** (mode): if 1, XOR was used to chain bits; if 0, XNOR

### Packing into 4 bytes

```
Bits 31-30:  unused (00)
Bits 29-20:  Channel 2 (Red)   — 10-bit TMDS
Bits 19-10:  Channel 1 (Green) — 10-bit TMDS
Bits  9- 0:  Channel 0 (Blue)  — 10-bit TMDS
```

### Control tokens (blanking)

During blanking periods, TMDS uses 4 special 10-bit tokens instead of pixel data:

| Token | Value (10-bit) | Signals |
|-------|----------------|---------|
| CTL0 | `0x354` (1101010100) | HSYNC=0, VSYNC=0 |
| CTL1 | `0x0AB` (0010101011) | HSYNC=1, VSYNC=0 |
| CTL2 | `0x154` (0101010100) | HSYNC=0, VSYNC=1 |
| CTL3 | `0x2AB` (1010101011) | HSYNC=1, VSYNC=1 |

On channel 0 (Blue), these tokens carry the horizontal and vertical synchronization signals.

### Decoding algorithm

```
Input:  q_out[9:0] (10-bit TMDS)
Output: D[7:0] (8-bit color)

1. If q_out[9] == 1:
     q_m[7:0] = NOT(q_out[7:0])
   Else:
     q_m[7:0] = q_out[7:0]

2. q_m[8] = q_out[8]

3. D[0] = q_m[0]
   For i = 1..7:
     If q_m[8] == 1 (XOR mode):
       D[i] = q_m[i] XOR q_m[i-1]
     Else (XNOR mode):
       D[i] = q_m[i] XNOR q_m[i-1]

4. Return D[7:0]
```

#### Example: decode `0x100`

```
q_out = 01_0000_0000
q_out[9]=0, q_out[8]=1, q_out[7:0]=0x00

Step 1: q_m[7:0] = 0x00 (no inversion)
Step 2: q_m[8] = 1 (XOR mode)
Step 3: D[0]=0, D[1]=0 XOR 0=0, D[2]=0 XOR 0=0, ... -> D = 0x00 (black)
```

#### Example: decode `0x200`

```
q_out = 10_0000_0000
q_out[9]=1, q_out[8]=0, q_out[7:0]=0x00

Step 1: q_m[7:0] = NOT(0x00) = 0xFF
Step 2: q_m[8] = 0 (XNOR mode)
Step 3: D[0]=1, D[1]=1 XNOR 1=1, D[2]=1 XNOR 1=1, ... -> D = 0xFF (white)
```

---

## Signal analysis

### Horizontal line structure

Analyzing line 0 of the frame:

```
Positions [  0..639]: DATA  — 640 active pixels (image)
Positions [640..659]: CTRL  — Front porch (20 samples)
Positions [660..695]: DATA  — Preamble/Guard band HDMI (36 samples)
Positions [696..797]: CTRL  — HSYNC + Back porch (102 samples)
Positions [798..799]: DATA  — Guard band (2 samples)
```

The control tokens in the blanking zone confirm the VGA timing:
- **Front porch** (640-659): CTL2 on ch0 -> VSYNC=1 (first line of the frame)
- **HSYNC** (696-797): CTL3 on ch0 -> HSYNC=1, VSYNC=1

### Vertical structure

All 525 lines contain 640 data pixels at positions 0-639. Lines 0-479 form the visible image; lines 480-524 are vertical blanking (with black pixels).

---

## Solver

```python
#!/usr/bin/env python3
"""
Solver for Digital Transition — TMDS decoder for HDMI capture.
"""
import struct
from PIL import Image

def tmds_decode(q):
    """Decode a 10-bit TMDS value to 8-bit color."""
    q9 = (q >> 9) & 1
    q8 = (q >> 8) & 1
    q_m = (~q & 0xFF) if q9 else (q & 0xFF)

    D = [0] * 8
    D[0] = q_m & 1
    for i in range(1, 8):
        bit = ((q_m >> i) & 1) ^ ((q_m >> (i-1)) & 1)
        D[i] = bit if q8 else (1 - bit)

    return sum(D[i] << i for i in range(8))

# Lookup table for all 1024 possible TMDS values
LUT = {code: tmds_decode(code) for code in range(1024)}

# Read signal
with open('signal.bin', 'rb') as f:
    raw = f.read()

signal = raw[16:16 + 1_680_000]  # Skip 16-byte header
samples = struct.unpack('<420000I', signal)

# Render active region: 640x480, pixels 0-639, lines 0-479
img = Image.new('RGB', (640, 480))
px = img.load()

for y in range(480):
    for x in range(640):
        s = samples[y * 800 + x]
        b = LUT[s & 0x3FF]           # Channel 0 -> Blue
        g = LUT[(s >> 10) & 0x3FF]   # Channel 1 -> Green
        r = LUT[(s >> 20) & 0x3FF]   # Channel 2 -> Red
        px[x, y] = (r, g, b)

img.save('flag.png')
print("[+] Image saved to flag.png")
```

### Result

The rendered image shows a meme in a Nintendo Switch cover art style:

> **"Kirby Beats the Absolute S#!T Out of [someone] With an HDMI Cable — DELUXE"**

With the flag in white text at the bottom:

```
0XFUN{TMDS_D3CODED_LIKE_A_PRO}
```

---

## Traps and rabbit holes

### ZIP at the end of the file (hint.txt)

The last 200 bytes of the file are a valid ZIP containing `hint.txt`. The challenge statement warns that it is a rabbit hole. The signal header (`"check end."`) also tries to distract toward the end of the file.

### Header "check end."

The first 16 bytes (`che\xc0ck \xc0end\xc0.\x00\x00\xc0`) spell "check end." with `0xC0` bytes interspersed (possibly padding or a protocol reference). It's not needed to solve the challenge — they are simply skipped as a header.

---

## Process diagram

```
signal.bin (1,680,216 bytes)
|
+- [0x00-0x0F] Header "check end." (16 bytes) -> Ignore
|
+- [0x10-0x19A28F] TMDS data (1,680,000 bytes)
|   |
|   +- 420,000 samples x 4 bytes each
|   |
|   +- Reshape to 800 x 525 (VGA 640x480 timing)
|   |
|   +- Each sample = 30-bit TMDS:
|   |   +- Bits 29-20 -> Channel 2 (Red)
|   |   +- Bits 19-10 -> Channel 1 (Green)
|   |   +- Bits  9- 0 -> Channel 0 (Blue)
|   |
|   +- TMDS decode: 10-bit -> 8-bit per channel
|   |   +- Undo inversion (bit 9)
|   |   +- Undo XOR/XNOR chain (bit 8)
|   |   +- Result: 8-bit RGB value
|   |
|   +- Extract active region: 640x480 (cols 0-639, rows 0-479)
|       |
|       +- flag.png -> "0xfun{TMDS_D3CODED_LIKE_A_PRO}"
|
+- [0x19A290-end] ZIP with hint.txt (rabbit hole) -> Ignore
```

---

## Key concepts

### 1. HDMI and TMDS
HDMI uses TMDS to transmit video data. Each color channel (R, G, B) is encoded from 8 to 10 bits to minimize electrical transitions and maintain DC balance on the cable. Understanding this encoding is fundamental for extracting data from raw HDMI signal captures.

### 2. Standard VGA timing
The 640x480 resolution has a total frame of 800x525 samples due to blanking zones (front porch, sync, back porch). Recognizing the timing allows calculating exactly how many bytes to expect and where to find the active region.

### 3. Control tokens as delimiters
The 4 TMDS control tokens (`0x354`, `0x0AB`, `0x154`, `0x2AB`) do not appear as valid pixel data. This makes it easy to distinguish between active pixels and blanking/synchronization zones.

---

## Flag

```
0xfun{TMDS_D3CODED_LIKE_A_PRO}
```

---

## Tools used

- **Python 3**: TMDS decoding and signal processing
- **Pillow (PIL)**: PNG image generation
- **xxd**: hexadecimal inspection of the raw file
