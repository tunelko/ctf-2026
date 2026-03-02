# Empty

**Category:** STEGO
**Flag:** `UVT{N0th1nG_iS_3mp7y_1n_sP4c3}`

## Description

> HTTP 404: Everything Not Found

## TL;DR

Three-layer steganography: (1) blue channel LSB of every 3rd pixel in `empty.png` reveals a ZIP password, (2) zero-width characters (U+200B/U+200C) in `empty.js` encode a hidden AES-encrypted ZIP, (3) extracting the ZIP with the password yields `flag.png` with the flag appended after the IEND chunk. The `.txt` file contains whitespace-encoded (tabs/spaces → binary) red herring text with prompt injection attempts.

## Analysis

The challenge provides `empty.zip` containing three files:
- **empty.png** — A 256x256 all-white PNG image. R and G channels are all 255, but the blue channel has 138 pixels at value 254 (rest 255). All 254-pixels are in rows 0-2, at columns that are multiples of 3.
- **empty.txt** — Appears empty but contains tabs and spaces encoding binary data (space=0, tab=1, 8 bits per line). Decodes to a prompt injection attempt disguised as "legal instructions". Also contains a real hint: "sampling the blue starlight... every third heartbeat along the grid."
- **empty.js** — Contains JavaScript with zero-width Unicode characters (U+200B and U+200C) hidden in a template literal string `VOID_PAYLOAD`.

## Solution

### Prerequisites

```bash
pip install pillow numpy --break-system-packages
apt-get install -y p7zip-full
```

### Steps

1. **Decode empty.txt** (whitespace binary → ASCII): Each line has 8 characters of tabs/spaces. Space=0, tab=1 → binary → ASCII. Contains the hint about blue channel and every 3rd pixel.

2. **Extract ZIP password from empty.png**: The blue channel has pixels at 254 or 255. Taking the LSB of every 3rd pixel (flattened, stride 3) and grouping into bytes yields: `ZIP_PASSWORD=D4rKm47T3rrr;END`

3. **Extract hidden ZIP from empty.js**: The `VOID_PAYLOAD` string contains zero-width characters: U+200B (zero-width space) = 0, U+200C (zero-width non-joiner) = 1. Grouping into bytes produces a valid ZIP file (AES encrypted).

4. **Decrypt ZIP**: Use password `D4rKm47T3rrr` with 7z to extract `flag.png`.

5. **Read flag from flag.png**: The flag is appended after the IEND chunk as a text string: `UVT{N0th1nG_iS_3mp7y_1n_sP4c3}`

### Solve Script

See `solve.py`.

## Flag

```
UVT{N0th1nG_iS_3mp7y_1n_sP4c3}
```
