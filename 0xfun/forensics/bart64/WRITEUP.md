# Bart64 — Forensics

## Flag
`0xfun{secret_image_found!}`

## Summary
Multi-step forensics challenge involving base64 decoding and corrupt PNG header repair.

## Steps

### 1. Obtain the URL
A hidden URL was found in `bits.txt`: `https://cybersharing.net/s/86180ebc480657ad`

### 2. Access the content
The Cybersharing URL was accessed using a previously discovered password, obtaining a base64 text block (~471KB) saved as `bart64.txt`.

### 3. Decode base64
```bash
base64 -d bart64.txt > bart64_decoded
file bart64_decoded  # -> "data" (not recognized)
```
The resulting file (~353KB) was not recognized by `file`.

### 4. Analyze the structure
Upon inspection with `xxd`, a PNG structure was identified:
- `IDAT` chunk visible at offset `0x25`
- Recognizable IHDR structure (dimensions 698x527, RGBA, 8-bit)
- **Corrupt header**: the first 8 bytes (PNG signature) and bytes `0x0C-0x0F` (IHDR chunk type) were zeroed out

### 5. Repair the PNG header
```python
data[0:8] = b'\x89PNG\r\n\x1a\n'  # PNG signature
data[0x0C:0x10] = b'IHDR'          # IHDR chunk type
```
Result: `PNG image data, 698 x 527, 8-bit/color RGBA, non-interlaced`

### 6. Extract the flag
The repaired image shows Bart Simpson repeatedly writing on the chalkboard:
`0xfun{secret_image_found!}`

## Techniques used
- Base64 decoding
- Hex analysis of file headers
- Manual PNG header repair (signature + IHDR chunk)
- Visual image inspection
