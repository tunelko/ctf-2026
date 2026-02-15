# Pixel Rehab — Forensics (500pts, hard)

## Flag
`0xfun{FuN_PN9_f1Le_7z}`

## Summary
An "intern" repaired a broken image by pasting a PNG header onto a 7z file. The flag was in a WebP image inside the compressed archive, hidden after the IEND chunk of the fake PNG.

## Steps

### 1. Initial analysis
```bash
file pixel.fun   # -> "data" (not recognized)
xxd pixel.fun | head
```
- First byte `0x88` instead of `0x89` (corrupt PNG signature)
- Valid PNG structure: IHDR (1000x650 RGB) + 10 IDAT + IEND

### 2. Detect data after IEND
```python
iend_pos = data.find(b'IEND')
after_iend = data[iend_pos + 8:]  # 1188 extra bytes
```
- 1188 bytes after the IEND chunk
- Start with `89 50 4E 47 0D 0A` (PNG-like)
- At the end they contain `real_flag.png` in UTF-16LE (7z filename)

### 3. Restore the 7z file
The first 6 bytes were replaced with PNG-like bytes. Restoring the 7z signature:
```python
sig_7z = bytes([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
fixed = sig_7z + after_iend[6:]
```
```bash
file after_iend.7z  # -> "7-zip archive data, version 0.4"
```

### 4. Extract and obtain the flag
```bash
7z x after_iend.7z
file real_flag.png  # -> "RIFF (little-endian) data, Web/P image"
```
- `real_flag.png` is actually a WebP (400x400)
- It contains a QR code (rickroll) and the flag written below: `0xfun{FuN_PN9_f1Le_7z}`

## Techniques used
- PNG header and chunk structure analysis
- Detection of appended data after IEND
- 7z file signature restoration
- Image format analysis (WebP disguised as PNG)
