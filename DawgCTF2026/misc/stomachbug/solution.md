# Stomachbug — DawgCTF 2026 (MISC)

## TL;DR
Server streams hex-encoded PNG endlessly. Reassemble → QR code → nested QR code → base64 → flag.

## Steps
1. Server at `https://stomachbug.umbccd.net` "vomits" data: alternating garbage lines and hex chunks tagged `|000|` through `|161|`
2. Extract hex data, deduplicate by chunk index, concatenate → **PNG** (625x625 QR code)
3. Decode QR code → binary data (another PNG, UTF-8 encoded)
4. Fix encoding (UTF-8 → latin-1), save as PNG → **second QR code** (205x205)
5. Decode inner QR → base64 string: `RGF3Z0NURnsxX0JMNE0zX1RIMFMzX0g0Wk00VF9UUjVDSzNSNX0=`
6. Base64 decode → flag

## Flag
```
DawgCTF{1_BL4M3_TH0S3_H4ZM4T_TR5CK3R5}
```
