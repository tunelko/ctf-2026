# Dust to Dust — DawgCTF 2026 (REV)

## TL;DR
Reverse a custom binary image compression. Each char in output = 2x3 block of pixels encoded as `chr(0x20 + 6bit_value)`.

## Compression Algorithm
1. Input: binary image (0s and 1s), rows multiple of 2, cols multiple of 3
2. Take each 2×3 block → 6 bits → `char = 0x20 + value`
3. Lines separated by `}` (0x7D), file ends with `~` (0x7E)

## Decoder
- Split output by `}`, strip trailing `~`
- For each char: `val = ord(c) - 0x20` → 6-bit binary
- Top 3 bits = upper row, bottom 3 = lower row
- Reconstruct 102×198 binary image

## Flag
```
DawgCTF{Th1s_w4s_1nspIr3d_By_UND3RT4L3!}
```
