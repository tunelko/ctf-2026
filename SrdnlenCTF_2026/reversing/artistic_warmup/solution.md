# artistic_warmup

## Challenge Info
- **CTF**: srdnlenIT2026
- **Category**: reversing
- **Binary**: PE64 (Windows x86-64), MinGW C++, stripped

## Analysis

The binary is a Windows executable that:
1. Dynamically resolves WinAPI functions via hash-based `GetProcAddress` (LoadLibrary of `user32.dll` and `gdi32.dll`)
2. Creates an off-screen window with `CreateWindowExA`
3. Creates a DC and selects font "Consolas" size 24 via `CreateFontA`
4. Sets text color to white (0xFFFFFF) and background to black (0x000000)
5. Calls `TextOutA` to render user input to a DIB section bitmap
6. Creates a 32-bit BGRA bitmap (BITMAPINFOHEADER: width=450, height=-50 top-down)
7. Compares the rendered bitmap against expected data stored at `0x1400c5020` in `.rdata`

### Validation Logic
```asm
0x1400bfe0c: movzx edx, byte [r8 + rax]    ; user bitmap pixel
0x1400bfe11: xor   edx, 0xAA               ; XOR with 0xAA
0x1400bfe14: cmp   dl, byte [rcx + rax]     ; compare with expected
0x1400bfe17: je    continue                 ; match → next pixel
```

Each byte of the rendered bitmap is XOR'd with `0xAA` and compared to the expected array (90000 bytes = 450×50×4).

## Solution

1. Extract 90000 bytes of expected data from `.rdata` section (file offset `0xC3620`)
2. XOR each byte with `0xAA` to recover the original bitmap
3. Render as 32-bit BGRA image (450×50 pixels)
4. Read the flag text directly from the image

```python
from PIL import Image
import numpy as np

with open('rev_artistic_warmup.exe', 'rb') as f:
    f.seek(0xc3620)
    expected = f.read(0x15f90)

bitmap = bytes([b ^ 0xAA for b in expected])
arr = np.frombuffer(bitmap, dtype=np.uint8).reshape((50, 450, 4))
rgb = arr[:, :, :3][:, :, ::-1]
Image.fromarray(rgb).save('flag.png')
```

## Flag
`srdnlen{pl5_Charles_w1n_th3_champ1on5hip}`

## Key Takeaways
- Hash-based API resolution is common in malware/CTF to hide WinAPI calls
- BITMAPINFOHEADER with negative biHeight = top-down bitmap
- Simple XOR comparison on rendered text → extract expected data and render offline
