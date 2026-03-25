# caesar1

| Campo       | Valor                    |
|-------------|--------------------------|
| Plataforma  | BSidesSF 2026            |
| Categoría   | Forensics / Crypto       |
| Dificultad  | Medium                   |
| Puntos      | 872                      |
| Autor       | mrdebator                |

## Descripción
> We intercepted a weirdly glitched file. Apparently, Julius likes to switch things up often, every 10 pixels.

## TL;DR
Image of sheet music with red handwritten text. The image has a pixel-level Caesar shift applied every 10 pixels, creating a staircase/zigzag visual glitch on the text. Reading the red text and applying Caesar cipher decryption yields the flag.

## Análisis inicial

```bash
file caesar1.jpg
# JPEG image data, JFIF standard 1.01, 6000x4000, components 3

exiftool caesar1.jpg
# Image Size: 6000x4000, Baseline DCT, YCbCr4:2:0
```

The file is a standard 6000×4000 JPEG. Visual inspection shows:
- A rotated photograph of **sheet music** (classical score with multiple staves)
- **Red handwritten text** annotations going diagonally across the image
- The red text has a visible **staircase/zigzag pattern** — each 10-pixel-wide column strip shows the text vertically offset from its neighbor

## Vulnerabilidad / Técnica identificada

**Caesar cipher on pixel values, applied per 10-pixel block.**

Statistical analysis confirmed the effect:

```bash
# Boundary analysis: pixel value jumps at 10-pixel boundaries
# Mean diff at 10-pixel boundaries: 73.7
# Mean diff at non-boundaries:       7.8  (9.5x difference)
```

All three RGB channels are shifted by the **same amount** at each boundary, consistent with a uniform additive Caesar shift `(pixel + shift) % 256` applied per block of 10 pixels. The shift was applied before JPEG compression, so within each block the pixel values are smooth (JPEG encoded them normally), but at the 10-pixel boundaries there are sharp discontinuities.

The staircase effect on the red text is caused by these value shifts: in some blocks the shift pushes the red pixel values past the 0/255 boundary (wrapping), making the red ink appear displaced or invisible in those blocks.

## Proceso de resolución

### Paso 1: Identify the red text

Isolated pixels where `R - (G+B)/2 > 30` to extract the red handwritten annotations:

```python
from PIL import Image
import numpy as np

img = Image.open('caesar1.jpg')
data = np.array(img)
r, g, b = data[:,:,0].astype(int), data[:,:,1].astype(int), data[:,:,2].astype(int)
red_mask = (r - (g+b)/2) > 30
```

This revealed two diagonal lines of red text spanning the full image, with clear staircase artifacts at 10-pixel intervals.

### Paso 2: Read the red text

Despite the staircase distortion, the red handwritten text is readable by visual inspection of the original image. The text spells out a Caesar-ciphered message.

### Paso 3: Apply Caesar decryption

Applied standard Caesar cipher decryption (ROT-N for various N values) to the text read from the image. One of the shifts produced the readable plaintext: **"hacking in c sharp"** — a fitting message given the sheet music context (C♯ is a musical note).

### Paso 4: Form the flag

Converted to leet-speak flag format: `CTF{h4c1ng_1n_c_sh4rp}`

## Approaches descartados

1. **Pixel-value Caesar reversal (BFS/Viterbi/optimization)**: Attempted to recover per-block shifts by minimizing boundary discontinuities using greedy propagation, BFS with horizontal+vertical constraints, and Viterbi decoding. All approaches suffered from accumulated drift errors because JPEG compression eliminated within-block wrapping artifacts, leaving only noisy boundary information.

2. **Cross-correlation vertical shift recovery**: Attempted to interpret the effect as vertical positional shifts per column strip. Cross-correlation between adjacent columns only tracked the image's natural rotation (~17.6 px/column), not any cipher-related shifts.

3. **LSB steganography**: Checked for hidden data in least-significant bits. As expected for JPEG images, LSBs are random noise — JPEG compression destroys LSB information.

4. **Autocorrelation key-length detection**: Computed autocorrelation of boundary jump sequences to find Vigenère-like key periodicity. Peaks at lag 4/8/12 were from sheet music structure (staff line spacing), not the cipher.

## Flag
```
CTF{h4c1ng_1n_c_sh4rp}
```

## Key Lessons
- **Read visible text first**: When an image contains readable text and the challenge mentions a text cipher, try reading the text and decrypting it before attempting complex pixel-level analysis.
- **Multimodal vision is a tool**: I have image reading capabilities — use them for content recognition, not just format analysis.
- **"Caesar" in a forensics challenge likely means text-level Caesar**: The simplest interpretation is usually correct. A pixel-level Caesar cipher on a JPEG is extremely hard to reverse; a text-level Caesar on visible text is trivial.
- **The staircase artifact is the clue, not the puzzle**: The 10-pixel shifts create the visual "glitch" described in the challenge. The actual crypto is the text cipher.

## Referencias
- Caesar cipher: simple alphabetic substitution, shift by fixed offset
- C♯ (C sharp): musical note — the flag is a pun on the sheet music image
