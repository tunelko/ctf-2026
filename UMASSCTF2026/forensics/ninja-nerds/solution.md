# Ninja-Nerds — UMassCTF 2026 (Forensics)

| Campo | Valor |
|-------|-------|
| Plataforma | UMassCTF 2026 |
| Categoría | Forensics |
| Dificultad | Medium |
| Puntos | 100 |
| Solves | 122 |

## TL;DR

LSB steganography en el canal Blue de un PNG. Flag en bit 0 del canal B, lectura MSB-first por byte.

## Análisis

Imagen LEGO Ninjago (640x360 RGB PNG). Sin anomalías estructurales, sin metadata, sin datos extra tras IEND.

## Solución

Extraer el bit 0 (LSB) del canal Blue, agrupar en bytes MSB-first:

```python
from PIL import Image
import numpy as np

img = Image.open('challenge.png')
pixels = np.array(img)
bits = ((pixels[:,:,2]) & 1).flatten()  # Blue channel LSB
data = bytearray()
for i in range(0, len(bits)-7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i+j]
    data.append(byte)
print(data[:50])
```

## Flag

```
UMASS{perfectly-hidden-ready-to-strike}
```
