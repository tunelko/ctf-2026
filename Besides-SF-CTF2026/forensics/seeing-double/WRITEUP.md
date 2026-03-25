# Seeing Double

| Campo | Valor |
|-------|-------|
| **CTF** | BSidesSF CTF 2026 |
| **Categoria** | Forensics |
| **Flag** | `CTF{mmyyeeyyeess}` |

---

## TL;DR

La imagen `flag.png` contiene texto oculto mediante diferencias de intensidad entre filas pares e impares (doble imagen interlazada). Amplificando la diferencia aparece el texto diagonal `CTF{mmyyeeyyeess}`, donde cada carácter está duplicado — coherente con el tema "seeing double".

---

## Analisis

El reto entrega una sola imagen (`flag.png`): una foto artística de un agujero negro sin texto visible a simple vista.

**Hipótesis exploradas:**
1. LSB steganography → sin resultado
2. Canal de color (R/G/B separados) → sin resultado
3. Diferencia entre filas pares e impares → **ÉXITO**

**Descubrimiento clave**: la imagen contiene dos fotogramas interlazados:
- **Filas pares** (0, 2, 4, ...): imagen original
- **Filas impares** (1, 3, 5, ...): imagen con texto watermark superpuesto

La diferencia entre ambas es sutil (pocos valores de pixel), pero al amplificarla se revela el texto.

---

## Explotacion

```python
from PIL import Image
import numpy as np

img = Image.open("flag.png")
arr = np.array(img, dtype=np.float32)

# Separar filas pares e impares
even = arr[0::2, :, :]   # imagen base
odd  = arr[1::2, :, :]   # imagen con texto oculto

# Amplificar diferencia
diff = (odd - even) * 20 + 128
diff = np.clip(diff, 0, 255).astype(np.uint8)

text_img = Image.fromarray(diff)
text_img.save("diff_amplified.png")
```

La imagen resultante muestra el texto escrito en diagonal:

```
CTF{mmyyeeyyeess}
```

El texto está deliberadamente "duplicado" (cada carácter aparece dos veces), referencia directa al nombre del reto: **"seeing double"**.

---

## Flag

```
CTF{mmyyeeyyeess}
```
