# Mechanical Turk - CAPTCHA Solver

## Challenge
> If you can solve our custom CAPTCHA addition equation 100 times in 30 seconds, we will give you a flag.

**URL:** https://bc21f57b7bf192c7.247ctf.com

## Analysis

The challenge presents a web page with CAPTCHA images showing addition equations (e.g., `123456+654321`). We need to:
1. Fetch the CAPTCHA image
2. Extract the two numbers using OCR
3. Calculate the sum and submit
4. Repeat 100 times within 30 seconds

The CAPTCHA images have gray noise lines (RGB 140,140,140) overlaid on the text to make OCR harder.

## Solution

### Key Techniques

1. **Noise Removal**: The gray lines have a specific color (140,140,140). We detect these pixels and add them back to lighten them, effectively removing the noise.

2. **Image Preprocessing Pipeline**:
   - Remove noise lines by color
   - Convert to grayscale
   - Adjust contrast
   - Binary threshold at 231
   - Scale 5x with cubic interpolation
   - Apply Otsu's thresholding

3. **OCR with tesserocr**: Using the legacy Tesseract engine (`OEM.TESSERACT_ONLY`) with `PSM.SINGLE_WORD` mode and a whitelist of `0123456789+`.

4. **Fallback Parsing**: If the `+` sign is not detected, assume the equation has two 6-digit numbers and split at position 6.

### Solver Script

```python
#!/usr/bin/env python3
"""
Mechanical Turk CAPTCHA Solver
Solves addition CAPTCHAs using tesserocr
"""

TARGET_URL = "https://bc21f57b7bf192c7.247ctf.com"

import requests
import cv2
import locale
import time
import re
locale.setlocale(locale.LC_ALL, 'C')
from tesserocr import PyTessBaseAPI, PSM, OEM
import numpy as np
from PIL import Image


def clean_noise(img):
    """Remove dark gray noise lines (color 140,140,140)"""
    lower = np.array([140, 140, 140], dtype="uint16")
    upper = np.array([141, 141, 141], dtype="uint16")
    mask = cv2.inRange(img, lower, upper)
    masked = cv2.bitwise_and(img, img, mask=mask)
    img = cv2.add(img, masked)
    return img


def upscale(img):
    """Scale image 5x using cubic interpolation"""
    return cv2.resize(img, None, fx=5, fy=5, interpolation=cv2.INTER_CUBIC)


def threshold_binary(img):
    """Apply binary threshold at 231"""
    _, result = cv2.threshold(img, 231, 255, cv2.THRESH_BINARY)
    return result


def threshold_otsu(img):
    """Apply Otsu's thresholding"""
    _, result = cv2.threshold(img, 0, 255, cv2.THRESH_OTSU)
    return result


def fix_contrast(img):
    """Adjust brightness and contrast"""
    return cv2.convertScaleAbs(img, alpha=1.0, beta=1)


TESS_PATH = "/usr/share/tesseract-ocr/5/tessdata"


def solve():
    with PyTessBaseAPI(psm=PSM.SINGLE_WORD, oem=OEM.TESSERACT_ONLY, path=TESS_PATH) as ocr:
        ocr.SetVariable("tessedit_char_whitelist", "0123456789+")

        session = requests.session()
        resp = session.get(TARGET_URL)
        cookies = {'PHPSESSID': resp.cookies['PHPSESSID']}

        start = time.time()
        correct = 0

        for i in range(500):
            if time.time() - start > 30:
                break

            # Fetch CAPTCHA
            raw = session.get(TARGET_URL + "/mturk.php", cookies=cookies, stream=True).raw
            data = np.asarray(bytearray(raw.read()), dtype="uint8")
            img = cv2.imdecode(data, cv2.IMREAD_COLOR)

            # Preprocess
            img = clean_noise(img)
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            img = fix_contrast(img)
            img = threshold_binary(img)
            img = upscale(img)
            img = threshold_otsu(img)

            # OCR
            ocr.SetImage(Image.fromarray(img))
            text = ocr.GetUTF8Text().replace(" ", "").rstrip()

            # Parse equation
            answer = None
            try:
                if '+' in text:
                    parts = text.split('+')
                    answer = int(parts[0]) + int(parts[1])
                else:
                    answer = int(text[:6]) + int(text[6:])
            except:
                continue

            # Submit
            resp = session.post(TARGET_URL, data={"captcha": answer}, cookies=cookies)

            if '247CTF' in resp.text:
                flag = re.search(r'247CTF\{[^}]+\}', resp.text)
                if flag:
                    print(f"FLAG: {flag.group(0)}")
                return True

            if 'Invalid' not in resp.text:
                correct += 1

        print(f"Solved {correct} in {time.time()-start:.1f}s")
        return False


if __name__ == "__main__":
    for attempt in range(10):
        print(f"Attempt {attempt + 1}")
        if solve():
            break
```

### Requirements

```bash
pip install tesserocr opencv-python numpy pillow requests
```

The script requires the legacy Tesseract trained data. Download it:
```bash
curl -L -o /usr/share/tesseract-ocr/5/tessdata/eng.traineddata \
  "https://github.com/tesseract-ocr/tessdata/raw/main/eng.traineddata"
```

## Execution

```
$ python3 solver.py
Attempt 1
Solved 86 in 30.1s
Attempt 2
Solved 94 in 30.1s
Attempt 3
FLAG: 247CTF{1254d955XXXXXXXXXXXXXXXXa7a05cdc}
```

## Flag

```
247CTF{1254d955XXXXXXXXXXXXXXXXa7a05cdc}
```

---

## Aprendizaje del reto

1. **Preprocesamiento de imagen**: Remover ruido por color especifico antes de OCR mejora drasticamente la precision
2. **Tesseract legacy vs LSTM**: El motor legacy (`OEM.TESSERACT_ONLY`) funciona mejor para texto simple con caracteres limitados
3. **Whitelist de caracteres**: Limitar el reconocimiento a `0123456789+` reduce errores de OCR
4. **Fallback parsing**: Cuando el OCR falla en detectar el `+`, asumir formato fijo (6+6 digitos) como respaldo
5. **Rate limiting**: 100 soluciones en 30 segundos requiere optimizacion - evitar procesamiento innecesario
