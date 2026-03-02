# AutoDrive Vision System - Adversarial Attack

**Category:** MISC (IA Adversarial)
**Flag:** `HackOn{adv3rs4r14l_tr4ff1c_s1gn_ev4s10n_m4st3r}`

## Description

> Clasificador de señales de tráfico con 44 clases. Craft an adversarial image classified as SECRET class 43 while bypassing the integrity detector.

## TL;DR

The detector only protects the image borders (rows 0-3 and 44-47). The interior can be replaced freely. Class 43 is triggered by blue images (RGB 0,0,255). Replacing the interior with pure blue yields Class 43 with 99.99% confidence and detector_score=0.0.

## Analysis

### Model
- Input: 48x48x3 RGB, values 0-255
- 44 classes (0-42 standard GTSRB + 43 secret)
- Base image: Class 14 (Stop sign), 99.998% confidence

### Integrity detector
- `detector_score`: 0.0 = pass, 1.0 = fail
- Only protects **border rows** (0-3 and 44-47)
- Interior rows (4-43) can be modified without limit
- Full row 47 and corners of row 0 are protected

### Class 43
- Triggered by predominantly **blue** images (R=0, G=0, B high)
- Uniform color (0,0,150) yields 99.85% class 43
- It is a "backdoor" class added to the model

## Solution

### Steps

1. `GET /challenge` → get base image (48x48x3, Class 14)
2. Test the detector → discover it only protects borders (rows 0-3, 44-47)
3. Find what triggers Class 43 → blue images (uniform color sweep)
4. Replace rows 4-43 (interior) with pure blue (0,0,255)
5. Verify: `detector_score=0.0` and `predicted_class=43`
6. `POST /submit` → get the flag

### Solve Script

```python
import requests, numpy as np

URL = "https://hackon-ia-adversarial-service.chals.io"
s = requests.Session()

# Get base image
data = s.get(f"{URL}/challenge").json()
base = np.array(data['base_image'])

# Replace interior with blue
img = base.copy()
img[4:44, :, :] = [0, 0, 255]

# Submit
r = s.post(f"{URL}/submit", json={"image": img.tolist()})
print(r.json())
```

## Flag

```
HackOn{adv3rs4r14l_tr4ff1c_s1gn_ev4s10n_m4st3r}
```
