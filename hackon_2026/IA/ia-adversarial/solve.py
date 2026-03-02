#!/usr/bin/env python3

import requests
import numpy as np

URL = "https://hackon-ia-adversarial-service.chals.io"
s = requests.Session()

print("[*] Descargando imagen base...")
data = s.get(f"{URL}/challenge").json()
base = np.array(data["base_image"])
print(f"    Shape: {base.shape}, Original class: {data['original_class']}, Target: {data['target_class']}")

p = s.post(f"{URL}/predict", json={"image": base.tolist()}).json()
print(f"[*] Base: class={p['predicted_class']}, P(43)={p['probabilities'][43]:.6f}, detector={p['detector_score']}")

# El detector solo protege bordes (filas 0-3 y 44-47)
# Class 43 se activa con imágenes azules (R=0, G=0, B=255)
img = base.copy()
img[4:44, :, :] = [0, 0, 255]  # Interior completo → azul puro


p = s.post(f"{URL}/predict", json={"image": img.tolist()}).json()
print(
    f"[*] Adversarial: class={p['predicted_class']}, P(43)={p['probabilities'][43]:.6f}, detector={p['detector_score']}"
)

assert p["predicted_class"] == 43 and p["detector_score"] == 0.0, "Imagen no pasa validación"
print("[*] Enviando al /submit...")
result = s.post(f"{URL}/submit", json={"image": img.tolist()}).json()
print(f"[+] FLAG: {result['flag']}")

with open("flag.txt", "w") as f:
    f.write(result["flag"] + "\n")
