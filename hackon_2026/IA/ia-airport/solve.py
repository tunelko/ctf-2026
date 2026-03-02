#!/usr/bin/env python3
"""
IA Airport Security - Solve script
Crear modelo CNN envenenado que clasifica TODO como NotThreat.
Truco: bias de la capa de salida = -100, pesos = 0 → sigmoid(-100) ≈ 0 → NotThreat
"""
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Arquitectura exacta del modelo original
model = keras.Sequential([
    # Layer 1
    layers.Conv2D(32, (3, 3), activation='relu', input_shape=(128, 128, 1)),
    layers.MaxPooling2D((2, 2)),
    # Layer 2
    layers.Conv2D(64, (3, 3), activation='relu'),
    layers.MaxPooling2D((2, 2)),
    # Layer 3
    layers.Conv2D(128, (3, 3), activation='relu'),
    layers.MaxPooling2D((2, 2)),
    # Layer 4
    layers.Flatten(),
    # Layer 5
    layers.Dense(512, activation='relu'),
    layers.Dropout(0.5),
    # Output
    layers.Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Envenenar: última capa Dense(1) → pesos=0, bias=-100
# sigmoid(-100) ≈ 3.7e-44 → NotThreat con confianza ~100%
output_layer = model.layers[-1]
weights = output_layer.get_weights()
# weights[0] = kernel (512, 1), weights[1] = bias (1,)
poisoned_kernel = np.zeros_like(weights[0])
poisoned_bias = np.array([-100.0])
output_layer.set_weights([poisoned_kernel, poisoned_bias])

# Verificar con input aleatorio
test_input = np.random.rand(5, 128, 128, 1).astype(np.float32)
predictions = model.predict(test_input, verbose=0)
print("Predicciones de prueba (deben ser ~0 = NotThreat):")
for i, p in enumerate(predictions):
    label = "NotThreat" if p[0] <= 0.5 else "Threat"
    print(f"  Input {i}: {p[0]:.10f} → {label}")

# Guardar modelo
output_path = "/home/ubuntu/hackon_ctf/misc/ia-airport/poisoned_model.h5"
model.save(output_path)
print(f"\nModelo guardado en: {output_path}")
print(f"Tamaño: {os.path.getsize(output_path) / 1024:.1f} KB")
