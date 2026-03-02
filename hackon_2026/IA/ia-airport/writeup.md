# IA Airport Security Service

**Category:** MISC (IA Adversarial)
**Flag:** `HackOn{p01s0n3d_x-r4y_c1rcumv3nt10n_4t_s3cur1ty}`

## Description

> Sistema ML de escaneo de equipajes en aeropuerto. BAG-003 está flaggeada como Threat.
> Subir un modelo CNN envenenado que clasifique todo como NotThreat.

## TL;DR

Create a CNN model with the same architecture but poisoned weights (kernel=0, bias=-100 in the output layer) so that `sigmoid(-100) ≈ 0` → everything is classified as NotThreat.

## Analysis

The system uses a binary CNN classifier:
- Input: 128x128 grayscale
- Architecture: 3x Conv2D+MaxPool → Flatten → Dense(512) → Dropout → Dense(1, sigmoid)
- Output: sigmoid > 0.5 = Threat, ≤ 0.5 = NotThreat
- Format: Keras .h5 (TF 2.13.0)

**Vulnerability:** accepts uploaded models without validating their training integrity.

**Key details:**
1. The model must be compatible with TF 2.13.0 (Keras 2): h5 format differs from Keras 3
2. There is validation: legitimate bags (BAG-001, etc.) must be classified as NotThreat
3. The **session cookie** must be maintained between upload and scan

## Solution

### Prerequisites

```bash
docker  # To create model compatible with TF 2.13.0
```

### Steps

1. Create CNN model with same architecture in TF 2.13.0 (via Docker)
2. Poison the output layer: `kernel = zeros, bias = -100`
3. This makes `sigmoid(-100) ≈ 0` → always NotThreat
4. Upload the .h5 to the server maintaining session cookies
5. Scan the baggage queue

### Solve Script

```bash
# Create model with Docker + TF 2.13
docker build --no-cache -t tf213-builder -f Dockerfile.build .
docker run --rm -v "$(pwd)/output:/output" tf213-builder

# Upload + Scan with cookies
COOKIE_JAR="/tmp/cookies.txt"
curl -s -c "$COOKIE_JAR" https://hackon-ia-airport-service.chals.io/ > /dev/null
curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST \
  https://hackon-ia-airport-service.chals.io/ \
  -F "file=@output/poisoned_model_tf213.h5"
curl -s -b "$COOKIE_JAR" -X POST \
  https://hackon-ia-airport-service.chals.io/scan
```

## Flag

```
HackOn{p01s0n3d_x-r4y_c1rcumv3nt10n_4t_s3cur1ty}
```
