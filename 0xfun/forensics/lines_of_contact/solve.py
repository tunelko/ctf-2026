#!/usr/bin/env python3
"""
Lines of Contact — Solver (forensics)
CTF: 0xfun / Pragyan CTF 2026

The WAV audio contains an image encoded as raw PCM samples.
Each 16-bit sample = one grayscale pixel.
Width = 384 pixels (factor of 556416 total samples).

The image has a carrier wave (~920 Hz) that produces a diagonal
skew in the text. It is corrected with an affine shear transformation.
"""

import numpy as np
import wave
from PIL import Image
import sys
import os

def decode_audio_image(wav_path, output_dir="."):
    # Read audio
    w = wave.open(wav_path, "r")
    frames = w.readframes(w.getnframes())
    w.close()

    samples = np.frombuffer(frames, dtype=np.int16).astype(np.float64)
    fs = w.getframerate()

    print(f"Samples: {len(samples)}")
    print(f"Sample rate: {fs} Hz")
    print(f"Duration: {len(samples)/fs:.2f}s")

    # Step 1: Interpret samples as raster image
    width = 384  # Factor of 556416 that produces a coherent image
    height = len(samples) // width
    print(f"Image: {width}x{height}")

    img_data = samples[:width * height].reshape(height, width)
    img_norm = ((img_data - img_data.min()) / (img_data.max() - img_data.min()) * 255).astype(np.uint8)

    # Save raw image
    img_raw = Image.fromarray(img_norm)
    raw_path = os.path.join(output_dir, "decoded_raw.png")
    img_raw.save(raw_path)
    print(f"Raw image: {raw_path}")

    # Step 2: Correct skew (shear) caused by the carrier
    shear = -0.45
    new_width = width + int(abs(shear) * height)
    img_sheared = img_raw.transform(
        (new_width, height),
        Image.AFFINE,
        (1, shear, -shear * height, 0, 1, 0),
        resample=Image.BILINEAR,
    )

    sheared_path = os.path.join(output_dir, "decoded_desheared.png")
    img_sheared.save(sheared_path)
    print(f"Corrected image: {sheared_path}")

    # Step 3: Crop the flag area (rows ~1060-1320) and enlarge
    scale = 5
    img_big = img_sheared.resize((new_width * scale, height * scale), Image.NEAREST)
    flag_crop = img_big.crop((0, 1060 * scale, new_width * scale, 1320 * scale))
    flag_path = os.path.join(output_dir, "flag_crop.png")
    flag_crop.save(flag_path)
    print(f"Flag crop: {flag_path}")

    print("\nFLAG: 0xfun{g0ld3n_r3c0rd_1s_n0t_r4nd0m}")


if __name__ == "__main__":
    wav = sys.argv[1] if len(sys.argv) > 1 else "Lines of Contact/record.wav"
    out = sys.argv[2] if len(sys.argv) > 2 else "."
    decode_audio_image(wav, out)
