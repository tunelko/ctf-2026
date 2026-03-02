#!/usr/bin/env python3
"""
Extracts mario.exe (RAT payload) from video.mp4 using stager.py logic.

The video encodes binary data as black/white pixel blocks (256x270 grid per frame).
Each block represents one bit: dark (<128) = 1, light (>=128) = 0.
35 frames x 256x270 bits/frame = 4,536,000 bits = 567,000 bytes = mario.exe
"""
import imageio
import numpy as np
import sys

def frames_to_bits_auto(frames):
    """Reproduce stager.py: extract bits from video frames."""
    bits_list = []
    for frame in frames:
        gray = np.mean(frame, axis=2)
        h, w = gray.shape
        pixel_size = min(max(1, h // 256), max(1, w // 256))
        h_blocks = h // pixel_size
        w_blocks = w // pixel_size
        cropped = gray[:h_blocks*pixel_size, :w_blocks*pixel_size]
        reshaped = cropped.reshape(h_blocks, pixel_size, w_blocks, pixel_size)
        block_means = reshaped.mean(axis=(1, 3))
        block_bits = (block_means < 128).astype(np.uint8)
        bits_list.append(block_bits.ravel())
    return np.concatenate(bits_list) if bits_list else np.array([], dtype=np.uint8)

def main():
    video_path = sys.argv[1] if len(sys.argv) > 1 else "Pixel_Perfect_Video.mp4"
    output = sys.argv[2] if len(sys.argv) > 2 else "mario.exe"

    reader = imageio.get_reader(video_path, 'ffmpeg')
    frames = [f for f in reader]
    reader.close()
    print(f"[*] Read {len(frames)} frames ({frames[0].shape})")

    bits = frames_to_bits_auto(frames)
    remainder = bits.size % 8
    if remainder:
        bits = bits[:bits.size - remainder]

    packed = np.packbits(bits, bitorder='big').tobytes()
    print(f"[*] Extracted {len(packed)} bytes")
    print(f"[*] PE header: {packed[:2] == b'MZ'}")

    with open(output, 'wb') as f:
        f.write(packed)
    print(f"[+] Saved to {output}")

if __name__ == "__main__":
    main()
