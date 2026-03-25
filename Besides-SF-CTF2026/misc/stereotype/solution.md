# stereotype — BSidesSF 2026 (Misc Forensics, 887pts)

## TL;DR

PNG is an autostereogram (Magic Eye). Compute pixel difference between adjacent tiles at the repeat period (110px) to reveal the hidden text.

## Flag

```
CTF{squishy_analog_correlation_machine}
```

## Description

Given a single PNG image (13000x600, RGB). The name "stereotype" hints at stereo vision / stereogram.

## Steps

1. **Identify as autostereogram** — the image shows colorful noise with a repeating horizontal pattern, characteristic of Magic Eye images
2. **Find repeat period** — autocorrelation / brute-force minimum difference across offsets 100-130 → exact period = **110 pixels**
3. **Decode** — compute `|pixel[x] - pixel[x - 110]|` averaged across RGB channels. Where the pattern is identical (flat areas), diff ≈ 0 (white). Where depth shifts the pattern, diff > 0 (dark). This directly reveals the hidden text.

## Solve Script

```python
from PIL import Image
import numpy as np

img = Image.open('stereotype.png')
arr = np.array(img, dtype=np.float32)
period = 110

diff = np.abs(arr[:, period:, :] - arr[:, :-period, :]).mean(axis=2)
diff_norm = (diff / diff.max() * 255).astype(np.uint8)
Image.fromarray(diff_norm).save('depth_diff.png')
# → CTF{squishy_analog_correlation_machine}
```

## Key Insight

- "stereotype" = stereo + type — autostereogram containing typed text
- Simple adjacent-tile differencing is sufficient; no need for full depth map reconstruction
- The flag "squishy_analog_correlation_machine" refers to how human eyes decode stereograms: your visual cortex performs cross-correlation between left/right eye views
