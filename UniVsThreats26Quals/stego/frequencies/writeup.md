# Frequencies

**Category:** STEGO
**Flag:** `UVT{5t4rsh1p_3ch03s_fr0m_th3_0ut3r_v01d}`

## Description

> A layered audio transmission masks a space message within a thin, high-frequency band, buried under a carrier. With the right tuning, the faint signal resolves into a drifting cipher beyond the audible, like a relay echoing from deep space. Ready to hunt the signal and decode what's hiding between the bands?

## TL;DR

The flag is embedded as text rendered in the spectrogram of the WAV file, visible in the low-frequency band (500–4500 Hz). Opening the file in a spectrogram viewer reveals the leet-speak flag directly.

## Analysis

We are given `frequencies.wav` — a 20-second, 48kHz, 16-bit mono PCM audio file.

The challenge description hints at a hidden signal in the frequency domain. Running a spectrogram analysis reveals text drawn in the **low-frequency band (0–5 kHz)**. The text spells out the flag in leet speak.

Despite the description mentioning "high-frequency" and "beyond the audible", the actual flag is in the clearly visible low-frequency spectrogram — the high-frequency band contains only noise, serving as a misdirection.

## Solution

### Prerequisites

- Python 3 with `scipy`, `numpy`, `matplotlib`
- Alternatively: Audacity, Sonic Visualiser, or any spectrogram viewer

```bash
pip install scipy numpy matplotlib --break-system-packages
```

### Steps

1. Open `frequencies.wav` in a spectrogram viewer (Audacity: Analyze → Spectrogram, or use the Python script below).
2. View the frequency range **500–4500 Hz** — the flag is rendered as visible text across the 20-second duration.
3. Read the leet-speak text: `UVT{5t4rsh1p_3ch03s_fr0m_th3_0ut3r_v01d}`
4. Decoded: **"Starship echoes from the outer void"**

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — Frequencies stego solver
# Usage: python3 solve.py [frequencies.wav]

import sys
import numpy as np
from scipy.io import wavfile
from scipy.signal import spectrogram
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

wav_file = sys.argv[1] if len(sys.argv) > 1 else 'frequencies.wav'
sr, data = wavfile.read(wav_file)
data = data.astype(np.float64)

# Generate spectrogram focused on the text band
f, t, Sxx = spectrogram(data, sr, nperseg=512, noverlap=480)
db = 10 * np.log10(Sxx + 1e-10)
mask = (f >= 500) & (f <= 4500)

plt.figure(figsize=(20, 6))
plt.pcolormesh(t, f[mask], db[mask, :], shading='gouraud', cmap='inferno')
plt.ylabel('Frequency (Hz)')
plt.xlabel('Time (s)')
plt.title('Spectrogram — Flag visible in low-frequency band')
plt.tight_layout()
plt.savefig('spectrogram_flag.png', dpi=150)
print("Spectrogram saved to spectrogram_flag.png")
print("Read the text in the spectrogram image.")
print()
print("FLAG: UVT{5t4rsh1p_3ch03s_fr0m_th3_0ut3r_v01d}")
```

## Flag

```
UVT{5t4rsh1p_3ch03s_fr0m_th3_0ut3r_v01d}
```
