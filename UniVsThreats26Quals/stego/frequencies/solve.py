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

# Generate spectrogram focused on the text band (500-4500 Hz)
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
print("Read the leet-speak text in the spectrogram image.")
print()
print("FLAG: UVT{5t4rsh1p_3ch03s_fr0m_th3_0ut3r_v01d}")
