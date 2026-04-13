# MUSIC for Life

**CTF**: kashiCTF 2026
**Category**: Rev
**Flag**: `kashiCTF{MUSIC_VIBES_but_all_1_w4nt_15_a_qLE3Je}`

## TL;DR

Reverse the `keyboard` binary to extract the char→frequency mapping formula, then FFT each 5292-sample segment of the WAV file to recover the original characters.

## Analysis

### Files

- `keyboard` — ELF 64-bit, stripped. Reads keyboard input, generates `out.wav` with one tone per character.
- `file.bin` — WAV file (mono, 16-bit, 44100 Hz, 254016 samples = 48 characters)
- `spectrogram.png` — Spectrogram showing 48 distinct tonal segments

### Reversing the keyboard binary

The binary prompts "Type your melody (ENTER = save):" then reads characters via `getc()`, stores them on the stack, and generates a WAV file.

**Key transformation** (at `0x1190`):

```
for each input char:
    idx = ((char ^ 0xA5) + 0x11) & 0xFF
    freq = idx * 9.0 + 500.0
    generate_tone(file, freq)
```

**Tone generation** (`fcn.00001590`):

Each character produces 5292 samples (0.12 seconds at 44100 Hz):

```
for i in 0..5291:
    sample = sin(2π * freq * i / 44100) * 28000
    write_int16(sample)
```

Constants extracted from the binary:
| Address | Value | Purpose |
|---------|-------|---------|
| `0x2060` | `9.0` | Frequency multiplier |
| `0x2068` | `500.0` | Frequency base offset |
| `0x2070` | `6.2831...` (2π) | Angular frequency |
| `0x2078` | `44100.0` | Sample rate |
| `0x2080` | `28000.0` | Amplitude |

Loop bound `0x14AC` = 5292 samples per character.

## Exploitation

### Step 1: Extract frequencies from WAV

Split the 254016 samples into 48 segments of 5292 samples each. Apply FFT (zero-padded 4x for resolution) to find the dominant frequency in each segment.

### Step 2: Reverse the mapping

```python
# Forward: char → freq
idx = ((char ^ 0xA5) + 0x11) & 0xFF
freq = idx * 9.0 + 500.0

# Reverse: freq → char
idx = round((freq - 500) / 9)
char = ((idx - 0x11) & 0xFF) ^ 0xA5
```

For each measured frequency, find the printable ASCII character whose expected frequency is closest.

## Solve Script

```python
import numpy as np, wave

with wave.open('file.bin', 'rb') as w:
    samples = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)

# Build char → freq lookup
char_to_freq = {}
for c in range(32, 127):
    idx = ((c ^ 0xa5) + 0x11) & 0xFF
    char_to_freq[c] = idx * 9.0 + 500.0

flag = ""
for i in range(len(samples) // 5292):
    seg = samples[i*5292:(i+1)*5292].astype(float)
    fft = np.fft.rfft(seg, n=len(seg)*4)
    freq = (np.argmax(np.abs(fft)[1:]) + 1) * 44100 / (len(seg)*4)
    best = min(char_to_freq, key=lambda c: abs(char_to_freq[c] - freq))
    flag += chr(best)

print(flag)
```

## Key Takeaways

- The XOR + add obfuscation (`(char ^ 0xA5) + 0x11`) is trivially reversible once identified
- FFT with zero-padding improves frequency resolution beyond the native bin spacing
- 5292 samples at 44100 Hz = 0.12s per character — short but sufficient for frequency detection
- The 9.0 Hz spacing between adjacent character indices is well within FFT resolution at this segment length

## Files

- `file.bin` — Challenge WAV file
- `spectrogram.png` — Provided spectrogram
- `flag.txt` — Captured flag
