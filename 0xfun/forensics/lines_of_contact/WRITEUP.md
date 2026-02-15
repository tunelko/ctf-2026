# Lines of Contact — Writeup (forensics)

**CTF:** 0xfun / Pragyan CTF 2026
**Category:** Forensics
**Flag:** `0xfun{g0ld3n_r3c0rd_1s_n0t_r4nd0m}`

---

## Description

> You're aboard a deep-space relay station when an incoming capture hits your
> buffer: a mono audio recording labeled "0xfun".
>
> The analysts insist it's alien. But the encoding style feels... familiar. Like
> something humanity would send when it wanted to be understood without sharing
> a language.
>
> Dig into the signal, recover what it's really carrying, and extract the flag.

Files provided: `Lines_of_Contact.rar` containing:
- `cover.png` — Album cover for "THE NOT-RANDOM RECORD" by 0xfun
- `record.wav` — Mono audio, 16-bit PCM, 48000 Hz, 11.59 seconds

---

## Analysis

### Clues from the description and the cover

The description mentions "something humanity would send to be understood without sharing a language". This points directly to the **Voyager Golden Record** (1977), a gold disc sent into space with images and sounds from Earth, where images were encoded as analog audio signals.

The cover reinforces this idea:
- Title: **"THE NOT-RANDOM RECORD"**
- Tracks: STATIC, SIGNAL, CALIBRATION (Side A) and NOISE, ORDER (Side B)
- Vinyl record aesthetic with "(c) 0xfun"

### Audio properties

```
Format:     WAV PCM 16-bit signed
Channels:   1 (mono)
Sample rate: 48000 Hz
Samples:    556416
Duration:   11.59 s
```

### Signal structure

Spectrogram and instantaneous frequency analysis (FM demodulation) reveals 5 sections:

| Time        | Section        | Description                            |
|-------------|----------------|----------------------------------------|
| 0.0 - 2.5s  | STATIC         | White noise (RMS ~3900)                |
| 2.5 - 2.9s  | CALIBRATION 1  | Pure tone at 1000 Hz                   |
| 2.9 - 7.0s  | SIGNAL         | Image data with ~920 Hz carrier        |
| 7.0 - 7.5s  | CALIBRATION 2  | Pure tone at 1000 Hz                   |
| 7.5 - 11.6s | SIGNAL         | Image data with ~920 Hz carrier        |

---

## Solution

### Step 1: Audio as raster image

The key is that **each 16-bit PCM sample IS a pixel** in grayscale. There is no complex FM/AM modulation -- the raw sample values directly represent the brightness of each pixel.

The total number of samples is **556416**. Factoring:

```
556416 = 2^7 x 3^3 x 7 x 23
```

Divisors that produce reasonable image dimensions include: 288x1932, 336x1656, **384x1449**, 448x1242, 576x966.

### Step 2: Identify the correct width

Testing **384 pixels wide** (= 48 x 8, matching 8 cycles of the 1000 Hz calibration tone), the image is revealed:

- Top section: static noise (STATIC)
- Calibration bars (the 1000 Hz sine wave rendered as a gradient)
- Text "CALIBRATION"
- A decorative shape/waveform
- Text "0xfun :: SIGNALS"
- More calibration bars
- **The flag** in two lines
- Text "nothing here is truly random"

```python
width = 384
height = 556416 // 384  # = 1449
img = samples.reshape(height, width)
img_normalized = ((img - img.min()) / (img.max() - img.min()) * 255).astype(np.uint8)
```

### Step 3: Correct the diagonal skew

The text appears skewed/italicized because the data signal has a **carrier wave at ~920 Hz** (period ~52 samples). Since 384 / 52 = 7.385 (not an integer), each image row starts at a different phase of the cycle, creating a cumulative horizontal offset.

This is corrected with an **affine shear transformation**:

```python
shear = -0.45
img_corrected = img.transform(
    (new_width, height),
    Image.AFFINE,
    (1, shear, -shear * height, 0, 1, 0),
    resample=Image.BILINEAR
)
```

### Step 4: Read the flag

Cropping and enlarging the text area (rows ~1060-1320), it reads clearly:

```
0xfun{g01d3n_r3c0rd_
1s_n0t_r4nd0m}
```

**Flag: `0xfun{g0ld3n_r3c0rd_1s_n0t_r4nd0m}`**

"golden record is not random" -- a reference to the Voyager Golden Record.

---

## Files

| File | Description |
|------|-------------|
| `Lines of Contact/cover.png` | Album cover (provided) |
| `Lines of Contact/record.wav` | Audio with the encoded image (provided) |
| `solve.py` | Complete solution script |
| `decoded_raw.png` | Decoded image (without shear correction) |
| `decoded_desheared.png` | Image with shear correction applied |
| `flag_crop.png` | Enlarged crop of the flag area |

## Execution

```bash
cd /home/ubuntu/0xfun/ctf/challenges/forensics/lines_of_contact
python3 solve.py "Lines of Contact/record.wav"
```

---

## Key concepts

- **Voyager Golden Record**: Disc sent into space in 1977 with images encoded as analog audio -- the direct inspiration for this challenge
- **Audio as raster image**: Each 16-bit PCM sample = one pixel; the image width is determined by factoring the total number of samples
- **Carrier and shear**: A carrier wave whose period does not exactly divide the image width produces a diagonal skew that is corrected with an affine transformation
- **Factoring for dimensions**: The correct width (384) matches 8 cycles of the 1000 Hz calibration tone at 48kHz
