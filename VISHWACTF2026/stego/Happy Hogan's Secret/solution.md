# Happy Hogan's Secrets — VishwaCTF 2026

**Category:** Steganography
**Flag:** `VishwaCTF{H4ppl_H0g4n_Fcs_Ex3ctly_Wha7_V_W4nted}`

---

## TL;DR

JPEG image has an appended ZIP containing a hex-encoded password (hex -> base64 -> base64 -> ROT13 = "Password"). Use it to decrypt `Protected_audio.zip`. The MP3 inside has an embedded ZIP at EOF containing `real_flag.txt` with a 5-layer encoded flag (ROT13 -> base64 -> hex -> base64 -> ROT13).

---

## Analysis

### Files provided

| File | Type | Size |
|------|------|------|
| `Recognize.jpg` | JPEG (700x300), photo of Happy Hogan | 68 KB |
| `Protected_audio.zip` | AES-encrypted ZIP | 40 KB |

### Step 1 — Extract hidden ZIP from JPEG

`binwalk` reveals a ZIP archive appended after the JPEG EOF marker (`FFD9`):

```bash
binwalk Recognize.jpg
# 67542  0x107D6  Zip archive data -> note.txt

dd if=Recognize.jpg bs=1 skip=67542 of=hidden.zip
unzip hidden.zip
```

**note.txt:**
```
Happy Hogan: 555449316256707463476c6157455539
"It's not that complicated."
```

### Step 2 — Decode the password (4 layers)

```
555449316256707463476c6157455539
  |-- hex decode --> UTI1bVptcGlaWEU5
  |-- base64 -----> Q25mZmpiZXE=
  |-- base64 -----> Cnffjbeq
  |-- ROT13 ------> Password
```

### Step 3 — Extract the encrypted ZIP

```bash
7z x -p"Password" Protected_audio.zip
```

Contents:
- `decoy.txt` — fake flag + hint: *"The flag is in the audio metadata"*
- `output2.mp3` — 1.3s audio ("I can't help you there")

### Step 4 — Find embedded ZIP in MP3

`binwalk` on the MP3 reveals a ZIP at offset 42044:

```bash
binwalk output2.mp3
# 42044  0xA43C  Zip archive data -> real_flag.txt

dd if=output2.mp3 bs=1 skip=42044 of=real_flag.zip
unzip real_flag.zip
```

**real_flag.txt:**
```
Flag: AGZ1BQIuAzD2AQH3AmN3AGH1AQH2AQH0AwHmZGH1ZmN1BGZlATHmAGH4ZmR1
AGp3AwD0AQHlAwt1BQZkATH3AmIuAzZmBGHmAwR3LGEyAmp1LGZmAzZ3ZmH4ZmN3
ZQZkAwV2LGL0AwL1ZmH2Zmx0LwEyAQp0AwMyAwZ2MGD2Zmx=
```

### Step 5 — Decode the flag (5 layers)

```
AGZ1BQIuAzD2AQH3...Zmx=
  |-- ROT13 ------> NTM1ODVhNmQ2NDU3NzA3NTU1...=
  |-- base64 -----> 53585a6d6457707555456454...39
  |-- hex decode -> SXZmdWpuUEdTe1U0Y2N5X1Uw...F9
  |-- base64 -----> IvfujnPGS{U4ccy_U0t4a_Spf_Rk3pgyl_Jun7_I_J4agrq}
  |-- ROT13 ------> VishwaCTF{H4ppl_H0g4n_Fcs_Ex3ctly_Wha7_V_W4nted}
```

---

## Decoy flags encountered

| Source | Flag | Status |
|--------|------|--------|
| `decoy.txt` | `VishwaCTF{H4ppy_H0g4n_1s_Sma4rt_But_N0t_Th1s_Much}` | Decoy |
| MP3 Description metadata (hex->b64->rot13) | `VishwaCTF{st3g0_c4n_b3_3a5y}` | Decoy |
| MP3 body `SECRET_FLAG:` (b64->rot13) | `VishwaCTF{st3gn0_c4n_b3_3a5y}` | Decoy |
| `real_flag.txt` (rot13->b64->hex->b64->rot13) | `VishwaCTF{H4ppl_H0g4n_Fcs_Ex3ctly_Wha7_V_W4nted}` | **Correct** |

---

## Solve script

```python
import base64, codecs

# Step 1: Extract password from note.txt hex
pwd_hex = "555449316256707463476c6157455539"
pwd = codecs.decode(
    base64.b64decode(
        base64.b64decode(
            bytes.fromhex(pwd_hex)
        )
    ).decode(), 'rot_13'
)
print(f"ZIP Password: {pwd}")  # Password

# Step 2: Decode real_flag.txt
encoded = ("AGZ1BQIuAzD2AQH3AmN3AGH1AQH2AQH0AwHmZGH1ZmN1BGZlATHmAGH4"
           "ZmR1AGp3AwD0AQHlAwt1BQZkATH3AmIuAzZmBGHmAwR3LGEyAmp1LGZm"
           "AzZ3ZmH4ZmN3ZQZkAwV2LGL0AwL1ZmH2Zmx0LwEyAQp0AwMyAwZ2MGD2Zmx=")

step1 = codecs.decode(encoded, 'rot_13')           # ROT13
step2 = base64.b64decode(step1).decode()            # base64
step3 = bytes.fromhex(step2).decode()               # hex
step4 = base64.b64decode(step3).decode()            # base64
flag  = codecs.decode(step4, 'rot_13')              # ROT13

print(f"Flag: {flag}")
# VishwaCTF{H4ppl_H0g4n_Fcs_Ex3ctly_Wha7_V_W4nted}
```

---

## Key lessons

- Multiple decoy flags to waste time — always look for ALL hidden data before committing to one answer
- `binwalk` both the image AND the audio — embedded ZIPs at EOF are common
- "Multi-layered encoding" meant literal stacked ciphers: ROT13 + base64 + hex interleaved 5 deep
- The hint in `decoy.txt` ("flag is in the audio metadata") is itself a misdirection; the real flag is in an embedded ZIP inside the MP3, not in the ID3 metadata
