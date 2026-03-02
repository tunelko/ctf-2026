# Penguin - Forensics

**Category:** Forensics
**Author:** stapat
**Hint:** "In a colony of many, one penguin's path is an anomaly. Silence the crowd to hear the individual."

## Flag

`EH4X{0n3_tr4ck_m1nd_tw0_tr4ck_F1les}`

## Analysis

```
$ file challenge.mkv
challenge.mkv: Matroska data
```

MKV container with 3 streams:
- Stream 0: H.264 video (576x320, 63s)
- Stream 1: FLAC audio "English (Stereo)" — 2ch, 44100Hz
- Stream 2: FLAC audio "English (5.1 Surround)" — also 2ch, 44100Hz (mislabeled!)

Metadata decoy: `COMMENT=EH4X{k33p_try1ng}` — fake flag.

## Solution

1. Notice two audio tracks — both stereo despite different labels. Sizes nearly identical (3714807 vs 3714051 bytes).

2. Extract both tracks:
```bash
ffmpeg -i challenge.mkv -map 0:1 -c copy audio_stereo.flac
ffmpeg -i challenge.mkv -map 0:2 -c copy audio_surround.flac
```

3. Subtract track 2 from track 1 — "silence the crowd to hear the individual":
```python
diff = track1_samples - track2_samples  # per-sample subtraction
```

4. The difference signal has a spike at ~25-28 seconds. Amplify and render spectrogram:
```bash
sox audio_diff.wav audio_diff_amp.wav gain 40
sox audio_diff_amp.wav -n trim 24.5 4 spectrogram -o flag.png
```

5. The spectrogram contains pixel-art text:
```
EH4X{0n3_tr4ck_m1nd
    _tw0_tr4ck_F1les}
```

## Key Takeaways

- Always check for multiple audio/subtitle tracks in MKV files
- Metadata flags can be decoys (`EH4X{k33p_try1ng}`)
- Audio track subtraction reveals hidden spectrogram images
- "5.1 Surround" labeled as stereo (2ch) is a red flag
