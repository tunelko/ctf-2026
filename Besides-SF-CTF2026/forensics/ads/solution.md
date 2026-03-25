# ads — BSidesSF 2026 (Forensics, 101pts)

## TL;DR

MP4 with two AV1 video streams. The main stream is a decoy; the second hidden stream (13 Kbps) contains the flag text on every frame.

## Flag

```
CTF{alternate_data_stream}
```

## Description

We're given `ads.mp4` — a 60-second MP4 video. The challenge name hints at **Alternate Data Streams**.

## Analysis

```bash
$ ffprobe -v quiet -print_format json -show_streams ads.mp4
```

Key findings:
- **Stream 0**: AV1 video, 800x450, 1.2 Mbps, handler: "CTF Trickery" — the visible decoy
- **Stream 1**: AV1 video, 800x450, 13 Kbps, handler: "VideoHandler" — hidden flag stream

The extremely low bitrate of stream 1 (13 Kbps vs 1.2 Mbps) suggests a near-static image — perfect for hiding flag text.

## Exploit / Recovery

```bash
# Extract the hidden second stream
ffmpeg -i ads.mp4 -map 0:1 -c copy hidden_stream.mp4

# Extract a frame
ffmpeg -i hidden_stream.mp4 -frames:v 1 flag.png
```

Every frame shows `CTF{alternate_data_stream}` on a colorful background.

## Key Lessons

- Always check for multiple streams in media containers with `ffprobe`
- Challenge name "ads" = Alternate Data Streams — a direct hint
- Handler name "CTF Trickery" on stream 0 confirms the decoy
- Low bitrate streams are suspicious — worth extracting separately
