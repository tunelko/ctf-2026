# Cursed Calligraphy

**CTF**: kashiCTF 2026
**Category**: Crypto
**Flag**: `kashiCTF{1t_i5_h4rd_t0_dr4w}`

## TL;DR

XLSX spreadsheet with 100 upload log entries — one row (ID 42) has a unique filename and "This is the one" in its Notes column. Its Google Drive link downloads a video of someone hand-drawing the flag in a paint program. Characters overlap but are readable: `1t_i5_h4rd_t0_dr4w`.

## Analysis

### Step 1: Find the right record

The file `nariyal.xlsx` has two sheets:
- **Employee Upload Logs**: 100 rows with columns: ID, Department, Filename, Uploader, Status, Drive Link, Notes
- **README**: Hints — "Look closely at filenames and uploader patterns"

Most filenames repeat (`input_trace.mp4` ×8, `cursor_demo.mp4` ×9, etc.). **Row 43 (ID 42)** stands out:
- **Unique filename**: `paint_capture_review.mp4` (appears only once)
- **Notes column**: `"This is the one"`
- **Department**: Input Lab
- **Drive Link**: `https://drive.google.com/file/d/1nIw_Mb6IBGGQNaiqqDHPeJL1oSwPBItx/view`

### Step 2: Download and analyze

The Drive link is a real, public Google Drive file. Downloaded a 16MB MP4 video (712×542, 72 seconds, 30fps) showing a screen recording of someone drawing characters in a paint program.

### Step 3: Reconstruct the flag

The video shows characters being hand-drawn one at a time, but all in the same area — they overlap, creating a messy composite. Approaches to read the flag:
- **Frame differencing**: Extract what was drawn in each time segment by comparing start/end frames of each drawing burst
- **Color-coded segments**: Assign different colors to strokes from different time segments to visually separate overlapping characters
- **Sequential frame viewing**: Watch the early frames where individual characters are still distinguishable

The drawn text reads: `kashiCTF{1t_i5_h4rd_t0_dr4w}`

## Key Takeaways

- "Only one holds the truth" → look for unique values (filename that appears exactly once, notes column with explicit hint)
- "The flag was never typed, only drawn" → video forensics, not text extraction
- Frame differencing is the standard technique for isolating overlapping drawings in screen recordings

## Files

- `nariyal.xlsx` — Challenge spreadsheet
- `paint_capture_review.mp4` — Downloaded video with hand-drawn flag
- `flag.txt` — Captured flag
