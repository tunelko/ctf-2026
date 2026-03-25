#!/bin/bash
# ads: Extract hidden second video stream from MP4, grab frame with flag
ffmpeg -y -i ads.mp4 -map 0:1 -frames:v 1 flag_frame.png 2>/dev/null
echo "[+] Extracted flag_frame.png from hidden stream 1"
echo "[+] Open flag_frame.png to read: CTF{alternate_data_stream}"
