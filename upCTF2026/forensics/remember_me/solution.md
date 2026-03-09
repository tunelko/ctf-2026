# Remember Me — upCTF 2026 (Forensics)

## Flag
```
upCTF{r3m3mb3r_m3_1m_4_w1nd0ws_f34tur3}
```

## TL;DR
AD1 forensic image of a compromised Windows workstation. The attacker encrypted a directory with XOR and wiped all traces of the malware. The encryption script was captured by **Windows Recall** (ukg.db) and the XOR key was derived via a known-plaintext attack using the UTF-8 BOM and the known flag format.

---

## Challenge Description

> A corporate workstation was compromised. The attacker managed to encrypt a critical directory containing sensitive company files, then wiped all traces of the malware from the system - or so they thought. Somewhere in the forensic image lies the ghost of their actions. Find the malware script, understand what it did, and recover the files.

---

## Step 1: Forensic Image Reconnaissance

The image comes in **AccessData AD1** format (ADSEGMENTEDFILE), created with FTK Imager 8.2.0.33:

```
remember_me.ad1   1.6 GB
remember_me.ad2   1.6 GB
remember_me.ad3   587 MB
```

From the `remember_me.ad1.txt` file:
```
Created By Exterro® FTK® Imager 8.2.0.33
Case Number: upCTF 2026 Remember Me
Evidence Number: 006

[Custom Content Sources]
 C:\:Windows [NTFS]|[root]|Users|*(Wildcard,Consider Case,Include Subdirectories)
 C:\:Windows [NTFS]|[root]|Windows|Prefetch|*(Wildcard,Consider Case,Include Subdirectories)
 C:\:Windows [NTFS]|[root]|Windows|System32|*(Wildcard,Consider Case,Include Subdirectories)
```

The image selectively contains: the user profile, prefetch, and System32.

To extract files from the AD1 format on Linux, the `dissect.evidence` library from Fox-IT/NCC Group was used:
```python
from dissect.evidence.ad1 import AD1
ad = AD1(["remember_me.ad1", "remember_me.ad2", "remember_me.ad3"])
```

---

## Step 2: PowerShell History — Reconstructing the Attacker's Timeline

**Artifact**: `Users/shieda/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt`

3 copies were found (2032, 2804, and 7684 bytes). The largest one (7684 bytes) contains the complete history. Key evidence extracted:

### 2.1. The attacker searched for content in Windows Recall (ukg.db)
```powershell
Get-Content ".\ukg.db" | Select-String "r3c4ll"
python -c "import sqlite3; conn = sqlite3.connect(r'C:\Users\shieda\AppData\Local\CoreAIPlatform.00\UKP\{DA73A0DB-DDF4-4A81-9506-CCB5DE8B0F14}\ukg.db'); conn.execute('VACUUM'); conn.commit(); conn.close(); print('Done')"
Get-Content ".\ukg.db" | Select-String "encrypt"
```
The attacker knew that Recall could contain evidence and attempted to search for and clean it with `VACUUM`.

### 2.2. The attacker executed and then deleted the malicious scripts
```powershell
python3 .\decrypt.py
Remove-Item "C:\Users\shieda\encrypt.py" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Users\shieda\build_ukg.py" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Users\shieda\verify.py" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Users\shieda\decrypt.py" -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\shieda\" -Recurse -Filter "*.py" | Remove-Item -Force
```

### 2.3. Massive artifact cleanup
```powershell
# Prefetch
Remove-Item "C:\Windows\Prefetch\PYTHON*" -Force -ErrorAction SilentlyContinue

# Temp
Remove-Item "$env:TEMP\*" -Force -Recurse -ErrorAction SilentlyContinue

# Event logs
wevtutil cl System
wevtutil cl Application
wevtutil cl Security
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# Python cache
Get-ChildItem "C:\Users\shieda\" -Recurse -Filter "__pycache__" | Remove-Item -Force -Recurse
Get-ChildItem "C:\Users\shieda\" -Recurse -Filter "*.pyc" | Remove-Item -Force

# Recycle bin, recent files, thumbnails
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse
Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force
```

---

## Step 3: Windows Recall (ukg.db) — The Ghost of Their Actions

**Artifact**: `Users/shieda/AppData/Local/CoreAIPlatform.00/UKP/{DA73A0DB-DDF4-4A81-9506-CCB5DE8B0F14}/ukg.db` (57344 bytes)

Windows Recall is a Windows 11 feature that takes periodic screenshots and stores the OCR text in a SQLite database. Despite the `VACUUM`, the data persisted.

### 3.1. Database Structure

```sql
sqlite3 ukg.db ".tables"
-- App, WindowCapture, WindowCaptureAppRelation, WindowCaptureTextIndex, ...

sqlite3 ukg.db "SELECT COUNT(*) FROM WindowCapture"
-- 30 captures
```

### 3.2. Screenshot Timeline

| ID | Window Title | Relevant Content |
|----|-------------|---------------------|
| 7 | Task Manager | `python.exe 0.1% 24.3 MB` (python running) |
| 9 | Untitled - Notepad | `import os` (script beginning) |
| 10 | Untitled - Notepad | `KEY = b""` / `TARGET_DIR = r"C:\Users\shieda\Documents\CompanySecrets"` |
| **11** | **encrypt.py - Notepad** | **Complete encryption script** |
| 12 | Command Prompt | `python encrypt.py` → `Done. All files encrypted.` |
| 13 | File Explorer (CompanySecrets) | `flag.txt.enc  Q3_financials.txt.enc  credentials.txt.enc  project_nightfall.txt.enc` |
| 14 | Command Prompt | `del encrypt.py` |
| 28 | Google Chrome | Search: `how to remove powershell history windows 11` |

### 3.3. Encryption Script Captured (Capture #11)

```
WindowTitle: encrypt.py - Notepad
OCR Text:
```
```python
import os

KEY = ""
TARGET_DIR = r"C:\Users\shieda\Documents\CompanySecrets"

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

for filename in os.listdir(TARGET_DIR):
    filepath = os.path.join(TARGET_DIR, filename)
    if os.path.isfile(filepath):
        with open(filepath, "rb") as f:
            data = f.read()
        encrypted = xor_encrypt(data, KEY)
        enc_path = filepath + ".enc"
        with open(enc_path, "wb") as f:
            f.write(encrypted)
        os.remove(filepath)

print("Done. All files encrypted.")
```

The OCR captured `KEY = ""` — the actual key does not appear in the text (likely Recall did not capture the exact value between quotes or it was too short for the OCR).

---

## Step 4: Encrypted Files

**Location**: `Users/shieda/Documents/CompanySecrets/`

| File | Size | First bytes (hex) |
|---------|--------|---------------------|
| `credentials.txt.enc` | 35 bytes | `bd 88 dc 77 29 23 6d ...` |
| `flag.txt.enc` | 63 bytes | `bd 88 dc 63 09 00 2e ...` |
| `flag.txt.enc` (2nd copy) | 41 bytes | `bd 88 dc 41 1c 2f 19 ...` |
| `Q3_financials.txt.enc` | 40 bytes | `bd 88 dc 65 5f 4c 1f ...` |
| `project_nightfall.txt.enc` | 41 bytes | `bd 88 dc 64 1e 03 27 ...` |

**Critical observation**: All files start with `bd 88 dc`. This indicates that all plaintexts share the same first bytes, XOR'd with the same key.

---

## Step 5: Key Derivation via Known-Plaintext Attack

### 5.1. UTF-8 BOM as known-plaintext

Text files created on Windows (Notepad) include a UTF-8 **Byte Order Mark** at the beginning: `\xef\xbb\xbf`. This gives us the first 3 bytes of the key:

```
enc[0:3] = bd 88 dc
BOM      = ef bb bf
key[0:3] = bd^ef  88^bb  dc^bf = 52 33 63 = "R3c"
```

### 5.2. Flag format as known-plaintext

We know that `flag.txt` contains `upCTF{`. The 41-byte file (2nd copy) starts with BOM + "upCTF{":

```
Plaintext:  ef bb bf  75 70 43 54 46 7b  ...
            (BOM)     u  p  C  T  F  {
Encrypted:  bd 88 dc  41 1c 2f 19 75 29  ...

Key derived byte by byte:
  key[0] = bd ^ ef = 52 = 'R'
  key[1] = 88 ^ bb = 33 = '3'
  key[2] = dc ^ bf = 63 = 'c'
  key[3] = 41 ^ 75 = 34 = '4'
  key[4] = 1c ^ 70 = 6c = 'l'
  key[5] = 2f ^ 43 = 6c = 'l'
  key[6] = 19 ^ 54 = 4d = 'M'
  key[7] = 75 ^ 46 = 33 = '3'
  key[8] = 29 ^ 7b = 52 = 'R'  ← same as key[0]! The key repeats.
```

**Full key: `R3c4llM3`** (8 bytes, cyclic)

Note the reference: "R3c4llM3" = "RecallMe" in leet speak, consistent with the Windows Recall theme.

---

## Step 6: Decrypting the Files

```python
key = b"R3c4llM3"

def xor_decrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
```

### Results:

| File | Decrypted content (without BOM) |
|---------|-------------------------------|
| `flag.txt.enc` (63 bytes) | `Welcome to the flag: upCTF{r3m3mb3r_m3_1m_4_w1nd0ws_f34tur3}` |
| `flag.txt.enc` (41 bytes) | `upCTF{XOR_1s_n0t_encrypti0n_bruh_7f3a}` |
| `credentials.txt.enc` | `CEO personal password: hunter2` |
| `Q3_financials.txt.enc` | `Q3 Revenue: .2M. Do not distribute.` |
| `project_nightfall.txt.enc` | `Project Nightfall launch: 2026-06-01` |

---

## Exploited Vulnerabilities

| # | Vulnerability | CWE |
|---|---------------|-----|
| 1 | XOR cipher with 8-byte key — trivial with known-plaintext | CWE-327 (Broken Crypto) |
| 2 | Windows Recall stores OCR of all activity — including source code open in Notepad | Feature by design |
| 3 | `VACUUM` in SQLite does not remove data from FTS (Full Text Search) tables | — |
| 4 | PowerShell history (`ConsoleHost_history.txt`) preserves all attacker activity | — |

## Discarded Approaches
- None — the approach was linear: history → Recall DB → script → known-plaintext → key → decrypt

## Key Lessons
- XOR with a short key is cryptographically broken: a single fragment of known plaintext (BOM, flag format, file headers) is enough to derive the full key
- Windows Recall (`ukg.db`) is a extremely valuable forensic artifact — it stores OCR text from periodic screenshots
- The attacker attempted cleanup (VACUUM, deleting prefetch, event logs, history) but failed to remove the content from Recall's FTS tables and the multiple copies of the PowerShell history in the AD1 image
- The UTF-8 BOM (`\xef\xbb\xbf`) that Windows adds to text files is a free known-plaintext for attacking XOR ciphers

## References
- [Windows Recall forensics](https://www.group-ib.com/blog/windows-recall-forensics/)
- [dissect.evidence — AD1 parser](https://github.com/fox-it/dissect)
- [XOR cipher cryptanalysis](https://en.wikipedia.org/wiki/XOR_cipher#Use_and_security)
