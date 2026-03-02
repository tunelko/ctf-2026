# MVP (Minimum Viable Product)

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | caliphallabsRooted2026         |
| Category    | reversing                      |
| Difficulty  | Easy-Medium                    |

## Description
Como empresa, nos aconsejaron lanzar cuanto antes un Producto Mínimo Viable (MVP). No estamos del todo convencidos, pero bueno, así son las cosas cuando uno se adentra en estos mundos. Eso sí, nos preocupa mucho que alguien robe nuestra idea, así que la hemos censurado.

## TL;DR
Windows PE64 that extracts an Authenticode certificate embedded within itself, decrypts it with AES-256-CBC (key=`caliphal_labs!!!!!!!!!!!!!!!!!!!`, IV=`mvpmvpmvpmvpmvpm`), loads it as a DLL in memory, and executes `get_mvp()` (which prints "Censored"). The flag is in the `get_flag()` function of the decrypted DLL, which is not directly invoked.

## Initial Analysis

### Binary Reconnaissance

```
$ file mvp.exe
PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 10 sections

$ strings -n 8 mvp.exe | grep -iE 'crypt|cert|key|mvp|caliphal'
mvpmvpmvpmvpmvpm
caliphal_labs!!!!!!!!!!!!!!!!!!!@
No certificates!
BCryptDecrypt
BCryptGenerateSymmetricKey
BCryptGetProperty
BCryptOpenAlgorithmProvider
BCryptSetProperty
ImageEnumerateCertificates
ImageGetCertificateData
```

Immediate observations:
- Compiled with **MinGW-w64 GCC 12** (not MSVC)
- Uses **Windows BCrypt API** for symmetric encryption (AES)
- Uses **imagehlp.dll** (`ImageEnumerateCertificates`, `ImageGetCertificateData`) -- reads Authenticode certificates from the PE itself
- Suspicious strings: `"mvpmvpmvpmvpmvpm"` (16 bytes, looks like an IV) and `"caliphal_labs!!!!!!!!!!!!!!!!!!!@"` (>32 bytes, looks like a key)

### Function Analysis

With r2/radare2, the relevant functions were identified:

| Address | Function | Description |
|---------|----------|-------------|
| `0x140007cf0` | decrypt/load | Main function: extracts cert, decrypts, loads DLL |
| `0x140001530` | printf wrapper | Prints string (used for the "mvp" output) |
| `0x1400015xx` | BCrypt imports | `BCryptOpenAlgorithmProvider`, `BCryptSetProperty`, `BCryptGetProperty`, `BCryptGenerateSymmetricKey`, `BCryptDecrypt` |

## Vulnerability / Protection Mechanism

There is no "vulnerability" per se -- it is a code protection scheme that hides the real DLL inside an Authenticode certificate embedded in the PE, encrypted with AES-256-CBC. The key and IV are hardcoded as strings in the binary itself, making the encryption trivially reversible.

## Solution Process

###  Execution flow analysis

The main function (`fcn.140007cf0`, called from the CRT startup) follows this flow:

```
1. GetModuleFileNameA()          → gets its own exe path
2. CreateFileA()                 → opens the exe for reading
3. ImageEnumerateCertificates()  → enumerates Authenticode certificates
4. ImageGetCertificateData()     → extracts certificate data
5. BCryptOpenAlgorithmProvider("AES")
6. BCryptSetProperty("ChainingMode", "ChainingModeCBC")
7. BCryptGenerateSymmetricKey(key="caliphal_labs!!!!!!!!!!!!!!!!!!!", cbSecret=32)
8. BCryptDecrypt(data=cert[0x5b0:], IV="mvpmvpmvpmvpmvpm", cbIV=16)  → first pass: gets size
9. BCryptDecrypt(data=cert[0x5b0:], IV="mvpmvpmvpmvpmvpm", cbIV=16)  → second pass: decrypts
10. GetTempPathA() + GetTempFileNameA("mvp")  → creates temporary file
11. WriteFile()                   → writes the decrypted DLL
12. LoadLibraryA(temp_dll)        → loads the DLL
13. GetProcAddress("get_mvp")     → looks for the export
14. call get_mvp()                → executes and gets string
15. printf(result)                → prints "Censored..."
16. FreeLibrary() + DeleteFileA() → cleans up
```

###  Cryptographic parameter identification

From the disassembly:

```asm
; Key (32 bytes) - at 0x140009040
lea rax, "caliphal_labs!!!!!!!!!!!!!!!!!!!@"
mov dword [var_28h], 0x20    ; cbSecret = 32

; IV (16 bytes) - at 0x140009020
lea rsi, "mvpmvpmvpmvpmvpm"
mov dword [var_28h], 0x10    ; cbIV = 16

; Algorithm
lea rdx, u"AES"
; Mode
lea r8, u"ChainingModeCBC"
```

Parameters:
- **Algorithm**: AES-256 (32-byte key)
- **Mode**: CBC (Cipher Block Chaining)
- **Key**: `caliphal_labs!!!!!!!!!!!!!!!!!!!` (first 32 bytes of the string)
- **IV**: `mvpmvpmvpmvpmvpm` (16 bytes)

###  Locating the encrypted data

The encrypted data is in the **Authenticode certificate table** of the PE:

```python
# PE optional header → data directory entry 4 (Certificate Table)
# cert_file_offset = 0xa600, cert_size = 86304 bytes

# WIN_CERTIFICATE structure:
#   dwLength (4 bytes) = 86304
#   wRevision (2 bytes) = 0x0200
#   wCertificateType (2 bytes) = 2 (PKCS#7)
#   bCertificate (variable) = ASN.1 data + encrypted DLL

# From the disassembly:
#   r12 = rsi + 0x5b0    → encrypted data starts at cert_data[0x5b0]
#   ebx = [rsi] - 0x5b0  → encrypted length = dwLength - 0x5b0 = 84848 bytes
```

The Authenticode certificate contains a valid PKCS#7 structure in the first 0x5b0 bytes (1456 bytes), followed by the encrypted DLL data.

###  Decryption

```python
from Crypto.Cipher import AES

key = b"caliphal_labs!!!!!!!!!!!!!!!!!!!"  # 32 bytes
iv  = b"mvpmvpmvpmvpmvpm"                  # 16 bytes

# Extract encrypted data from the PE certificate
encrypted = cert_data[0x5B0 : 0x5B0 + 84848]

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted)
# → decrypted[:2] == b"MZ" → valid DLL
```

###  Analysis of the decrypted DLL

```
$ file decrypted.dll
PE32+ executable (DLL) (console) x86-64, for MS Windows, 20 sections
```

Relevant exports:

| Export | Address | Behavior |
|--------|---------|----------|
| `get_mvp` | `0x137d` | Returns `"Censurado. (c) 2026 Caliphal Labs - Todos los derechos reservados."` |
| `get_flag` | `0x1370` | Returns `"clctf{MVP_r1gHts_pr073tEd_w1Th_c3rT1F1c4735}"` |

Disassembly:

```asm
; get_flag (NOT called by the main binary)
sym.get_flag:
    push rbp
    mov rbp, rsp
    lea rax, "clctf{MVP_r1gHts_pr073tEd_w1Th_c3rT1F1c4735}"
    pop rbp
    ret

; get_mvp (called by the main binary via GetProcAddress)
sym.get_mvp:
    push rbp
    mov rbp, rsp
    lea rax, "Censurado. © 2026 Caliphal Labs - Todos los derechos reservados."
    pop rbp
    ret
```

The binary calls `get_mvp()` → "Censored". The flag is in `get_flag()`, a DLL export that the main binary never invokes.

## Discarded Approaches

None -- the direct approach (extract cert → decrypt → strings) worked on the first try. The cryptographic parameters were all hardcoded as readable strings.

## Final Exploit

See `solve.py` -- Python script that:
1. Parses the PE to find the certificate table
2. Extracts the encrypted data from offset 0x5b0
3. Decrypts with AES-256-CBC
4. Searches for the flag in the decrypted DLL

```bash
$ python3 solve.py
[*] Certificate at file offset 0xa600, size 86304
[*] Encrypted data: 84848 bytes (offset 0x5b0 in cert)
[+] Decrypted DLL: 84848 bytes (MZ header OK)

[+] FLAG: clctf{MVP_r1gHts_pr073tEd_w1Th_c3rT1F1c4735}
```

## Execution
```bash
python3 solve.py    # Only needs mvp.exe in the same directory
```

## Flag
```
clctf{MVP_r1gHts_pr073tEd_w1Th_c3rT1F1c4735}
```

## Key Lessons

1. **Authenticode certificates as a data container**: the PE uses the certificate table to hide an encrypted DLL. This is a real evasion/steganography technique in malware, since certificates don't affect PE execution and many tools ignore them.

2. **Hardcoded keys = zero protection**: both the AES key and IV are plain strings in the binary. With just `strings mvp.exe` you get the parameters needed to decrypt.

3. **DLL with hidden exports**: the DLL has `get_flag()` as an export that the binary never calls. Reviewing the complete export table is crucial when analyzing a DLL.

4. **The GetModuleFileName → read self → extract → decrypt → LoadLibrary flow is a classic pattern** of self-extracting/self-decrypting malware.

## Flow Diagram

```
mvp.exe
  │
  ├── GetModuleFileNameA() → reads its own path
  ├── CreateFileA() → opens mvp.exe
  ├── ImageEnumerateCertificates() → finds 1 cert
  ├── ImageGetCertificateData() → extracts cert (86304 bytes)
  │     │
  │     └── cert[0x5b0:] → encrypted data (84848 bytes)
  │
  ├── BCrypt AES-256-CBC decrypt
  │     key = "caliphal_labs!!!!!!!!!!!!!!!!!!!"
  │     iv  = "mvpmvpmvpmvpmvpm"
  │     │
  │     └── Decrypted DLL (PE32+ DLL)
  │
  ├── GetTempFileNameA("mvp") → creates temp file
  ├── WriteFile() → writes DLL to temp
  ├── LoadLibraryA() → loads DLL
  ├── GetProcAddress("get_mvp") → looks for export
  ├── call get_mvp() → "Censurado. ©..."
  ├── printf() → prints result
  ├── FreeLibrary() + DeleteFileA() → cleans up
  │
  └── [HIDDEN] get_flag() → "clctf{...}" (uninvoked export)
```

## References
- [PE Authenticode / Certificate Table](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only)
- [Windows BCrypt API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)
- [ImageGetCertificateData](https://learn.microsoft.com/en-us/windows/win32/api/imagehlp/nf-imagehlp-imagegetcertificatedata)
