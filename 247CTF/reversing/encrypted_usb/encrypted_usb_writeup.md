# Writeup: Encrypted USB - 247CTF Reversing Challenge

## Challenge Info

- **Category**: Reversing
- **Platform**: 247CTF
- **File**: `432b23369f1677dccfbcc9e9a237081eb4833b44.zip`

## Challenge Description

> An important USB drive containing sensitive information has been encrypted by some new ransomware variant. Can you reverse the ransomware encryption function and recover the files?

Additionally, a `README.txt` file is provided with additional context:

```
Urgent Incident Response help needed!

We have been contacted by a key client, whose external storage devices have all
been encrypted by some new and unknown ransomware variant.

Important files which have not been backed up have been encrypted and the client
needs access to the files from 1 specific device urgently.

The drive uses BitLocker encryption; however, it was mounted at the time of the attack.

The client will not disclose their BitLocker password; however, we do have access
to the BitLocker recovery keys from the asset management team.

Unfortunately, the asset management team didn't map the recovery keys to specific
devices, so we only have a company-wide dump.

The external storage device image (encrypted_usb.dd) and BitLocker recovery key
dump (recovery_keys_dump.txt) are attached.

Can you help?
```

## Provided Files

```
├── encrypted_usb.dd         # BitLocker encrypted disk image (76 MB)
├── recovery_keys_dump.txt   # 1000 BitLocker recovery keys
└── README.txt               # Incident description
```

---

## Phase 1: Decrypting the BitLocker Volume

### Initial Analysis

First we verify the file type:

```bash
$ file encrypted_usb.dd
encrypted_usb.dd: DOS/MBR boot sector, code offset 0x52+2, OEM-ID "-FVE-FS-",
sectors/cluster 8, Media descriptor 0xf8, sectors/track 63, heads 255,
hidden sectors 128, dos < 4.0 BootSector (0x0), FAT (1Y bit by descriptor);
NTFS, sectors/track 63, sectors 155647, $MFT start cluster 4,
$MFTMirror start cluster 9727, bytes/RecordSegment 2^(-1*246),
clusters/index block 1, serial number 0760c3e5c60c3e526
```

The identifier `-FVE-FS-` confirms this is a BitLocker encrypted volume (Full Volume Encryption).

### Brute-Force Recovery Keys

We have 1000 recovery keys in standard BitLocker format (8 groups of 6 digits):

```
123456-789012-345678-901234-567890-123456-789012-345678
...
```

We use `dislocker` to test each key:

```python
#!/usr/bin/env python3
import subprocess
import os

keys_file = "recovery_keys_dump.txt"
img_file = "encrypted_usb.dd"
mount_point = "/tmp/bitlocker_mount"

os.makedirs(mount_point, exist_ok=True)

with open(keys_file, 'r') as f:
    keys = [line.strip() for line in f if line.strip()]

print(f"Testing {len(keys)} keys...")

for i, key in enumerate(keys):
    if i % 100 == 0:
        print(f"Progress: {i}/{len(keys)}")

    # Try to decrypt
    result = subprocess.run(
        ["dislocker", "-V", img_file, f"-p{key}", "--", mount_point],
        capture_output=True,
        text=True,
        timeout=10
    )

    # Check if successful
    dislocker_file = os.path.join(mount_point, "dislocker-file")
    if os.path.exists(dislocker_file):
        print(f"\n*** SUCCESS! Key #{i+1}: {key}")
        print(f"Decrypted file at: {dislocker_file}")
        break

    # Cleanup
    subprocess.run(["fusermount", "-u", mount_point], capture_output=True)

print("Done!")
```

### Result

```
*** SUCCESS! Key #793: 334565-564641-129580-248655-292215-551991-326733-393679
```

### Mount the Decrypted Volume

```bash
# Mount with dislocker
$ dislocker -V encrypted_usb.dd -p334565-564641-129580-248655-292215-551991-326733-393679 -- /tmp/bitlocker_mount

# Mount the NTFS filesystem
$ mount -o loop /tmp/bitlocker_mount/dislocker-file /tmp/ntfs_mount

# Volume contents
$ ls -la /tmp/ntfs_mount/
drwxrwxrwx 1 root root    4096 May 18  2020 .
drwxr-xr-x 3 root root    4096 Feb  2 13:30 ..
-rwxrwxrwx 1 root root  484449 May 18  2020 crypto_passphrase.png.xxx.crypt
-rwxrwxrwx 1 root root   17488 May 18  2020 cryptor
-rwxrwxrwx 1 root root    9352 May 18  2020 do_not_open.png.xxx.crypt
-rwxrwxrwx 1 root root  135394 May 18  2020 meeting_minutes.png.xxx.crypt
-rwxrwxrwx 1 root root  909569 May 18  2020 passwords.png.xxx.crypt
-rwxrwxrwx 1 root root     305 May 18  2020 ransom.txt
-rwxrwxrwx 1 root root 1755677 May 18  2020 salary_screenshot.png.xxx.crypt
```

### Ransom Note

```
$ cat ransom.txt
Oh no! Your files are encrypted!
Your files have been encrypted using a secure xor encryption algorithm
and are completely unrecoverable!
To decrypt your files, you need your secret encryption key.
To retrieve your secret encryption key, you will need to pay 50 BOTCIINS...
```

The note reveals that **XOR encryption** is used.

---

## Phase 2: Reverse Engineering the Ransomware

### Binary Analysis

```bash
$ file cryptor
cryptor: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, BuildID[sha1]=..., stripped
```

### Imported Functions

```bash
$ strings cryptor | grep -E "^[a-z]+$"
fopen
fread
fwrite
fclose
strlen
strcmp
strcpy
strrchr
opendir
readdir
closedir
```

### Disassembly of the Encryption Function

Using `objdump -d cryptor`, we identify the encryption function at `0x12c9`:

```asm
; Function encrypt(char* input_file, char* output_file, char* key)
;
; Main XOR loop (0x140d - 0x143f):

140d:   mov    -0x50(%rbp),%rdx      ; buffer
1411:   mov    -0x64(%rbp),%eax      ; index i
1414:   cltq
1416:   movzbl (%rdx,%rax,1),%eax    ; buffer[i]
141a:   mov    %eax,%ecx

141c:   mov    -0x64(%rbp),%eax      ; index i
141f:   movslq %eax,%rdx
1422:   mov    -0x88(%rbp),%rax      ; key
1429:   add    %rdx,%rax             ; key + i
142c:   movzbl (%rax),%eax           ; key[i]

142f:   xor    %ecx,%eax             ; buffer[i] ^ key[i]
1431:   mov    %eax,%ecx

1433:   mov    -0x50(%rbp),%rdx      ; buffer
1437:   mov    -0x64(%rbp),%eax      ; index i
143a:   cltq
143c:   mov    %cl,(%rdx,%rax,1)     ; buffer[i] = result

143f:   addl   $0x1,-0x64(%rbp)      ; i++
```

### main() Function - Key Validation

At `0x15a8-0x15e6`:

```asm
15a8:   cmpl   $0x2,-0x124(%rbp)     ; argc == 2?
15af:   jne    15e8
...
15c2:   call   strlen@plt
15c7:   cmp    $0x4,%rax             ; strlen(argv[1]) == 4?
15cb:   jne    15e8
```

**Key finding**: The ransomware expects a key of **exactly 4 characters** as an argument.

### Reconstructed Pseudocode

```c
void encrypt(char* input_file, char* output_file, char* key) {
    int key_len = strlen(key);
    FILE* fin = fopen(input_file, "rb");
    FILE* fout = fopen(output_file, "wb");

    char buffer[key_len];
    int bytes_read;

    while ((bytes_read = fread(buffer, 1, key_len, fin)) == key_len) {
        for (int i = 0; i < bytes_read; i++) {
            buffer[i] ^= key[i];
        }
        fwrite(buffer, 1, bytes_read, fout);
    }

    fclose(fin);
    fclose(fout);
}

int main(int argc, char** argv) {
    if (argc != 2 || strlen(argv[1]) != 4) {
        return 1;
    }

    // Iterates through current directory, encrypts .cryf -> .crypt files
    DIR* dir = opendir(".");
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL) {
        if (has_extension(entry->d_name, ".cryf")) {
            char outname[256];
            strcpy(outname, entry->d_name);
            strcat(outname, ".crypt");
            encrypt(entry->d_name, outname, argv[1]);
        }
    }

    closedir(dir);
    return 0;
}
```

---

## Phase 3: Recovering the XOR Key

### Known-Plaintext Attack

The encrypted files are PNG images. The PNG format has a known fixed header:

| Offset | Bytes (hex)           | Meaning              |
|--------|-----------------------|----------------------|
| 0-7    | 89 50 4E 47 0D 0A 1A 0A | PNG magic header   |

### Key Extraction

```bash
$ xxd crypto_passphrase.png.xxx.crypt | head -1
00000000: ef33 213e 6b69 7573 ...  .3!>kius...
```

Encrypted bytes: `ef 33 21 3e 6b 69 75 73`
PNG header:     `89 50 4E 47 0D 0A 1A 0A`

Applying XOR:

```python
>>> png_header = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
>>> encrypted  = bytes([0xef, 0x33, 0x21, 0x3e, 0x6b, 0x69, 0x75, 0x73])
>>> key = bytes([p ^ e for p, e in zip(png_header, encrypted)])
>>> print(key)
b'fcoyfcoy'
```

**Recovered key: `fcoy`** (4 characters, repeating)

### Manual Verification

| PNG byte | Encrypted | XOR result | ASCII |
|----------|-----------|------------|-------|
| 0x89     | 0xef      | 0x66       | 'f'   |
| 0x50     | 0x33      | 0x63       | 'c'   |
| 0x4E     | 0x21      | 0x6f       | 'o'   |
| 0x47     | 0x3e      | 0x79       | 'y'   |
| 0x0D     | 0x6b      | 0x66       | 'f'   |
| 0x0A     | 0x69      | 0x63       | 'c'   |
| 0x1A     | 0x75      | 0x6f       | 'o'   |
| 0x0A     | 0x73      | 0x79       | 'y'   |

---

## Phase 4: Decrypting the Files

### Decryption Script

```python
#!/usr/bin/env python3
import os

key = b'fcoy'

for fname in os.listdir('.'):
    if fname.endswith('.crypt'):
        with open(fname, 'rb') as f:
            data = f.read()

        # XOR is symmetric: encrypt(encrypt(x)) = x
        decrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

        # Remove .xxx.crypt extension
        outname = fname.replace('.xxx.crypt', '')
        with open(outname, 'wb') as f:
            f.write(decrypted)

        print(f'Decrypted: {fname} -> {outname}')
```

### Result

```
Decrypted: salary_screenshot.png.xxx.crypt -> salary_screenshot.png
Decrypted: crypto_passphrase.png.xxx.crypt -> crypto_passphrase.png
Decrypted: passwords.png.xxx.crypt -> passwords.png
Decrypted: do_not_open.png.xxx.crypt -> do_not_open.png
Decrypted: meeting_minutes.png.xxx.crypt -> meeting_minutes.png
```

### Verification

```bash
$ file *.png
crypto_passphrase.png: PNG image data, 628 x 367, 8-bit/color RGB, non-interlaced
do_not_open.png:       PNG image data, 617 x 98, 8-bit/color RGB, non-interlaced
meeting_minutes.png:   PNG image data, 356 x 356, 8-bit/color RGB, non-interlaced
passwords.png:         PNG image data, 680 x 680, 8-bit/color RGBA, interlaced
salary_screenshot.png: PNG image data, 1271 x 709, 8-bit/color RGB, non-interlaced
```

---

## Flag

The flag is found in `do_not_open.png`:

```
247CTF{494f7cceXXXXXXXXXXXXXXXXe673b1ae}
```

---

## Final Files in Directory

```
/root/ctf/reversing_432/
├── 432b23369f1677dccfbcc9e9a237081eb4833b44.zip   # Original challenge file
├── bruteforce.py                                   # BitLocker brute-force script
├── bruteforce_key.sh                               # Alternative script (bash)
├── crypto_passphrase.png                           # Decrypted image
├── crypto_passphrase.png.xxx.crypt                 # Original encrypted image
├── cryptor                                         # Ransomware binary
├── do_not_open.png                                 # Image with FLAG
├── do_not_open.png.xxx.crypt                       # Original encrypted image
├── encrypted_usb.dd                                # BitLocker image
├── encrypted_usb.md                                # This writeup
├── meeting_minutes.png                             # Decrypted image
├── meeting_minutes.png.xxx.crypt                   # Original encrypted image
├── passwords.png                                   # Decrypted image
├── passwords.png.xxx.crypt                         # Original encrypted image
├── ransom.txt                                      # Ransom note
├── README.txt                                      # Incident description
├── recovery_keys_dump.txt                          # 1000 BitLocker keys
├── salary_screenshot.png                           # Decrypted image
└── salary_screenshot.png.xxx.crypt                 # Original encrypted image
```

---

## Summary of Techniques Used

1. **BitLocker brute-force**: Testing 1000 recovery keys with `dislocker`
2. **Reverse engineering**: Analyzing stripped ELF binary with `objdump`
3. **Algorithm analysis**: Identifying XOR encryption with 4-byte key
4. **Known-Plaintext Attack**: Using known PNG header to recover XOR key
5. **XOR decryption**: Applying the same XOR operation to decrypt (symmetric property)

---

## Challenge Takeaways

- **BitLocker without key mapping**: Always maintain an inventory that relates recovery keys to specific devices
- **XOR is not secure**: XOR encryption is trivially breakable with known-plaintext attacks
- **File headers**: File formats with fixed headers (PNG, PDF, ZIP, etc.) are vulnerable to known-plaintext attacks
- **Short keys**: A 4-byte key offers only 2^32 possibilities, besides being vulnerable to frequency analysis
