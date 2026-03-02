# airlock - Reversing Writeup

**Category:** Reversing
**Event:** UniVsThreats 2026 Quals
**Flag:** `UVT{S0m3_s3cR3tZ_4r_nVr_m3Ant_t0_B_SHRD}`

## Challenge Description

> Congratulations earthling! You found the culprit that deleted those files... By investigating the USB further, a team member found out that there is a program that would unlock the airlock of that spaceship. Your mission is to reconstruct the access chain, verify the airlock authentication path and recover the hidden evidence that explains who triggered the wipe, why it was done and what was meant to stay buried.

**Provided:** `airlockauth` (ELF 64-bit, stripped, PIE)

**Context:** This binary was found on the FAT partition of a USB disk image (`space_usb.img`) from the related forensics challenge. The same image contains all required input files.

---

## Step 1 — Binary Reconnaissance

```bash
$ file airlockauth
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped

$ strings airlockauth | grep -v "^[._]"
EVP_DigestInit_ex    EVP_sha256       EVP_MD_CTX_new
EVP_DigestFinal_ex   EVP_DigestUpdate OPENSSL_cleanse
fgets    fopen    fread    malloc   strlen   strcspn
seed32.bin           missing seed
nav.bc               missing nav
payload.enc          missing payload
signal verified
access denied
```

Key observations:
- **Stripped** — no symbol names, function identification required
- **OpenSSL EVP API** — uses SHA256 (`EVP_sha256`, `EVP_DigestInit/Update/Final`)
- **Three input files** — `seed32.bin`, `nav.bc`, `payload.enc`
- **Two outcomes** — "signal verified" / "access denied"
- **No flag print** — the binary validates but doesn't output the decrypted result

---

## Step 2 — Locating Input Files

All three files exist on the USB disk image from the forensics challenge:

| File | Location | Size |
|------|----------|------|
| `seed32.bin` | ext4 partition, **deleted** (inode 17) | 32 bytes |
| `nav.bc` | FAT partition, `/nav.bc` | 256 bytes |
| `payload.enc` | FAT partition, `/payload.enc` | 40 bytes |

Recovery of `seed32.bin`:
```bash
# Mount ext4 partition (offset 204800*512)
losetup --find --show --offset 104857600 space_usb.img
debugfs -R "dump <17> seed32.bin" /dev/loopN
```

The authentication token is also reconstructed from the USB:
- **Prefix** `ASTRA9-` from `crew_log.txt` on the FAT partition
- **Suffix** `BRO-1337` from deleted `crew_id.part2` (inode 18) on ext4

**Full token: `ASTRA9-BRO-1337`**

---

## Step 3 — Reverse Engineering the Binary

The binary is stripped, so `main` doesn't have a symbol. The entry point at `0x1640` calls `__libc_start_main` with the real main at `0x1300`.

### Function Map

| Address | Role | Prototype (reconstructed) |
|---------|------|---------------------------|
| `0x1300` | `main()` | Orchestrates everything |
| `0x1730` | `sha256_hash()` | `int sha256(void *data, size_t len, void *out32)` |
| `0x17f0` | `read_file()` | `int read_file(char *path, void **buf, size_t *size)` |

### main() — Full Decompilation (pseudocode)

```c
int main() {
    char token[256];
    void *seed_data, *nav_data, *payload_data;
    size_t seed_size, nav_size, payload_size;
    uint8_t nav_hash[32];       // rsp+0x50
    uint8_t final_key[32];      // rsp+0x70

    // Read token from stdin
    fgets(token, 0x100, stdin);
    token[strcspn(token, "\n")] = '\0';

    // Read the three input files
    if (read_file("seed32.bin", &seed_data, &seed_size) || seed_size != 0x20)
        { fprintf(stderr, "missing seed\n"); return 1; }

    if (read_file("nav.bc", &nav_data, &nav_size) || nav_size <= 0x0f)
        { fprintf(stderr, "missing nav\n"); return 1; }

    if (read_file("payload.enc", &payload_data, &payload_size) || payload_size <= 7)
        { fprintf(stderr, "missing payload\n"); return 1; }

    // Stage 1: Hash the navigation bytecode
    sha256_hash(nav_data, nav_size, nav_hash);   // 0x14b4

    // Build combined buffer: seed32 || token || nav_hash
    size_t token_len = strlen(token);
    size_t total = token_len + 0x40;              // token_len + 64
    uint8_t *combined = malloc(total);

    // Copy seed32 (32 bytes) via SSE movdqu/movups
    memcpy(combined, seed_data, 32);              // 0x1504-0x151e
    // Copy token after seed
    memcpy(combined + 32, token, token_len);      // 0x1522
    // Copy nav_hash after token (fills remaining 32 bytes)
    size_t remaining = total - (token_len + 32);
    memcpy(combined + 32 + token_len, nav_hash, remaining);  // 0x154b

    // Stage 2: Hash the combined buffer → XOR key
    sha256_hash(combined, total, final_key);      // 0x155b

    // Decrypt payload via XOR
    uint8_t *decrypted = malloc(payload_size);
    memcpy(decrypted, payload_data, payload_size);
    for (int i = 0; i < payload_size; i++)
        decrypted[i] ^= final_key[i & 0x1f];     // 0x1599-0x15b0

    // Check magic bytes: "UVT{" == 0x7b545655
    if (*(uint32_t*)decrypted == 0x7b545655)      // 0x15b2
        puts("signal verified");
    else
        puts("access denied");

    // Cleanse and free all buffers
    OPENSSL_cleanse(final_key, 32);
    OPENSSL_cleanse(combined, total);
    OPENSSL_cleanse(decrypted, payload_size);
    free(combined); free(decrypted); free(seed_data);
    free(nav_data); free(payload_data);
    return 0;
}
```

### Key Assembly Details

**Seed copy via SSE (0x1504-0x151e):**
```asm
movdqu xmm0, [r15]         ; load seed[0:16]
movups [rax], xmm0          ; store to combined[0:16]
movdqu xmm1, [r15+0x10]    ; load seed[16:32]
movups [rax+0x10], xmm1     ; store to combined[16:32]
```

**Buffer size calculation (0x14cc-0x14d0):**
```asm
lea  rax, [rax+0x40]        ; total = strlen(token) + 64
```
With token length 15: `total = 15 + 64 = 79`.
Buffer layout: `seed(32) + token(15) + nav_hash(32) = 79 bytes`. Correct.

**XOR loop (0x1599-0x15b0):**
```asm
xor_loop:
    mov    rdx, rax
    and    edx, 0x1f             ; i & 31 → wrap every 32 bytes
    movzx  edx, BYTE [rsp+rdx+0x70]  ; key[i % 32]
    xor    BYTE [r13+rax], dl    ; payload[i] ^= key[i % 32]
    add    rax, 1
    cmp    r12, rax              ; r12 = payload_size
    jne    xor_loop
```

**Magic check (0x15b2):**
```asm
cmp  DWORD [r13+0x0], 0x7b545655   ; "UVT{" in little-endian
jne  access_denied                   ; 0x161e → puts("access denied")
```

---

## Step 4 — Reproducing the Decryption

### Algorithm Summary

```
┌─────────────┐     ┌─────────────┐
│  nav.bc     │     │ seed32.bin  │
│  (256 B)    │     │  (32 B)     │
└──────┬──────┘     └──────┬──────┘
       │                   │
   SHA256()            copy to buf[0:32]
       │                   │
       ▼                   ▼
  nav_hash ────────► buf = seed32 ║ token ║ nav_hash
  (32 B)                    (32)    (15)     (32)
                            └────────┬───────┘
                                     │ = 79 bytes
                                 SHA256()
                                     │
                                     ▼
                                 xor_key (32 B)
                                     │
                    ┌────────────────┤
                    │           XOR decrypt
                    ▼                │
              payload.enc ──────────►│
               (40 B)               ▼
                                   FLAG
                            "UVT{S0m3_s3cR3tZ_..."
```

### Python Implementation

```python
import hashlib

seed    = open("seed32.bin", "rb").read()   # 32 bytes
nav     = open("nav.bc", "rb").read()       # 256 bytes
payload = open("payload.enc", "rb").read()  # 40 bytes
token   = b"ASTRA9-BRO-1337"               # 15 bytes

nav_hash = hashlib.sha256(nav).digest()
combined = seed + token + nav_hash          # 32 + 15 + 32 = 79 bytes
xor_key  = hashlib.sha256(combined).digest()

flag = bytes(p ^ xor_key[i & 0x1f] for i, p in enumerate(payload))
print(flag.decode())  # UVT{S0m3_s3cR3tZ_4r_nVr_m3Ant_t0_B_SHRD}
```

### Verification

```
nav_hash  = 700c450a6d41192846ded28457618e5f381666a631c05ee10f6bc4759e3a1584
combined  = aa882a927ccab9a86d0b38108666947896a04f7923272bc175018264651a2622
            4153545241392d42524f2d31333337
            700c450a6d41192846ded28457618e5f381666a631c05ee10f6bc4759e3a1584
xor_key   = 0a4511bb2690c45fdae63c84e481ab96ff924abfd1b612692e6c713c6ec38a75
plaintext = UVT{S0m3_s3cR3tZ_4r_nVr_m3Ant_t0_B_SHRD}
```

---

## Scripts

- `solve.py` — Full solver with verbose output of each stage
- Input files: `seed32.bin`, `nav.bc`, `payload.enc` (included, extracted from USB image)

## Key Lessons

1. **Stripped binaries** require manual function identification — entry point → `__libc_start_main` arg1 → real main
2. **Two-stage hashing** — the binary doesn't just hash the token directly; it chains SHA256(nav.bc) into a combined buffer with the seed before deriving the XOR key
3. **SSE copy instructions** (`movdqu`/`movups`) are common in optimized code — recognize them as 16-byte memcpy operations
4. **Buffer size from `lea rax, [rax+0x40]`** — the `+0x40` constant (64) = 32 (seed) + 32 (hash), with token length added dynamically
5. **The binary never outputs the flag** — it only prints "signal verified" or "access denied". The decrypted payload must be reconstructed externally by reproducing the algorithm
